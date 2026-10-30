"""SQLite StorageBackend SPI implementation with WAL mode and distributed leasing.

Provides local and edge persistent storage backed by aiosqlite, enforcing PRAGMA
journal_mode=WAL and PRAGMA busy_timeout=2000 on connection initialisation.
"""

import asyncio
import json
import os
import sqlite3
import time
import uuid
from collections.abc import Mapping
from typing import Any

import aiosqlite

from blockstate.errors import (
    ConcurrentSessionError,
    LeaseTimeoutError,
    OptimisticLockError,
)
from blockstate.ports.storage import (
    LeaseHandle,
    SchemaUpcaster,
    SessionCheckpoint,
    upcast_checkpoint_payload,
)


def _now_epoch_ms() -> int:
    """Return current Unix epoch timestamp in milliseconds."""
    return int(time.time() * 1000)


class SQLiteStorageBackend:
    """SQLite StorageBackend SPI implementation with WAL mode and distributed leasing."""

    def __init__(
        self,
        database: str = ":memory:",
        *,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> None:
        self._raw_path = database
        self._db_path = self._normalise_database_path(database)
        self._upcasters: dict[int, SchemaUpcaster] = dict(upcasters or {})
        self._target_schema_version = target_schema_version
        self._connection: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._journal_mode: str = ""

    def register_upcaster(self, from_version: int, upcaster: SchemaUpcaster) -> None:
        """Register a pure schema upcaster function from from_version to from_version + 1."""
        self._upcasters[from_version] = upcaster

    def _normalise_database_path(self, path: str) -> str:
        """Normalise DSN or file path to standard filesystem path or :memory:."""
        cleaned = path.strip()
        if cleaned.startswith("sqlite+aiosqlite:///"):
            cleaned = cleaned[len("sqlite+aiosqlite:///") :]
        elif cleaned.startswith("sqlite:///"):
            cleaned = cleaned[len("sqlite:///") :]
        return cleaned

    async def _init_connection(self) -> aiosqlite.Connection:
        """Create and initialise SQLite connection with WAL mode and busy timeout."""
        if self._db_path != ":memory:":
            dirname = os.path.dirname(os.path.abspath(self._db_path))
            if dirname:
                os.makedirs(dirname, exist_ok=True)

        conn = await aiosqlite.connect(self._db_path)
        # Enforce PRAGMAs: WAL mode and 2000ms busy timeout
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA busy_timeout=2000;")
        await conn.execute("PRAGMA foreign_keys=ON;")

        async with conn.execute("PRAGMA journal_mode;") as cursor:
            row = await cursor.fetchone()
            self._journal_mode = str(row[0]).lower() if row else ""

        await self._init_schema(conn)
        return conn

    async def _init_schema(self, conn: aiosqlite.Connection) -> None:
        """Initialise database tables for session leasing and checkpoints."""
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blockstate_leases (
                session_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL,
                expires_at_epoch_ms INTEGER NOT NULL,
                fence_token INTEGER NOT NULL
            );
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blockstate_checkpoints (
                session_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                revision_id INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                task_stack_json TEXT NOT NULL,
                last_ledger_hash TEXT NOT NULL,
                pending_ledger_outbox_json TEXT NOT NULL,
                vault_map BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        await conn.commit()

    async def _get_connection(self) -> aiosqlite.Connection:
        """Get or establish active database connection."""
        if self._connection is None:
            self._connection = await self._init_connection()
        return self._connection

    async def get_journal_mode(self) -> str:
        """Return the active SQLite journal mode."""
        if not self._journal_mode:
            await self._get_connection()
        return self._journal_mode

    async def acquire_lease(
        self,
        session_id: str,
        ttl_ms: int = 30000,
        wait_timeout_ms: int = 2000,
    ) -> LeaseHandle:
        """Acquire an exclusive distributed lease for a session.

        Waits up to wait_timeout_ms on contention before raising
        ConcurrentSessionError (BLK-CON-409).
        """
        deadline = time.monotonic() + (wait_timeout_ms / 1000.0)
        poll_interval_s = min(0.025, max(0.005, wait_timeout_ms / 1000.0 / 20))

        while True:
            async with self._lock:
                conn = await self._get_connection()
                now = _now_epoch_ms()

                query = (
                    "SELECT lease_id, expires_at_epoch_ms, fence_token "
                    "FROM blockstate_leases WHERE session_id = ?"
                )
                async with conn.execute(query, (session_id,)) as cursor:
                    row = await cursor.fetchone()

                if row is None:
                    # Clean session without active lease
                    lease_id = uuid.uuid4().hex
                    expires_at = now + ttl_ms
                    fence_token = 1
                    ins_query = (
                        "INSERT INTO blockstate_leases "
                        "(session_id, lease_id, expires_at_epoch_ms, fence_token) "
                        "VALUES (?, ?, ?, ?)"
                    )
                    try:
                        await conn.execute(
                            ins_query,
                            (session_id, lease_id, expires_at, fence_token),
                        )
                        await conn.commit()
                        return LeaseHandle(
                            session_id=session_id,
                            lease_id=lease_id,
                            expires_at_epoch_ms=expires_at,
                            fence_token=fence_token,
                        )
                    except (sqlite3.IntegrityError, aiosqlite.IntegrityError):
                        continue

                current_lease_id, expires_at_epoch_ms, fence_token = row
                if now >= expires_at_epoch_ms:
                    # Stale or expired lease can be re-acquired
                    new_lease_id = uuid.uuid4().hex
                    new_expires_at = now + ttl_ms
                    new_fence = fence_token + 1
                    upd_query = (
                        "UPDATE blockstate_leases SET "
                        "lease_id = ?, expires_at_epoch_ms = ?, fence_token = ? "
                        "WHERE session_id = ? AND lease_id = ?"
                    )
                    cursor = await conn.execute(
                        upd_query,
                        (new_lease_id, new_expires_at, new_fence, session_id, current_lease_id),
                    )
                    await conn.commit()
                    if cursor.rowcount > 0:
                        return LeaseHandle(
                            session_id=session_id,
                            lease_id=new_lease_id,
                            expires_at_epoch_ms=new_expires_at,
                            fence_token=new_fence,
                        )
                    continue

            # Contention: active lease held by another worker
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConcurrentSessionError(
                    f"Session '{session_id}' is leased by active worker '{current_lease_id}'",
                    code="BLK-CON-409",
                    session_id=session_id,
                )
            await asyncio.sleep(min(poll_interval_s, remaining))

    async def release_lease(self, lease: LeaseHandle) -> None:
        """Release an acquired session lease if it matches the active token."""
        async with self._lock:
            conn = await self._get_connection()
            await conn.execute(
                "UPDATE blockstate_leases SET expires_at_epoch_ms = 0 "
                "WHERE session_id = ? AND lease_id = ?",
                (lease.session_id, lease.lease_id),
            )
            await conn.commit()

    async def renew_lease(
        self,
        lease: LeaseHandle,
        ttl_ms: int = 30000,
    ) -> LeaseHandle:
        """Renew an active session lease heartbeat.

        Raises LeaseTimeoutError (BLK-STO-003) if the lease expired or was stolen.
        """
        now = _now_epoch_ms()
        async with self._lock:
            conn = await self._get_connection()
            check_query = (
                "SELECT lease_id, expires_at_epoch_ms, fence_token "
                "FROM blockstate_leases WHERE session_id = ?"
            )
            async with conn.execute(check_query, (lease.session_id,)) as cursor:
                row = await cursor.fetchone()

            if row is None or row[0] != lease.lease_id or now >= row[1]:
                raise LeaseTimeoutError(
                    f"Cannot renew lease for session '{lease.session_id}': "
                    "lease was stolen or lost",
                    code="BLK-STO-003",
                    session_id=lease.session_id,
                )

            new_expires_at = now + ttl_ms
            await conn.execute(
                "UPDATE blockstate_leases SET expires_at_epoch_ms = ? "
                "WHERE session_id = ? AND lease_id = ?",
                (new_expires_at, lease.session_id, lease.lease_id),
            )
            await conn.commit()

            return LeaseHandle(
                session_id=lease.session_id,
                lease_id=lease.lease_id,
                expires_at_epoch_ms=new_expires_at,
                fence_token=row[2],
            )

    async def load_checkpoint(self, session_id: str) -> SessionCheckpoint | None:
        """Load the most recent session checkpoint from SQLite, applying registered upcasters."""
        async with self._lock:
            conn = await self._get_connection()
            async with conn.execute(
                """
                SELECT session_id, schema_version, revision_id, state_json,
                       task_stack_json, last_ledger_hash, pending_ledger_outbox_json,
                       vault_map, created_at, updated_at
                FROM blockstate_checkpoints WHERE session_id = ?
                """,
                (session_id,),
            ) as cursor:
                row = await cursor.fetchone()

        if row is None:
            return None

        raw_payload: dict[str, Any] = {
            "session_id": row[0],
            "schema_version": row[1],
            "revision_id": row[2],
            "state": json.loads(row[3]),
            "task_stack": tuple(json.loads(row[4])),
            "last_ledger_hash": row[5],
            "pending_ledger_outbox": tuple(json.loads(row[6])),
            "vault_map": bytes(row[7]) if row[7] is not None else b"",
            "created_at": row[8],
            "updated_at": row[9],
        }

        migrated_payload = upcast_checkpoint_payload(
            raw_payload,
            self._upcasters,
            self._target_schema_version,
        )
        return SessionCheckpoint(**migrated_payload)

    async def save_checkpoint(
        self,
        checkpoint: SessionCheckpoint,
        lease: LeaseHandle,
    ) -> None:
        """Save a session checkpoint verifying lease ownership and optimistic CAS revision.

        Raises LeaseTimeoutError (BLK-STO-003) if the lease is invalid or expired.
        Raises OptimisticLockError (BLK-STO-002) on CAS revision mismatch.
        """
        async with self._lock:
            conn = await self._get_connection()
            now = _now_epoch_ms()

            # 1. Lease ownership validation
            async with conn.execute(
                "SELECT lease_id, expires_at_epoch_ms FROM blockstate_leases WHERE session_id = ?",
                (checkpoint.session_id,),
            ) as cursor:
                lease_row = await cursor.fetchone()

            if lease_row is None or lease_row[0] != lease.lease_id or now >= lease_row[1]:
                raise LeaseTimeoutError(
                    f"Cannot save checkpoint for session '{checkpoint.session_id}': "
                    "lease is invalid",
                    code="BLK-STO-003",
                    session_id=checkpoint.session_id,
                )

            # 2. Optimistic CAS revision validation
            async with conn.execute(
                "SELECT revision_id FROM blockstate_checkpoints WHERE session_id = ?",
                (checkpoint.session_id,),
            ) as cursor:
                cp_row = await cursor.fetchone()

            if cp_row is not None:
                existing_rev = cp_row[0]
                if checkpoint.revision_id != existing_rev + 1:
                    raise OptimisticLockError(
                        f"Optimistic lock conflict on session '{checkpoint.session_id}': "
                        f"expected revision {existing_rev + 1}, got {checkpoint.revision_id}",
                        code="BLK-STO-002",
                        session_id=checkpoint.session_id,
                    )

            # 3. Upsert checkpoint payload
            state_json = json.dumps(checkpoint.state)
            task_stack_json = json.dumps(checkpoint.task_stack)
            pending_outbox_json = json.dumps(checkpoint.pending_ledger_outbox)
            vault_map_blob = checkpoint.vault_map

            cursor = await conn.execute(
                """
                INSERT INTO blockstate_checkpoints (
                    session_id, schema_version, revision_id, state_json, task_stack_json,
                    last_ledger_hash, pending_ledger_outbox_json, vault_map, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    schema_version=excluded.schema_version,
                    revision_id=excluded.revision_id,
                    state_json=excluded.state_json,
                    task_stack_json=excluded.task_stack_json,
                    last_ledger_hash=excluded.last_ledger_hash,
                    pending_ledger_outbox_json=excluded.pending_ledger_outbox_json,
                    vault_map=excluded.vault_map,
                    updated_at=excluded.updated_at
                WHERE blockstate_checkpoints.revision_id + 1 = excluded.revision_id
                """,
                (
                    checkpoint.session_id,
                    checkpoint.schema_version,
                    checkpoint.revision_id,
                    state_json,
                    task_stack_json,
                    checkpoint.last_ledger_hash,
                    pending_outbox_json,
                    vault_map_blob,
                    checkpoint.created_at,
                    checkpoint.updated_at,
                ),
            )
            await conn.commit()
            if cursor.rowcount == 0:
                raise OptimisticLockError(
                    f"Optimistic lock conflict on session '{checkpoint.session_id}': "
                    f"revision {checkpoint.revision_id} could not be atomically saved",
                    code="BLK-STO-002",
                    session_id=checkpoint.session_id,
                )

    async def close(self) -> None:
        """Close the underlying SQLite connection."""
        async with self._lock:
            if self._connection is not None:
                await self._connection.close()
                self._connection = None


# Canonical alias for StorageBackend SPI
SQLiteStateStore = SQLiteStorageBackend

__all__: list[str] = [
    "SQLiteStateStore",
    "SQLiteStorageBackend",
]
