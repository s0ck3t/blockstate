"""PostgreSQL StorageBackend SPI implementation with async SQLAlchemy and asyncpg.

Provides cloud production persistent storage backed by SQLAlchemy[asyncio] and asyncpg,
with distributed leasing, optimistic CAS revision checks, and SchemaUpcaster chaining.
"""

import asyncio
import json
import time
import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from blockstate.config import BlockstateSettings
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


def _build_metadata() -> tuple[MetaData, Table, Table]:
    """Construct SQLAlchemy Table metadata schemas for leases and checkpoints."""
    meta = MetaData()
    leases = Table(
        "blockstate_leases",
        meta,
        Column("session_id", String(255), primary_key=True),
        Column("lease_id", String(64), nullable=False),
        Column("expires_at_epoch_ms", BigInteger, nullable=False),
        Column("fence_token", Integer, nullable=False),
    )
    checkpoints = Table(
        "blockstate_checkpoints",
        meta,
        Column("session_id", String(255), primary_key=True),
        Column("schema_version", Integer, nullable=False),
        Column("revision_id", Integer, nullable=False),
        Column("state_json", Text, nullable=False),
        Column("task_stack_json", Text, nullable=False),
        Column("last_ledger_hash", String(255), nullable=False),
        Column("pending_ledger_outbox_json", Text, nullable=False),
        Column("vault_map", LargeBinary, nullable=False),
        Column("created_at", String(64), nullable=False),
        Column("updated_at", String(64), nullable=False),
    )
    return meta, leases, checkpoints


class PostgresStorageBackend:
    """PostgreSQL StorageBackend SPI implementation backed by async SQLAlchemy."""

    def __init__(
        self,
        dsn: str | None = None,
        *,
        engine: AsyncEngine | None = None,
        pool_size: int = 20,
        max_overflow: int = 10,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> None:
        self._raw_dsn = dsn
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._upcasters: dict[int, SchemaUpcaster] = dict(upcasters or {})
        self._target_schema_version = target_schema_version
        self._lock = asyncio.Lock()
        self._tables_created = False

        self.metadata, self.leases_table, self.checkpoints_table = _build_metadata()

        if engine is not None:
            self._engine = engine
            self._dsn = str(engine.url)
            self._engine_owned = False
        else:
            self._dsn = self._normalise_dsn(dsn)
            self._engine_owned = True
            if "sqlite" in self._dsn:
                self._engine = create_async_engine(self._dsn, pool_pre_ping=True)
            else:
                self._engine = create_async_engine(
                    self._dsn,
                    pool_size=self._pool_size,
                    max_overflow=self._max_overflow,
                    pool_pre_ping=True,
                )

    @property
    def engine(self) -> AsyncEngine:
        """Return the underlying SQLAlchemy AsyncEngine."""
        return self._engine

    @property
    def dsn(self) -> str:
        """Return normalised DSN connection string."""
        return self._dsn

    def register_upcaster(self, from_version: int, upcaster: SchemaUpcaster) -> None:
        """Register a pure schema upcaster function from from_version to from_version + 1."""
        self._upcasters[from_version] = upcaster

    def _normalise_dsn(self, dsn: str | None) -> str:
        """Normalise PostgreSQL DSN strings for asyncpg driver compatibility."""
        if not dsn:
            settings = BlockstateSettings()
            dsn = settings.postgres_dsn.get_secret_value()
        if not dsn:
            dsn = "postgresql+asyncpg://localhost:5432/blockstate"

        cleaned = dsn.strip()
        if cleaned.startswith("postgres://"):
            cleaned = "postgresql+asyncpg://" + cleaned[len("postgres://") :]
        elif cleaned.startswith("postgresql://") and not cleaned.startswith("postgresql+"):
            cleaned = "postgresql+asyncpg://" + cleaned[len("postgresql://") :]
        return cleaned

    async def _ensure_tables(self) -> None:
        """Ensure required tables exist in the target database."""
        if not self._tables_created:
            async with self._lock:
                if not self._tables_created:
                    async with self._engine.begin() as conn:
                        await conn.run_sync(self.metadata.create_all)
                    self._tables_created = True

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
        await self._ensure_tables()
        deadline = time.monotonic() + (wait_timeout_ms / 1000.0)
        poll_interval_s = min(0.025, max(0.005, wait_timeout_ms / 1000.0 / 20))

        while True:
            async with self._lock:
                now = _now_epoch_ms()
                try:
                    async with self._engine.begin() as conn:
                        select_stmt = select(
                            self.leases_table.c.lease_id,
                            self.leases_table.c.expires_at_epoch_ms,
                            self.leases_table.c.fence_token,
                        ).where(self.leases_table.c.session_id == session_id)
                        result = await conn.execute(select_stmt)
                        row = result.fetchone()

                        if row is None:
                            # Clean session: insert new lease
                            lease_id = uuid.uuid4().hex
                            expires_at = now + ttl_ms
                            fence_token = 1
                            ins_stmt = self.leases_table.insert().values(
                                session_id=session_id,
                                lease_id=lease_id,
                                expires_at_epoch_ms=expires_at,
                                fence_token=fence_token,
                            )
                            await conn.execute(ins_stmt)
                            return LeaseHandle(
                                session_id=session_id,
                                lease_id=lease_id,
                                expires_at_epoch_ms=expires_at,
                                fence_token=fence_token,
                            )

                        current_lease_id, expires_at_epoch_ms, fence_token = row
                        if now >= expires_at_epoch_ms:
                            # Expired or stale lease can be re-acquired
                            new_lease_id = uuid.uuid4().hex
                            new_expires_at = now + ttl_ms
                            new_fence = fence_token + 1
                            upd_stmt = (
                                update(self.leases_table)
                                .where(
                                    self.leases_table.c.session_id == session_id,
                                    self.leases_table.c.lease_id == current_lease_id,
                                )
                                .values(
                                    lease_id=new_lease_id,
                                    expires_at_epoch_ms=new_expires_at,
                                    fence_token=new_fence,
                                )
                            )
                            res = await conn.execute(upd_stmt)
                            if res.rowcount > 0:
                                return LeaseHandle(
                                    session_id=session_id,
                                    lease_id=new_lease_id,
                                    expires_at_epoch_ms=new_expires_at,
                                    fence_token=new_fence,
                                )
                            continue
                except IntegrityError:
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
        await self._ensure_tables()
        async with self._lock, self._engine.begin() as conn:
            upd_stmt = (
                update(self.leases_table)
                .where(
                    self.leases_table.c.session_id == lease.session_id,
                    self.leases_table.c.lease_id == lease.lease_id,
                )
                .values(expires_at_epoch_ms=0)
            )
            await conn.execute(upd_stmt)

    async def renew_lease(
        self,
        lease: LeaseHandle,
        ttl_ms: int = 30000,
    ) -> LeaseHandle:
        """Renew an active session lease heartbeat.

        Raises LeaseTimeoutError (BLK-STO-003) if the lease expired or was stolen.
        """
        await self._ensure_tables()
        now = _now_epoch_ms()
        async with self._lock, self._engine.begin() as conn:
            select_stmt = select(
                self.leases_table.c.lease_id,
                self.leases_table.c.expires_at_epoch_ms,
                self.leases_table.c.fence_token,
            ).where(self.leases_table.c.session_id == lease.session_id)
            result = await conn.execute(select_stmt)
            row = result.fetchone()

            if row is None or row[0] != lease.lease_id or now >= row[1]:
                raise LeaseTimeoutError(
                    f"Cannot renew lease for session '{lease.session_id}': "
                    "lease was stolen or lost",
                    code="BLK-STO-003",
                    session_id=lease.session_id,
                )

            new_expires_at = now + ttl_ms
            upd_stmt = (
                update(self.leases_table)
                .where(
                    self.leases_table.c.session_id == lease.session_id,
                    self.leases_table.c.lease_id == lease.lease_id,
                )
                .values(expires_at_epoch_ms=new_expires_at)
            )
            await conn.execute(upd_stmt)

            return LeaseHandle(
                session_id=lease.session_id,
                lease_id=lease.lease_id,
                expires_at_epoch_ms=new_expires_at,
                fence_token=row[2],
            )

    async def load_checkpoint(self, session_id: str) -> SessionCheckpoint | None:
        """Load recent session checkpoint from PostgreSQL, applying registered upcasters."""
        await self._ensure_tables()
        async with self._lock, self._engine.begin() as conn:
            select_stmt = select(
                self.checkpoints_table.c.session_id,
                self.checkpoints_table.c.schema_version,
                self.checkpoints_table.c.revision_id,
                self.checkpoints_table.c.state_json,
                self.checkpoints_table.c.task_stack_json,
                self.checkpoints_table.c.last_ledger_hash,
                self.checkpoints_table.c.pending_ledger_outbox_json,
                self.checkpoints_table.c.vault_map,
                self.checkpoints_table.c.created_at,
                self.checkpoints_table.c.updated_at,
            ).where(self.checkpoints_table.c.session_id == session_id)
            result = await conn.execute(select_stmt)
            row = result.fetchone()

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
        await self._ensure_tables()
        async with self._lock:
            now = _now_epoch_ms()
            async with self._engine.begin() as conn:
                # 1. Lease ownership validation
                select_lease_stmt = select(
                    self.leases_table.c.lease_id,
                    self.leases_table.c.expires_at_epoch_ms,
                ).where(self.leases_table.c.session_id == checkpoint.session_id)
                lease_res = await conn.execute(select_lease_stmt)
                lease_row = lease_res.fetchone()

                if lease_row is None or lease_row[0] != lease.lease_id or now >= lease_row[1]:
                    raise LeaseTimeoutError(
                        f"Cannot save checkpoint for session '{checkpoint.session_id}': "
                        "lease is invalid",
                        code="BLK-STO-003",
                        session_id=checkpoint.session_id,
                    )

                # 2. Optimistic CAS revision validation
                select_cp_stmt = select(
                    self.checkpoints_table.c.revision_id,
                ).where(self.checkpoints_table.c.session_id == checkpoint.session_id)
                cp_res = await conn.execute(select_cp_stmt)
                cp_row = cp_res.fetchone()

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

                dialect_name = self._engine.dialect.name
                stmt: Any = None
                if dialect_name == "postgresql":
                    from sqlalchemy.dialects.postgresql import insert as pg_insert

                    stmt = (
                        pg_insert(self.checkpoints_table)
                        .values(
                            session_id=checkpoint.session_id,
                            schema_version=checkpoint.schema_version,
                            revision_id=checkpoint.revision_id,
                            state_json=state_json,
                            task_stack_json=task_stack_json,
                            last_ledger_hash=checkpoint.last_ledger_hash,
                            pending_ledger_outbox_json=pending_outbox_json,
                            vault_map=vault_map_blob,
                            created_at=checkpoint.created_at,
                            updated_at=checkpoint.updated_at,
                        )
                        .on_conflict_do_update(
                            index_elements=["session_id"],
                            set_={
                                "schema_version": checkpoint.schema_version,
                                "revision_id": checkpoint.revision_id,
                                "state_json": state_json,
                                "task_stack_json": task_stack_json,
                                "last_ledger_hash": checkpoint.last_ledger_hash,
                                "pending_ledger_outbox_json": pending_outbox_json,
                                "vault_map": vault_map_blob,
                                "updated_at": checkpoint.updated_at,
                            },
                            where=(
                                self.checkpoints_table.c.revision_id + 1 == checkpoint.revision_id
                            ),
                        )
                    )
                elif dialect_name == "sqlite":
                    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

                    stmt = (
                        sqlite_insert(self.checkpoints_table)
                        .values(
                            session_id=checkpoint.session_id,
                            schema_version=checkpoint.schema_version,
                            revision_id=checkpoint.revision_id,
                            state_json=state_json,
                            task_stack_json=task_stack_json,
                            last_ledger_hash=checkpoint.last_ledger_hash,
                            pending_ledger_outbox_json=pending_outbox_json,
                            vault_map=vault_map_blob,
                            created_at=checkpoint.created_at,
                            updated_at=checkpoint.updated_at,
                        )
                        .on_conflict_do_update(
                            index_elements=["session_id"],
                            set_={
                                "schema_version": checkpoint.schema_version,
                                "revision_id": checkpoint.revision_id,
                                "state_json": state_json,
                                "task_stack_json": task_stack_json,
                                "last_ledger_hash": checkpoint.last_ledger_hash,
                                "pending_ledger_outbox_json": pending_outbox_json,
                                "vault_map": vault_map_blob,
                                "updated_at": checkpoint.updated_at,
                            },
                            where=(
                                self.checkpoints_table.c.revision_id + 1 == checkpoint.revision_id
                            ),
                        )
                    )
                else:
                    # Fallback for standard dialects
                    if cp_row is None:
                        stmt = self.checkpoints_table.insert().values(
                            session_id=checkpoint.session_id,
                            schema_version=checkpoint.schema_version,
                            revision_id=checkpoint.revision_id,
                            state_json=state_json,
                            task_stack_json=task_stack_json,
                            last_ledger_hash=checkpoint.last_ledger_hash,
                            pending_ledger_outbox_json=pending_outbox_json,
                            vault_map=vault_map_blob,
                            created_at=checkpoint.created_at,
                            updated_at=checkpoint.updated_at,
                        )
                    else:
                        stmt = (
                            update(self.checkpoints_table)
                            .where(
                                self.checkpoints_table.c.session_id == checkpoint.session_id,
                                self.checkpoints_table.c.revision_id + 1 == checkpoint.revision_id,
                            )
                            .values(
                                schema_version=checkpoint.schema_version,
                                revision_id=checkpoint.revision_id,
                                state_json=state_json,
                                task_stack_json=task_stack_json,
                                last_ledger_hash=checkpoint.last_ledger_hash,
                                pending_ledger_outbox_json=pending_outbox_json,
                                vault_map=vault_map_blob,
                                updated_at=checkpoint.updated_at,
                            )
                        )

                save_res = await conn.execute(stmt)
                if save_res.rowcount == 0:
                    raise OptimisticLockError(
                        f"Optimistic lock conflict on session '{checkpoint.session_id}': "
                        f"revision {checkpoint.revision_id} could not be atomically saved",
                        code="BLK-STO-002",
                        session_id=checkpoint.session_id,
                    )

    async def close(self) -> None:
        """Dispose of the underlying SQLAlchemy AsyncEngine pool."""
        if self._engine_owned:
            await self._engine.dispose()


# Canonical alias for StorageBackend SPI
PostgresStateStore = PostgresStorageBackend

__all__: list[str] = [
    "PostgresStateStore",
    "PostgresStorageBackend",
]
