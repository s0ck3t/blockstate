"""Unit and contract tests for SQLiteStorageBackend (SQLiteStateStore)."""

import os
import shutil
import tempfile
from collections.abc import Mapping
from typing import Any

import pytest

from blockstate.adapters.storage.sqlite import (
    SQLiteStateStore,
    SQLiteStorageBackend,
)
from blockstate.ports.storage import SchemaUpcaster, SessionCheckpoint
from blockstate.testing.contracts import StateStoreContractSuite


class TestSQLiteStorageBackendContract(StateStoreContractSuite):
    """Execute complete StateStoreContractSuite against SQLiteStorageBackend."""

    __test__ = True

    def setup_method(self) -> None:
        """Create isolated temporary directory for test database."""
        self._temp_dir = tempfile.mkdtemp(prefix="blockstate_sqlite_test_")
        self._db_path = os.path.join(self._temp_dir, "test.db")
        self._backends: list[SQLiteStorageBackend] = []

    def teardown_method(self) -> None:
        """Clean up temporary directory and database files."""
        if os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def create_backend(
        self,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> SQLiteStorageBackend:
        backend = SQLiteStorageBackend(
            database=self._db_path,
            upcasters=upcasters,
            target_schema_version=target_schema_version,
        )
        self._backends.append(backend)
        return backend

    async def _close_backend(self, backend: Any) -> None:
        await super()._close_backend(backend)


@pytest.mark.asyncio
async def test_sqlite_alias_equality() -> None:
    """Verify SQLiteStateStore is a direct alias for SQLiteStorageBackend."""
    assert SQLiteStateStore is SQLiteStorageBackend


@pytest.mark.asyncio
async def test_sqlite_wal_mode_enforced(tmp_path: Any) -> None:
    """Verify PRAGMA journal_mode=WAL is enforced on connection initialisation."""
    db_file = str(tmp_path / "wal_test.db")
    backend = SQLiteStorageBackend(database=db_file)
    try:
        mode = await backend.get_journal_mode()
        assert mode == "wal"
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_sqlite_busy_timeout_enforced(tmp_path: Any) -> None:
    """Verify PRAGMA busy_timeout=2000 is enforced upon initialisation."""
    db_file = str(tmp_path / "timeout_test.db")
    backend = SQLiteStorageBackend(database=db_file)
    try:
        conn = await backend._get_connection()
        async with conn.execute("PRAGMA busy_timeout;") as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == 2000
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_sqlite_persistence_across_connections(tmp_path: Any) -> None:
    """Verify checkpoints and leases persist across separate backend instances on disk."""
    db_file = str(tmp_path / "persist_test.db")
    backend1 = SQLiteStorageBackend(database=db_file)

    lease = await backend1.acquire_lease("session_persist", ttl_ms=20000)
    cp = SessionCheckpoint(
        session_id="session_persist",
        schema_version=1,
        revision_id=0,
        state={"persisted_key": "persisted_value"},
    )
    await backend1.save_checkpoint(cp, lease)
    await backend1.close()

    # Re-open in fresh backend instance
    backend2 = SQLiteStorageBackend(database=db_file)
    try:
        loaded = await backend2.load_checkpoint("session_persist")
        assert loaded is not None
        assert loaded.session_id == "session_persist"
        assert loaded.revision_id == 0
        assert loaded.state == {"persisted_key": "persisted_value"}
    finally:
        await backend2.close()


@pytest.mark.asyncio
async def test_sqlite_register_upcaster_dynamically(tmp_path: Any) -> None:
    """Verify registering an upcaster dynamically on SQLiteStorageBackend."""
    db_file = str(tmp_path / "upcast_test.db")
    backend = SQLiteStorageBackend(database=db_file, target_schema_version=2)
    try:
        backend.register_upcaster(
            1,
            lambda d: {**d, "schema_version": 2, "state": {**d.get("state", {}), "migrated": True}},
        )
        lease = await backend.acquire_lease("session_upcast", ttl_ms=10000)
        cp = SessionCheckpoint(session_id="session_upcast", schema_version=1, revision_id=0)
        await backend.save_checkpoint(cp, lease)

        loaded = await backend.load_checkpoint("session_upcast")
        assert loaded is not None
        assert loaded.schema_version == 2
        assert loaded.state.get("migrated") is True
        await backend.release_lease(lease)
    finally:
        await backend.close()


def test_sqlite_dsn_normalisation_variants() -> None:
    """Verify stripping of sqlite+aiosqlite:/// and sqlite:/// prefixes."""
    b1 = SQLiteStorageBackend(database="sqlite+aiosqlite:///path/to/db.sqlite")
    assert b1._db_path == "path/to/db.sqlite"

    b2 = SQLiteStorageBackend(database="sqlite:///another/path.db")
    assert b2._db_path == "another/path.db"

    b3 = SQLiteStorageBackend(database=":memory:")
    assert b3._db_path == ":memory:"


@pytest.mark.asyncio
async def test_sqlite_memory_database_initialisation() -> None:
    """Verify in-memory SQLite database initialisation and close."""
    backend = SQLiteStorageBackend(database=":memory:")
    try:
        conn = await backend._get_connection()
        assert conn is not None
        mode = await backend.get_journal_mode()
        assert mode == "memory"
    finally:
        await backend.close()
