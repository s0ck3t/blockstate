"""Unit, dialect, and contract tests for PostgresStorageBackend (PostgresStateStore)."""

import os
import shutil
import tempfile
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects.postgresql import Insert as PGInsert
from sqlalchemy.dialects.postgresql import dialect as postgresql_dialect
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from blockstate.adapters.storage.postgres import (
    PostgresStateStore,
    PostgresStorageBackend,
)
from blockstate.ports.storage import SchemaUpcaster, SessionCheckpoint
from blockstate.testing.contracts import StateStoreContractSuite


class TestPostgresStorageBackendContract(StateStoreContractSuite):
    """Execute complete StateStoreContractSuite against PostgresStorageBackend.

    Uses an asynchronous SQLite dialect engine for hermetic local test execution.
    """

    __test__ = True

    def setup_method(self) -> None:
        """Create isolated temporary directory for test database."""
        self._temp_dir = tempfile.mkdtemp(prefix="blockstate_postgres_test_")
        self._db_path = os.path.join(self._temp_dir, "test.db")
        self._dsn = f"sqlite+aiosqlite:///{self._db_path}"

    def teardown_method(self) -> None:
        """Clean up temporary directory and database files."""
        if os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def create_backend(
        self,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> PostgresStorageBackend:
        return PostgresStorageBackend(
            dsn=self._dsn,
            upcasters=upcasters,
            target_schema_version=target_schema_version,
        )


@pytest.mark.asyncio
async def test_postgres_alias_equality() -> None:
    """Verify PostgresStateStore is a direct alias for PostgresStorageBackend."""
    assert PostgresStateStore is PostgresStorageBackend


def test_postgres_dsn_normalisation() -> None:
    """Verify DSN normalisation from postgres:// and postgresql:// to postgresql+asyncpg://."""
    b1 = PostgresStorageBackend(dsn="postgres://user:secret@db.internal:5432/appdb")
    assert b1.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/appdb"

    b2 = PostgresStorageBackend(dsn="postgresql://user:secret@db.internal:5432/appdb")
    assert b2.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/appdb"

    b3 = PostgresStorageBackend(dsn="postgresql+asyncpg://user:secret@db.internal:5432/appdb")
    assert b3.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/appdb"

    b_default = PostgresStorageBackend(dsn="")
    assert "postgresql+asyncpg://" in b_default.dsn


@pytest.mark.asyncio
async def test_postgres_engine_injection_and_property(tmp_path: Any) -> None:
    """Verify injecting a pre-existing AsyncEngine into PostgresStorageBackend."""
    db_file = str(tmp_path / "injected.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    backend = PostgresStorageBackend(engine=engine)
    try:
        assert backend.engine is engine
        assert "sqlite+aiosqlite" in backend.dsn
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_postgres_dialect_upsert_compilation(monkeypatch: Any) -> None:
    """Verify save_checkpoint executes PostgreSQL pg_insert with on_conflict_do_update."""
    backend = PostgresStorageBackend(dsn="sqlite+aiosqlite:///:memory:")
    try:
        await backend._ensure_tables()
        monkeypatch.setattr(backend._engine.dialect, "name", "postgresql")

        lease = await backend.acquire_lease("session-pg-upsert", ttl_ms=10000)
        cp = SessionCheckpoint(
            session_id="session-pg-upsert",
            schema_version=1,
            revision_id=0,
            state={"status": "active"},
        )

        executed_stmts: list[Any] = []
        real_execute = AsyncConnection.execute

        async def spy_execute(
            self: Any, statement: Any, *exec_args: Any, **exec_kwargs: Any
        ) -> Any:
            executed_stmts.append(statement)
            if isinstance(statement, PGInsert):
                mock_result = MagicMock()
                mock_result.rowcount = 1
                return mock_result
            return await real_execute(self, statement, *exec_args, **exec_kwargs)

        monkeypatch.setattr(AsyncConnection, "execute", spy_execute)

        await backend.save_checkpoint(cp, lease)

        pg_inserts = [s for s in executed_stmts if isinstance(s, PGInsert)]
        assert len(pg_inserts) == 1
        pg_stmt = pg_inserts[0]

        compiled = str(pg_stmt.compile(dialect=postgresql_dialect()))  # type: ignore[no-untyped-call]
        assert "INSERT INTO blockstate_checkpoints" in compiled
        assert "ON CONFLICT (session_id) DO UPDATE SET" in compiled
        assert "blockstate_checkpoints.revision_id +" in compiled

        await backend.release_lease(lease)
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_postgres_register_upcaster_dynamically(tmp_path: Any) -> None:
    """Verify registering an upcaster dynamically on PostgresStorageBackend."""
    db_file = str(tmp_path / "pg_upcast.db")
    dsn = f"sqlite+aiosqlite:///{db_file}"
    backend = PostgresStorageBackend(dsn=dsn, target_schema_version=2)
    try:
        backend.register_upcaster(
            1,
            lambda d: {**d, "schema_version": 2, "state": {**d.get("state", {}), "migrated": True}},
        )
        lease = await backend.acquire_lease("session_pg_upcast", ttl_ms=10000)
        cp = SessionCheckpoint(session_id="session_pg_upcast", schema_version=1, revision_id=0)
        await backend.save_checkpoint(cp, lease)

        loaded = await backend.load_checkpoint("session_pg_upcast")
        assert loaded is not None
        assert loaded.schema_version == 2
        assert loaded.state.get("migrated") is True
        await backend.release_lease(lease)
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_postgres_fallback_dialect_upsert(tmp_path: Any, monkeypatch: Any) -> None:
    """Verify standard fallback branch when engine dialect is generic/other."""
    db_file = str(tmp_path / "fallback_dialect.db")
    dsn = f"sqlite+aiosqlite:///{db_file}"
    backend = PostgresStorageBackend(dsn=dsn)
    try:
        await backend._ensure_tables()
        monkeypatch.setattr(backend._engine.dialect, "name", "other")

        lease = await backend.acquire_lease("session_fallback", ttl_ms=10000)
        # Initial insert
        cp0 = SessionCheckpoint(session_id="session_fallback", schema_version=1, revision_id=0)
        await backend.save_checkpoint(cp0, lease)

        # Update existing
        cp1 = SessionCheckpoint(session_id="session_fallback", schema_version=1, revision_id=1)
        await backend.save_checkpoint(cp1, lease)

        loaded = await backend.load_checkpoint("session_fallback")
        assert loaded is not None
        assert loaded.revision_id == 1
        await backend.release_lease(lease)
    finally:
        await backend.close()
