"""PostgreSQL LedgerSink implementation using async SQLAlchemy.

Provides append-only persistence of TurnLedger records to a relational database
backed by SQLAlchemy[asyncio], with dialect-specific conflict idempotency.
"""

import asyncio
import contextlib
import json
from typing import Any

from sqlalchemy import (
    Column,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    select,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from blockstate.config import BlockstateSettings
from blockstate.ports.ledger import TurnLedgerRecord


def _build_ledger_metadata(table_name: str) -> tuple[MetaData, Table]:
    """Construct SQLAlchemy Table metadata schema for turn ledger records."""
    meta = MetaData()
    table = Table(
        table_name,
        meta,
        Column("record_hash", String(64), primary_key=True),
        Column("session_id", String(255), nullable=False, index=True),
        Column("turn_index", Integer, nullable=False),
        Column("prev_record_hash", String(64), nullable=False),
        Column("stage_from", String(255), nullable=False),
        Column("stage_to", String(255), nullable=False),
        Column("exposed_tools_json", Text, nullable=False),
        Column("prompt_hash", String(64), nullable=False),
        Column("vaulted_input_hash", String(64), nullable=False),
        Column("vaulted_output_hash", String(64), nullable=False),
        Column("guard_outcome", String(255), nullable=False),
        Column("timestamp_utc", String(64), nullable=False),
        Index("ix_blockstate_ledger_session_turn", "session_id", "turn_index"),
    )
    return meta, table


class PostgresLedgerSink:
    """Audit sink persisting TurnLedger records to PostgreSQL via async SQLAlchemy."""

    def __init__(
        self,
        dsn: str | None = None,
        *,
        engine: AsyncEngine | None = None,
        pool_size: int = 20,
        max_overflow: int = 10,
        table_name: str = "blockstate_turn_ledger",
    ) -> None:
        self._raw_dsn = dsn
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._table_name = table_name
        self._lock = asyncio.Lock()
        self._tables_created = False

        self.metadata, self.table = _build_ledger_metadata(table_name)

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

    def _normalise_dsn(self, dsn: str | None) -> str:
        """Normalise PostgreSQL DSN strings for asyncpg driver compatibility."""
        if not dsn or not dsn.strip():
            settings = BlockstateSettings()
            dsn = settings.postgres_dsn.get_secret_value()
        if not dsn or not dsn.strip():
            dsn = "postgresql+asyncpg://localhost:5432/blockstate"

        cleaned = dsn.strip()
        if cleaned.startswith("postgres://"):
            cleaned = "postgresql+asyncpg://" + cleaned[len("postgres://"):]
        elif cleaned.startswith("postgresql://") and not cleaned.startswith("postgresql+"):
            cleaned = "postgresql+asyncpg://" + cleaned[len("postgresql://"):]
        return cleaned

    async def _ensure_tables(self) -> None:
        """Ensure required ledger table exists in the target database."""
        if not self._tables_created:
            async with self._lock:
                if not self._tables_created:
                    async with self._engine.begin() as conn:
                        await conn.run_sync(self.metadata.create_all)
                    self._tables_created = True

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a validated turn record to the relational database idempotently."""
        await self._ensure_tables()

        row_data: dict[str, Any] = {
            "record_hash": record.record_hash,
            "session_id": record.session_id,
            "turn_index": record.turn_index,
            "prev_record_hash": record.prev_record_hash,
            "stage_from": record.stage_from,
            "stage_to": record.stage_to,
            "exposed_tools_json": json.dumps(list(record.exposed_tools)),
            "prompt_hash": record.prompt_hash,
            "vaulted_input_hash": record.vaulted_input_hash,
            "vaulted_output_hash": record.vaulted_output_hash,
            "guard_outcome": record.guard_outcome,
            "timestamp_utc": record.timestamp_utc,
        }

        dialect_name = self._engine.dialect.name
        async with self._engine.begin() as conn:
            if dialect_name == "postgresql":
                pg_stmt = (
                    pg_insert(self.table)
                    .values(**row_data)
                    .on_conflict_do_nothing(index_elements=["record_hash"])
                )
                await conn.execute(pg_stmt)
            elif dialect_name == "sqlite":
                sqlite_stmt = (
                    sqlite_insert(self.table)
                    .values(**row_data)
                    .on_conflict_do_nothing(index_elements=["record_hash"])
                )
                await conn.execute(sqlite_stmt)
            else:
                with contextlib.suppress(IntegrityError):
                    await conn.execute(self.table.insert().values(**row_data))

    async def flush(self) -> None:
        """Flush buffered turn records to durable storage."""
        # Connection pool transactions are committed per execution block
        pass

    async def close(self) -> None:
        """Close the underlying engine if owned."""
        if self._engine_owned:
            await self._engine.dispose()

    async def get_records(self, session_id: str | None = None) -> list[TurnLedgerRecord]:
        """Retrieve stored turn records optionally filtered by session identifier."""
        await self._ensure_tables()
        stmt = select(self.table).order_by(self.table.c.session_id, self.table.c.turn_index)
        if session_id is not None:
            stmt = stmt.where(self.table.c.session_id == session_id)

        records: list[TurnLedgerRecord] = []
        async with self._engine.connect() as conn:
            result = await conn.execute(stmt)
            for row in result:
                records.append(
                    TurnLedgerRecord(
                        record_hash=row.record_hash,
                        session_id=row.session_id,
                        turn_index=row.turn_index,
                        prev_record_hash=row.prev_record_hash,
                        stage_from=row.stage_from,
                        stage_to=row.stage_to,
                        exposed_tools=tuple(json.loads(row.exposed_tools_json)),
                        prompt_hash=row.prompt_hash,
                        vaulted_input_hash=row.vaulted_input_hash,
                        vaulted_output_hash=row.vaulted_output_hash,
                        guard_outcome=row.guard_outcome,
                        timestamp_utc=row.timestamp_utc,
                    )
                )

        return records


__all__: list[str] = ["PostgresLedgerSink"]
