"""Unit and contract tests for FileLedgerSink, PostgresLedgerSink, and S3LedgerSink."""

import os
import shutil
import tempfile
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects.postgresql import Insert as PGInsert
from sqlalchemy.dialects.postgresql import dialect as postgresql_dialect
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from blockstate.adapters.ledger.file import FileLedgerSink
from blockstate.adapters.ledger.postgres import PostgresLedgerSink
from blockstate.adapters.ledger.s3 import S3LedgerSink
from blockstate.ports.ledger import TurnLedgerRecord
from blockstate.testing.contracts import LedgerSinkContractSuite


class TestFileLedgerSinkContract(LedgerSinkContractSuite):
    """Execute complete LedgerSinkContractSuite against FileLedgerSink."""

    __test__ = True

    def setup_method(self) -> None:
        """Create isolated temporary directory for test ledger file."""
        self._temp_dir = tempfile.mkdtemp(prefix="blockstate_file_ledger_test_")
        self._file_path = os.path.join(self._temp_dir, "ledger.jsonl")

    def teardown_method(self) -> None:
        """Clean up temporary directory and files."""
        if os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def create_sink(self) -> FileLedgerSink:
        """Create initialised FileLedgerSink instance."""
        return FileLedgerSink(file_path=self._file_path)


class TestPostgresLedgerSinkContract(LedgerSinkContractSuite):
    """Execute complete LedgerSinkContractSuite against PostgresLedgerSink.

    Uses an asynchronous SQLite dialect engine for hermetic local test execution.
    """

    __test__ = True

    def setup_method(self) -> None:
        """Create isolated temporary directory for test database."""
        self._temp_dir = tempfile.mkdtemp(prefix="blockstate_postgres_ledger_test_")
        self._db_path = os.path.join(self._temp_dir, "test_ledger.db")
        self._dsn = f"sqlite+aiosqlite:///{self._db_path}"

    def teardown_method(self) -> None:
        """Clean up temporary directory and database files."""
        if os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def create_sink(self) -> PostgresLedgerSink:
        """Create initialised PostgresLedgerSink instance."""
        return PostgresLedgerSink(dsn=self._dsn)


class AsyncMockBody:
    """Async body reader test double mimicking aiobotocore response stream."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self) -> bytes:
        return self._data


class InMemoryS3Client:
    """In-memory S3 client test double for hermetic aiobotocore testing."""

    def __init__(self) -> None:
        self.storage: dict[str, dict[str, bytes]] = {}

    async def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str = "application/json",
    ) -> dict[str, Any]:
        if Bucket not in self.storage:
            self.storage[Bucket] = {}
        self.storage[Bucket][Key] = Body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    async def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        if Bucket not in self.storage or Key not in self.storage[Bucket]:
            raise KeyError(f"Key {Key} not found in bucket {Bucket}")
        return {"Body": AsyncMockBody(self.storage[Bucket][Key])}

    async def list_objects_v2(
        self, *, Bucket: str, Prefix: str = ""
    ) -> dict[str, Any]:
        if Bucket not in self.storage:
            return {"Contents": []}
        matched_keys = sorted(
            [k for k in self.storage[Bucket] if k.startswith(Prefix)]
        )
        return {"Contents": [{"Key": k} for k in matched_keys]}

    async def close(self) -> None:
        pass


class TestS3LedgerSinkContract(LedgerSinkContractSuite):
    """Execute complete LedgerSinkContractSuite against S3LedgerSink with in-memory client."""

    __test__ = True

    def setup_method(self) -> None:
        """Initialise mock client and bucket name."""
        self._mock_client = InMemoryS3Client()
        self._bucket_name = "test-audit-ledger-bucket"

    def create_sink(self) -> S3LedgerSink:
        """Create initialised S3LedgerSink instance using mock client."""
        return S3LedgerSink(
            bucket_name=self._bucket_name,
            prefix="test_ledger",
            client=self._mock_client,
        )


# =============================================================================
# Direct unit tests for FileLedgerSink edge cases
# =============================================================================


@pytest.mark.asyncio
async def test_file_ledger_sink_existing_file_deduplication(tmp_path: Any) -> None:
    """Verify FileLedgerSink pre-loads existing hashes and ignores corrupt lines."""
    file_path = str(tmp_path / "existing.jsonl")
    sink1 = FileLedgerSink(file_path=file_path)

    rec1 = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="session-init",
        turn_index=0,
        stage_from="start",
        stage_to="end",
        exposed_tools=("tool_a",),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="h" * 64,
    )
    await sink1.append(rec1)
    await sink1.close()

    # Append corrupt line manually to test defensive parsing
    with open(file_path, "a", encoding="utf-8") as f:
        f.write("corrupted non-json line\n")

    # Second sink instance should load rec1 hash and survive corrupt line
    sink2 = FileLedgerSink(file_path=file_path)
    assert rec1.record_hash in sink2._seen_hashes

    # Re-append rec1 should be skipped
    await sink2.append(rec1)
    await sink2.flush()

    records = await sink2.get_records()
    assert len(records) == 1
    assert records[0].record_hash == rec1.record_hash


@pytest.mark.asyncio
async def test_file_ledger_sink_nonexistent_file_get_records(tmp_path: Any) -> None:
    """Verify get_records on a nonexistent file returns empty list."""
    sink = FileLedgerSink(file_path=str(tmp_path / "nonexistent.jsonl"))
    records = await sink.get_records()
    assert records == []


# =============================================================================
# Direct unit tests for PostgresLedgerSink edge cases
# =============================================================================


def test_postgres_ledger_sink_dsn_normalisation() -> None:
    """Verify DSN normalisation from postgres:// and postgresql:// to postgresql+asyncpg://."""
    s1 = PostgresLedgerSink(dsn="postgres://user:secret@db.internal:5432/blockstate")
    assert s1.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/blockstate"

    s2 = PostgresLedgerSink(dsn="postgresql://user:secret@db.internal:5432/blockstate")
    assert s2.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/blockstate"

    s3 = PostgresLedgerSink(dsn="postgresql+asyncpg://user:secret@db.internal:5432/blockstate")
    assert s3.dsn == "postgresql+asyncpg://user:secret@db.internal:5432/blockstate"

    s_default = PostgresLedgerSink(dsn="")
    assert "postgresql+asyncpg://" in s_default.dsn

    s_whitespace = PostgresLedgerSink(dsn="   \t\n  ")
    assert "postgresql+asyncpg://" in s_whitespace.dsn


@pytest.mark.asyncio
async def test_postgres_ledger_sink_engine_injection(tmp_path: Any) -> None:
    """Verify injecting a pre-existing AsyncEngine into PostgresLedgerSink."""
    db_file = str(tmp_path / "injected_ledger.db")
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    sink = PostgresLedgerSink(engine=engine)
    try:
        assert sink.engine is engine
        assert "sqlite+aiosqlite" in sink.dsn
    finally:
        await sink.close()


@pytest.mark.asyncio
async def test_postgres_ledger_sink_dialect_upsert_compilation(monkeypatch: Any) -> None:
    """Verify append executes PostgreSQL pg_insert with on_conflict_do_nothing."""
    sink = PostgresLedgerSink(dsn="sqlite+aiosqlite:///:memory:")
    try:
        await sink._ensure_tables()
        monkeypatch.setattr(sink._engine.dialect, "name", "postgresql")

        rec = TurnLedgerRecord(
            prev_record_hash="0" * 64,
            session_id="session-pg-upsert",
            turn_index=0,
            stage_from="start",
            stage_to="end",
            exposed_tools=("tool_a",),
            prompt_hash="p" * 64,
            vaulted_input_hash="i" * 64,
            vaulted_output_hash="o" * 64,
            guard_outcome="allow",
            timestamp_utc="2026-10-27T12:00:00Z",
            record_hash="h" * 64,
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

        await sink.append(rec)

        pg_inserts = [s for s in executed_stmts if isinstance(s, PGInsert)]
        assert len(pg_inserts) == 1
        pg_stmt = pg_inserts[0]

        compiled = str(pg_stmt.compile(dialect=postgresql_dialect()))  # type: ignore[no-untyped-call]
        assert "INSERT INTO blockstate_turn_ledger" in compiled
        assert "ON CONFLICT (record_hash) DO NOTHING" in compiled
    finally:
        await sink.close()


@pytest.mark.asyncio
async def test_postgres_ledger_sink_fallback_dialect_branch(
    tmp_path: Any, monkeypatch: Any
) -> None:
    """Verify generic fallback dialect branch executes without errors."""
    db_file = str(tmp_path / "fallback_ledger.db")
    sink = PostgresLedgerSink(dsn=f"sqlite+aiosqlite:///{db_file}")
    try:
        await sink._ensure_tables()
        monkeypatch.setattr(sink._engine.dialect, "name", "other")

        rec = TurnLedgerRecord(
            prev_record_hash="0" * 64,
            session_id="session-fallback",
            turn_index=0,
            stage_from="start",
            stage_to="end",
            exposed_tools=(),
            prompt_hash="p" * 64,
            vaulted_input_hash="i" * 64,
            vaulted_output_hash="o" * 64,
            guard_outcome="allow",
            timestamp_utc="2026-10-27T12:00:00Z",
            record_hash="h" * 64,
        )
        await sink.append(rec)
        # Duplicate append in fallback dialect should catch IntegrityError safely
        await sink.append(rec)

        records = await sink.get_records("session-fallback")
        assert len(records) == 1
    finally:
        await sink.close()


# =============================================================================
# Direct unit tests for S3LedgerSink edge cases
# =============================================================================


@pytest.mark.asyncio
async def test_s3_ledger_sink_client_lifecycle_and_key_naming() -> None:
    """Verify S3 key generation format and client lifecycle."""
    mock_client = InMemoryS3Client()
    sink = S3LedgerSink(
        bucket_name="my-audit-bucket",
        prefix="compliance/audit/",
        client=mock_client,
    )

    rec = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="user_123",
        turn_index=5,
        stage_from="step1",
        stage_to="step2",
        exposed_tools=("calc",),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="abcde12345" + ("0" * 54),
    )

    key = sink._make_key(rec)
    assert key == f"compliance/audit/user_123/00000005_{rec.record_hash}.json"

    await sink.append(rec)
    stored_keys = list(mock_client.storage["my-audit-bucket"].keys())
    assert key in stored_keys

    records = await sink.get_records("user_123")
    assert len(records) == 1
    assert records[0].record_hash == rec.record_hash
    await sink.close()


@pytest.mark.asyncio
async def test_file_ledger_sink_blank_lines(tmp_path: Any) -> None:
    """Verify FileLedgerSink gracefully skips blank lines during reading and loading."""
    file_path = str(tmp_path / "blank_lines.jsonl")
    sink = FileLedgerSink(file_path=file_path)

    rec = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="session-blank",
        turn_index=0,
        stage_from="start",
        stage_to="end",
        exposed_tools=(),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="h" * 64,
    )
    await sink.append(rec)

    # Inject blank lines into file
    with open(file_path, "a", encoding="utf-8") as f:
        f.write("\n   \n\n")

    records = await sink.get_records()
    assert len(records) == 1
    assert records[0].record_hash == rec.record_hash

    # Re-initialise sink with blank lines present
    sink2 = FileLedgerSink(file_path=file_path)
    assert rec.record_hash in sink2._seen_hashes


@pytest.mark.asyncio
async def test_s3_ledger_sink_aiobotocore_lazy_initialisation() -> None:
    """Verify S3LedgerSink initialises aiobotocore client lazily and closes cleanly."""
    sink = S3LedgerSink(
        bucket_name="test-bucket",
        region_name="us-east-1",
        aws_access_key_id="mock_key",
        aws_secret_access_key="mock_secret",
    )
    client = await sink._get_client()
    assert client is not None
    assert sink._client is client

    # Cached client call
    client2 = await sink._get_client()
    assert client2 is client

    await sink.flush()
    await sink.close()
    assert sink._client is None


class MockAsyncPaginator:
    """Mock paginator for S3 list_objects_v2."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    async def paginate(self, **kwargs: Any) -> Any:
        for page in self._pages:
            yield page


@pytest.mark.asyncio
async def test_s3_ledger_sink_paginator_branch() -> None:
    """Verify S3LedgerSink get_records with paginator."""
    rec = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="user_paginator",
        turn_index=0,
        stage_from="step1",
        stage_to="step2",
        exposed_tools=(),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="paginator_hash" + ("0" * 50),
    )
    key = f"ledger/user_paginator/00000000_{rec.record_hash}.json"
    body_data = rec.model_dump_json().encode("utf-8")

    class ClientWithPaginator:
        def __init__(self) -> None:
            self.closed = False

        def get_paginator(self, operation_name: str) -> MockAsyncPaginator:
            return MockAsyncPaginator([{"Contents": [{"Key": key}]}])

        async def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"Body": AsyncMockBody(body_data)}

        async def close(self) -> None:
            self.closed = True

    sink = S3LedgerSink(
        bucket_name="paginator-bucket",
        prefix="ledger",
        client=ClientWithPaginator(),
    )
    records = await sink.get_records()
    assert len(records) == 1
    assert records[0].record_hash == rec.record_hash


def test_json_deserialised_record_hashable() -> None:
    """Verify that a TurnLedgerRecord deserialised from JSON is hashable in sets and dicts."""
    raw_json = (
        '{"prev_record_hash": "0000", "session_id": "s1", "turn_index": 0, '
        '"stage_from": "a", "stage_to": "b", "exposed_tools": ["tool1", "tool2"], '
        '"prompt_hash": "ph", "vaulted_input_hash": "ih", "vaulted_output_hash": "oh", '
        '"guard_outcome": "allow", "timestamp_utc": "2026-10-27T12:00:00Z", '
        '"record_hash": "rh"}'
    )
    record = TurnLedgerRecord.model_validate_json(raw_json)
    assert isinstance(record.exposed_tools, tuple)
    record_set = {record}
    assert record in record_set
    assert hash(record) is not None


@pytest.mark.asyncio
async def test_file_ledger_sink_non_utf8_recovery(tmp_path: Any) -> None:
    """Verify FileLedgerSink survives non-utf-8 bytes in ledger file using errors='replace'."""
    file_path = str(tmp_path / "non_utf8.jsonl")

    # Write corrupt non-UTF-8 bytes
    with open(file_path, "wb") as f:
        f.write(b"\x80\xff\xfe\n")

    sink = FileLedgerSink(file_path=file_path)
    records = await sink.get_records()
    assert records == []

    # Appending a valid record succeeds and works normally
    rec = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="session-utf8",
        turn_index=0,
        stage_from="start",
        stage_to="end",
        exposed_tools=(),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="h" * 64,
    )
    await sink.append(rec)
    records2 = await sink.get_records()
    assert len(records2) == 1
    assert records2[0].record_hash == rec.record_hash


@pytest.mark.asyncio
async def test_s3_ledger_sink_continuation_token_and_directory_markers() -> None:
    """Verify fallback list_objects_v2 loops with ContinuationToken and skips non-json keys."""
    rec1 = TurnLedgerRecord(
        prev_record_hash="0" * 64,
        session_id="session_multi",
        turn_index=0,
        stage_from="s1",
        stage_to="s2",
        exposed_tools=(),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:00:00Z",
        record_hash="h1" + ("0" * 62),
    )
    rec2 = TurnLedgerRecord(
        prev_record_hash=rec1.record_hash,
        session_id="session_multi",
        turn_index=1,
        stage_from="s2",
        stage_to="s3",
        exposed_tools=(),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc="2026-10-27T12:01:00Z",
        record_hash="h2" + ("0" * 62),
    )

    class MultiPageS3Client:
        def __init__(self) -> None:
            self.closed = False

        async def list_objects_v2(
            self, *, Bucket: str, Prefix: str = "", ContinuationToken: str | None = None
        ) -> dict[str, Any]:
            if not ContinuationToken:
                return {
                    "Contents": [
                        {"Key": "ledger/session_multi/"},  # directory marker (non-json)
                        {"Key": f"ledger/session_multi/00000000_{rec1.record_hash}.json"},
                        {"Key": "ledger/session_multi/corrupt.json"},  # corrupted json
                    ],
                    "IsTruncated": True,
                    "NextContinuationToken": "page2_token",
                }
            return {
                "Contents": [
                    {"Key": f"ledger/session_multi/00000001_{rec2.record_hash}.json"},
                ],
                "IsTruncated": False,
            }

        async def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
            if rec1.record_hash in Key:
                return {"Body": AsyncMockBody(rec1.model_dump_json().encode("utf-8"))}
            if rec2.record_hash in Key:
                return {"Body": AsyncMockBody(rec2.model_dump_json().encode("utf-8"))}
            if "corrupt.json" in Key:
                return {"Body": AsyncMockBody(b"invalid-not-json-content")}
            raise KeyError(Key)

        async def close(self) -> None:
            self.closed = True

    sink = S3LedgerSink(
        bucket_name="multi-page-bucket",
        prefix="ledger",
        client=MultiPageS3Client(),
    )
    records = await sink.get_records("session_multi")
    assert len(records) == 2
    assert records[0].record_hash == rec1.record_hash
    assert records[1].record_hash == rec2.record_hash


