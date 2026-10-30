"""File-based JSONL LedgerSink implementation with durable disk flush.

Provides append-only persistence of TurnLedger records to local JSON Lines (.jsonl)
files with idempotent deduplication and fsync durability.
"""

import asyncio
import contextlib
import os
from pathlib import Path

from blockstate.ports.ledger import TurnLedgerRecord


class FileLedgerSink:
    """Audit sink persisting TurnLedger records to a local JSONL file."""

    def __init__(self, file_path: str | Path = ".blockstate/ledger.jsonl") -> None:
        self.file_path = Path(file_path)
        self._lock = asyncio.Lock()
        self._seen_hashes: set[str] = set()
        self._initialise_seen_hashes()

    def _initialise_seen_hashes(self) -> None:
        """Scan existing file if present to initialise seen record hashes."""
        if not self.file_path.exists():
            return
        with (
            contextlib.suppress(OSError),
            open(self.file_path, encoding="utf-8", errors="replace") as f,
        ):
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                with contextlib.suppress(Exception):
                    record = TurnLedgerRecord.model_validate_json(stripped)
                    self._seen_hashes.add(record.record_hash)

    def _write_and_sync(self, line: str) -> None:
        """Write line and perform fsync in worker thread."""
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            with contextlib.suppress(AttributeError, OSError):
                os.fsync(f.fileno())

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a validated turn record to the JSONL audit file idempotently."""
        async with self._lock:
            if record.record_hash in self._seen_hashes:
                return

            line = record.model_dump_json() + "\n"
            await asyncio.to_thread(self._write_and_sync, line)
            self._seen_hashes.add(record.record_hash)

    async def flush(self) -> None:
        """Flush buffered turn records to durable disk storage."""
        # Each append synchronously flushes and fsyncs the file via to_thread
        pass

    async def close(self) -> None:
        """Close the sink and release filesystem resources."""
        await self.flush()

    def _read_records_sync(self, session_id: str | None) -> list[TurnLedgerRecord]:
        """Read and parse records from JSONL file in worker thread."""
        if not self.file_path.exists():
            return []

        records: list[TurnLedgerRecord] = []
        with open(self.file_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                with contextlib.suppress(Exception):
                    record = TurnLedgerRecord.model_validate_json(stripped)
                    if session_id is None or record.session_id == session_id:
                        records.append(record)

        # Sort by turn_index ascending per session
        records.sort(key=lambda r: (r.session_id, r.turn_index))
        return records

    async def get_records(self, session_id: str | None = None) -> list[TurnLedgerRecord]:
        """Retrieve stored turn records optionally filtered by session identifier."""
        await self.flush()
        return await asyncio.to_thread(self._read_records_sync, session_id)


__all__: list[str] = ["FileLedgerSink"]
