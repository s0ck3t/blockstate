"""Asynchronous session-partitioned TurnLedger ring buffer with WAL drain and recovery.

Provides non-blocking emission of audit records, per-session monotonic causal ordering,
transactional outbox acknowledgement, graceful drain on shutdown, and emergency
Write-Ahead Log (WAL) spilling to prevent audit trail loss.
"""

import asyncio
import contextlib
import logging
import os
import signal
from collections.abc import Awaitable, Callable
from pathlib import Path

from blockstate.ports.ledger import LedgerSink, TurnLedgerRecord
from blockstate.ports.storage import StorageBackend

logger = logging.getLogger(__name__)


class SessionPartitionedRingBuffer:
    """Asynchronous session-partitioned ring buffer for TurnLedger records."""

    def __init__(
        self,
        sink: LedgerSink,
        *,
        storage: StorageBackend | None = None,
        wal_path: str | Path = ".blockstate/wal/ledger.wal",
        drain_timeout_seconds: float = 10.0,
        max_buffer_size: int = 10000,
        outbox_ack_callback: Callable[[TurnLedgerRecord], Awaitable[None]] | None = None,
    ) -> None:
        self.sink = sink
        self.storage = storage
        self.wal_path = Path(wal_path)
        self.drain_timeout_seconds = drain_timeout_seconds
        self.max_buffer_size = max_buffer_size
        self.outbox_ack_callback = outbox_ack_callback

        self._session_queues: dict[str, asyncio.Queue[TurnLedgerRecord]] = {}
        self._session_tasks: dict[str, asyncio.Task[None]] = {}
        self._pending_records: set[TurnLedgerRecord] = set()
        self._dispatch_errors: list[Exception] = []
        self._lock = asyncio.Lock()
        self._draining = False
        self._closed = False

        self._register_signals_defensively()

    @property
    def pending_count(self) -> int:
        """Return the number of unacknowledged records in the ring buffer."""
        return len(self._pending_records)

    @property
    def active_sessions(self) -> list[str]:
        """Return list of session identifiers currently registered in the buffer."""
        return list(self._session_queues.keys())

    def _register_signals_defensively(self) -> None:
        """Register signal handlers for SIGINT and SIGTERM where supported."""
        try:
            import threading

            if threading.current_thread() is threading.main_thread():
                loop = asyncio.get_event_loop()
                for sig_name in ("SIGINT", "SIGTERM"):
                    sig = getattr(signal, sig_name, None)
                    if sig is not None:
                        with contextlib.suppress(NotImplementedError, RuntimeError):
                            loop.add_signal_handler(
                                sig,
                                lambda: asyncio.create_task(self.drain(self.drain_timeout_seconds)),
                            )
        except Exception:
            pass

    def enqueue(self, record: TurnLedgerRecord) -> None:
        """Enqueue a TurnLedgerRecord into its session partition non-blockingly."""
        if self._closed:
            raise RuntimeError("SessionPartitionedRingBuffer is closed")

        self._pending_records.add(record)

        session_id = record.session_id
        if session_id not in self._session_queues:
            self._session_queues[session_id] = asyncio.Queue(maxsize=self.max_buffer_size)

        queue = self._session_queues[session_id]
        try:
            queue.put_nowait(record)
        except asyncio.QueueFull:
            self._pending_records.discard(record)
            raise

        if session_id not in self._session_tasks or self._session_tasks[session_id].done():
            task = asyncio.create_task(self._process_session_queue(session_id))
            self._session_tasks[session_id] = task

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a record satisfying the LedgerSink protocol via non-blocking enqueue."""
        self.enqueue(record)

    async def _process_session_queue(self, session_id: str) -> None:
        """Worker task consuming records for a single session in strict causal order."""
        queue = self._session_queues.get(session_id)
        if queue is None:
            return
        try:
            while True:
                if self._draining and queue.empty():
                    break
                try:
                    record = await asyncio.wait_for(queue.get(), timeout=2.0)
                except TimeoutError:
                    if queue.empty():
                        break
                    continue

                try:
                    await self._dispatch_record(record)
                except Exception as exc:
                    logger.warning(
                        "Sink dispatch failed for record %s: %s", record.record_hash, exc
                    )
                    self._dispatch_errors.append(exc)
                    # Stop processing this session partition to prevent hash chain corruption
                    break
                finally:
                    queue.task_done()
        finally:
            self._session_tasks.pop(session_id, None)
            if session_id in self._session_queues and self._session_queues[session_id].empty():
                self._session_queues.pop(session_id, None)

    async def _dispatch_record(self, record: TurnLedgerRecord) -> None:
        """Dispatch a single record to the sink and acknowledge outbox entry."""
        await self.sink.append(record)
        self._pending_records.discard(record)

        if self.outbox_ack_callback is not None:
            try:
                await self.outbox_ack_callback(record)
            except Exception as exc:
                logger.warning(
                    "Outbox acknowledgement callback failed for %s: %s",
                    record.record_hash,
                    exc,
                )

        if self.storage is not None:
            try:
                await self._ack_storage_outbox(record)
            except Exception as exc:
                logger.warning(
                    "Storage outbox acknowledgement failed for %s: %s",
                    record.record_hash,
                    exc,
                )

    async def _ack_storage_outbox(self, record: TurnLedgerRecord) -> None:
        """Clear entry from SessionCheckpoint.pending_ledger_outbox if present."""
        if self.storage is None:
            return

        cp = await self.storage.load_checkpoint(record.session_id)
        if cp is None or not cp.pending_ledger_outbox:
            return

        matching = [
            e
            for e in cp.pending_ledger_outbox
            if e.get("record_hash") == record.record_hash
            or e.get("turn_index") == record.turn_index
        ]
        if not matching:
            return

        try:
            lease = await self.storage.acquire_lease(
                record.session_id, ttl_ms=10000, wait_timeout_ms=1000
            )
            try:
                latest = await self.storage.load_checkpoint(record.session_id)
                if latest is not None and latest.pending_ledger_outbox:
                    filtered_outbox = tuple(
                        e
                        for e in latest.pending_ledger_outbox
                        if e.get("record_hash") != record.record_hash
                        and e.get("turn_index") != record.turn_index
                    )
                    updated_cp = latest.model_copy(
                        update={
                            "revision_id": latest.revision_id + 1,
                            "pending_ledger_outbox": filtered_outbox,
                        }
                    )
                    await self.storage.save_checkpoint(updated_cp, lease)
            finally:
                await self.storage.release_lease(lease)
        except Exception as exc:
            logger.warning("Could not update pending_ledger_outbox: %s", exc)

    async def flush(self) -> None:
        """Wait for currently queued partition records to dispatch and flush sink."""
        await self.wait_idle(timeout=self.drain_timeout_seconds)
        if self._dispatch_errors:
            err = self._dispatch_errors.pop(0)
            raise RuntimeError(f"Ledger sink dispatch failed: {err}") from err

    async def wait_idle(self, timeout: float = 10.0) -> None:
        """Wait until all currently queued items across all partitions have been written."""

        async def _wait() -> None:
            for session_id, queue in list(self._session_queues.items()):
                task = self._session_tasks.get(session_id)
                if task is not None and not task.done():
                    await queue.join()
            await self.sink.flush()

        await asyncio.wait_for(_wait(), timeout=timeout)

    def _spill_to_wal(self, records: list[TurnLedgerRecord]) -> list[TurnLedgerRecord]:
        """Spill unacknowledged records to local Write-Ahead Log (.blockstate/wal/ledger.wal)."""
        if not records:
            return []

        sorted_records = sorted(records, key=lambda r: (r.session_id, r.turn_index))
        self.wal_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.wal_path, "a", encoding="utf-8") as f:
            for r in sorted_records:
                f.write(r.model_dump_json() + "\n")
            f.flush()
            with contextlib.suppress(AttributeError, OSError):
                os.fsync(f.fileno())
        return sorted_records

    async def drain(self, timeout_seconds: float = 10.0) -> list[TurnLedgerRecord]:
        """Gracefully drain buffered records to sink; spill unacknowledged records to WAL."""
        self._draining = True
        spilled_records: list[TurnLedgerRecord] = []

        async def _drain_queues() -> None:
            for queue in list(self._session_queues.values()):
                await queue.join()
            await self.sink.flush()

        try:
            await asyncio.wait_for(_drain_queues(), timeout=timeout_seconds)
        except Exception as exc:
            logger.warning("Drain timed out or encountered sink error: %s. Spilling to WAL.", exc)

        if self._pending_records:
            spilled_records = self._spill_to_wal(list(self._pending_records))
            self._pending_records.clear()

        # Cancel remaining session tasks
        for task in list(self._session_tasks.values()):
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        return spilled_records

    async def close(self) -> None:
        """Close the ring buffer, drain remaining records, and close the sink."""
        if not self._closed:
            self._closed = True
            await self.drain(timeout_seconds=self.drain_timeout_seconds)
            if hasattr(self.sink, "close") and callable(self.sink.close):
                res = self.sink.close()
                if asyncio.iscoroutine(res):
                    await res


async def recover_wal(wal_path: str | Path, sink: LedgerSink) -> int:
    """Replay spilled records from WAL file into the ledger sink upon startup.

    Enforces causal ordering and removes the WAL file once successfully flushed.
    Returns the count of replayed records.
    """
    path = Path(wal_path)
    if not path.exists():
        return 0

    lines: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                lines.append(stripped)

    if not lines:
        path.unlink(missing_ok=True)
        return 0

    records: list[TurnLedgerRecord] = []
    for line in lines:
        try:
            records.append(TurnLedgerRecord.model_validate_json(line))
        except Exception as exc:
            logger.warning("Skipping corrupted or truncated WAL line: %s (%s)", line, exc)

    if not records:
        path.unlink(missing_ok=True)
        return 0

    # Enforce strict causal ordering per session
    records.sort(key=lambda r: (r.session_id, r.turn_index))

    for rec in records:
        await sink.append(rec)
    await sink.flush()

    # Once flush succeeds without error, delete WAL file
    path.unlink(missing_ok=True)
    return len(records)


__all__: list[str] = [
    "SessionPartitionedRingBuffer",
    "recover_wal",
]
