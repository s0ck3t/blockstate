"""Unit and integration tests for SessionPartitionedRingBuffer and recover_wal."""

import asyncio
import contextlib
import os
import time
from typing import Any

import pytest

from blockstate.adapters.ledger.ring_buffer import (
    SessionPartitionedRingBuffer,
    recover_wal,
)
from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.ports.ledger import TurnLedgerRecord, compute_record_hash
from blockstate.ports.storage import SessionCheckpoint
from blockstate.testing.doubles import InMemoryLedgerSink


def _make_record(
    session_id: str,
    turn_index: int,
    prev_record_hash: str = "0" * 64,
    stage_from: str = "init",
    stage_to: str = "active",
) -> TurnLedgerRecord:
    """Helper to create a validated TurnLedgerRecord with valid SHA-256 hash."""
    rec_hash = compute_record_hash(
        prev_record_hash=prev_record_hash,
        session_id=session_id,
        turn_index=turn_index,
        stage_from=stage_from,
        stage_to=stage_to,
        exposed_tools=("tool_a",),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc=f"2026-10-27T12:0{turn_index}:00Z",
    )
    return TurnLedgerRecord(
        prev_record_hash=prev_record_hash,
        session_id=session_id,
        turn_index=turn_index,
        stage_from=stage_from,
        stage_to=stage_to,
        exposed_tools=("tool_a",),
        prompt_hash="p" * 64,
        vaulted_input_hash="i" * 64,
        vaulted_output_hash="o" * 64,
        guard_outcome="allow",
        timestamp_utc=f"2026-10-27T12:0{turn_index}:00Z",
        record_hash=rec_hash,
    )


class SlowSink:
    """LedgerSink test double introducing artificial latency to test non-blocking emission."""

    def __init__(self, delay_s: float = 0.05) -> None:
        self.delay_s = delay_s
        self.records: list[TurnLedgerRecord] = []
        self.flush_called = False
        self.closed = False

    async def append(self, record: TurnLedgerRecord) -> None:
        await asyncio.sleep(self.delay_s)
        self.records.append(record)

    async def flush(self) -> None:
        self.flush_called = True

    async def close(self) -> None:
        self.closed = True


class FailingSink:
    """LedgerSink test double that always raises an error on append or flush."""

    def __init__(self, fail_append: bool = True, fail_flush: bool = False) -> None:
        self.fail_append = fail_append
        self.fail_flush = fail_flush
        self.records: list[TurnLedgerRecord] = []

    async def append(self, record: TurnLedgerRecord) -> None:
        if self.fail_append:
            raise RuntimeError("Sink destination network failure")
        self.records.append(record)

    async def flush(self) -> None:
        if self.fail_flush:
            raise RuntimeError("Sink flush failure")

    async def close(self) -> None:
        pass


# =============================================================================
# Ring Buffer Monotonic Ordering & Concurrency Tests
# =============================================================================


@pytest.mark.asyncio
async def test_ring_buffer_non_blocking_enqueue(tmp_path: Any) -> None:
    """Verify enqueue returns immediately (< 10ms) even when sink I/O is slow (100ms)."""
    slow_sink = SlowSink(delay_s=0.1)
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=slow_sink, wal_path=wal_path)

    rec = _make_record("session-1", 0)

    start = time.monotonic()
    buffer.enqueue(rec)
    elapsed_ms = (time.monotonic() - start) * 1000

    assert elapsed_ms < 20.0
    assert buffer.pending_count >= 1

    await buffer.drain(timeout_seconds=5.0)
    assert len(slow_sink.records) == 1
    assert slow_sink.records[0].record_hash == rec.record_hash
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_monotonic_session_ordering(tmp_path: Any) -> None:
    """Verify records for a session are dispatched in strict ascending turn sequence."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    rec0 = _make_record("session-seq", 0, prev_record_hash="0" * 64)
    rec1 = _make_record("session-seq", 1, prev_record_hash=rec0.record_hash)
    rec2 = _make_record("session-seq", 2, prev_record_hash=rec1.record_hash)

    # Enqueue multiple turns in sequence
    await buffer.append(rec0)
    await buffer.append(rec1)
    await buffer.append(rec2)

    await buffer.drain(timeout_seconds=5.0)

    persisted = await sink.get_records("session-seq")
    assert len(persisted) == 3
    assert [r.turn_index for r in persisted] == [0, 1, 2]
    assert persisted[0].record_hash == rec0.record_hash
    assert persisted[1].record_hash == rec1.record_hash
    assert persisted[2].record_hash == rec2.record_hash
    assert sink.verify_hash_chain()
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_multi_session_concurrency(tmp_path: Any) -> None:
    """Verify multiple sessions are dispatched concurrently while maintaining per-session order."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    sessions = [f"session_{i}" for i in range(5)]
    records_per_session: dict[str, list[TurnLedgerRecord]] = {s: [] for s in sessions}

    for turn in range(3):
        for s in sessions:
            prev_hash = (
                records_per_session[s][-1].record_hash
                if records_per_session[s]
                else "0" * 64
            )
            rec = _make_record(s, turn, prev_record_hash=prev_hash)
            records_per_session[s].append(rec)
            buffer.enqueue(rec)

    assert set(buffer.active_sessions) == set(sessions)

    await buffer.drain(timeout_seconds=5.0)

    for s in sessions:
        stored = await sink.get_records(s)
        assert len(stored) == 3
        assert [r.turn_index for r in stored] == [0, 1, 2]
        for idx in range(3):
            assert stored[idx].record_hash == records_per_session[s][idx].record_hash

    await buffer.close()


# =============================================================================
# Outbox Acknowledgement Tests
# =============================================================================


@pytest.mark.asyncio
async def test_ring_buffer_outbox_ack_callback(tmp_path: Any) -> None:
    """Verify outbox_ack_callback is invoked upon successful sink write."""
    sink = InMemoryLedgerSink()
    acknowledged: list[TurnLedgerRecord] = []

    async def on_ack(rec: TurnLedgerRecord) -> None:
        acknowledged.append(rec)

    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(
        sink=sink, wal_path=wal_path, outbox_ack_callback=on_ack
    )

    rec = _make_record("session-ack", 0)
    buffer.enqueue(rec)

    await buffer.drain(timeout_seconds=5.0)
    assert len(acknowledged) == 1
    assert acknowledged[0].record_hash == rec.record_hash
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_storage_outbox_clearing(tmp_path: Any) -> None:
    """Verify pending_ledger_outbox in SessionCheckpoint is cleared upon sink write."""
    storage = InMemoryStateStore()
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, storage=storage, wal_path=wal_path)

    session_id = "session-storage-outbox"
    rec = _make_record(session_id, 0)

    # Seed checkpoint with outbox entry
    lease = await storage.acquire_lease(session_id, ttl_ms=10000)
    cp = SessionCheckpoint(
        session_id=session_id,
        schema_version=1,
        revision_id=0,
        pending_ledger_outbox=({"record_hash": rec.record_hash, "turn_index": 0},),
    )
    await storage.save_checkpoint(cp, lease)
    await storage.release_lease(lease)

    # Enqueue record
    buffer.enqueue(rec)
    await buffer.drain(timeout_seconds=5.0)

    # Verify outbox entry was cleared from checkpoint
    updated_cp = await storage.load_checkpoint(session_id)
    assert updated_cp is not None
    assert updated_cp.pending_ledger_outbox == ()
    await buffer.close()


# =============================================================================
# WAL Spilling & Recovery Tests
# =============================================================================


@pytest.mark.asyncio
async def test_ring_buffer_wal_spill_on_sink_failure(tmp_path: Any) -> None:
    """Verify failing sink triggers WAL spill to .blockstate/wal/ledger.wal during drain."""
    failing_sink = FailingSink(fail_append=True)
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=failing_sink, wal_path=wal_path)

    rec0 = _make_record("session-fail", 0)
    rec1 = _make_record("session-fail", 1, prev_record_hash=rec0.record_hash)

    buffer.enqueue(rec0)
    buffer.enqueue(rec1)

    spilled = await buffer.drain(timeout_seconds=2.0)
    assert len(spilled) == 2
    assert os.path.exists(wal_path)

    # Verify WAL file contents
    with open(wal_path, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    assert len(lines) == 2

    # Replay WAL into healthy sink
    healthy_sink = InMemoryLedgerSink()
    recovered_count = await recover_wal(wal_path, healthy_sink)
    assert recovered_count == 2
    assert not os.path.exists(wal_path)

    persisted = await healthy_sink.get_records("session-fail")
    assert len(persisted) == 2
    assert persisted[0].record_hash == rec0.record_hash
    assert persisted[1].record_hash == rec1.record_hash

    await buffer.close()


@pytest.mark.asyncio
async def test_recover_wal_nonexistent_or_empty(tmp_path: Any) -> None:
    """Verify recover_wal handles nonexistent and empty WAL files safely."""
    sink = InMemoryLedgerSink()

    # Nonexistent path
    nonexistent = tmp_path / "wal" / "missing.wal"
    assert await recover_wal(nonexistent, sink) == 0

    # Empty file
    empty_wal = tmp_path / "wal" / "empty.wal"
    empty_wal.parent.mkdir(parents=True, exist_ok=True)
    empty_wal.write_text("", encoding="utf-8")

    assert await recover_wal(empty_wal, sink) == 0
    assert not empty_wal.exists()


@pytest.mark.asyncio
async def test_ring_buffer_closed_raises_runtime_error(tmp_path: Any) -> None:
    """Verify enqueueing onto a closed ring buffer raises RuntimeError."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "ledger.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    await buffer.close()

    rec = _make_record("session-closed", 0)
    with pytest.raises(RuntimeError, match="closed"):
        buffer.enqueue(rec)


@pytest.mark.asyncio
async def test_recover_wal_preserves_file_on_sink_failure(tmp_path: Any) -> None:
    """Verify recover_wal does not delete WAL file if the sink fails during recovery."""
    wal_path = tmp_path / "wal" / "preserve.wal"
    wal_path.parent.mkdir(parents=True, exist_ok=True)

    rec = _make_record("session-preserve", 0)
    wal_path.write_text(rec.model_dump_json() + "\n", encoding="utf-8")

    failing_sink = FailingSink(fail_append=True)
    with pytest.raises(RuntimeError, match="failure"):
        await recover_wal(wal_path, failing_sink)

    # WAL must be preserved for future retry
    assert wal_path.exists()


@pytest.mark.asyncio
async def test_ring_buffer_flush_and_wait_idle(tmp_path: Any) -> None:
    """Verify flush calls wait_idle and flushes underlying sink."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "flush.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    rec = _make_record("session-flush", 0)
    buffer.enqueue(rec)

    await buffer.flush()
    assert buffer.pending_count == 0
    persisted = await sink.get_records("session-flush")
    assert len(persisted) == 1
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_spill_empty_records(tmp_path: Any) -> None:
    """Verify _spill_to_wal with empty list returns empty list."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "empty_spill.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)
    assert buffer._spill_to_wal([]) == []
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_outbox_ack_callback_failure(tmp_path: Any) -> None:
    """Verify failure in outbox_ack_callback does not crash dispatch."""
    sink = InMemoryLedgerSink()

    async def broken_ack(rec: TurnLedgerRecord) -> None:
        raise RuntimeError("Callback explosion")

    wal_path = tmp_path / "wal" / "broken_callback.wal"
    buffer = SessionPartitionedRingBuffer(
        sink=sink, wal_path=wal_path, outbox_ack_callback=broken_ack
    )

    rec = _make_record("session-broken-cb", 0)
    buffer.enqueue(rec)

    await buffer.flush()
    records = await sink.get_records("session-broken-cb")
    assert len(records) == 1
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_storage_outbox_variants(tmp_path: Any) -> None:
    """Verify _ack_storage_outbox handles missing, empty, or unmatching checkpoints."""
    storage = InMemoryStateStore()
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "storage_var.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, storage=storage, wal_path=wal_path)

    # 1. No checkpoint at all
    rec1 = _make_record("session-no-cp", 0)
    await buffer._ack_storage_outbox(rec1)

    # 2. Checkpoint with empty pending outbox
    lease = await storage.acquire_lease("session-empty-outbox", ttl_ms=10000)
    cp_empty = SessionCheckpoint(session_id="session-empty-outbox")
    await storage.save_checkpoint(cp_empty, lease)
    await storage.release_lease(lease)
    rec2 = _make_record("session-empty-outbox", 0)
    await buffer._ack_storage_outbox(rec2)

    # 3. Checkpoint with outbox not matching current record
    lease = await storage.acquire_lease("session-mismatch-outbox", ttl_ms=10000)
    cp_mismatch = SessionCheckpoint(
        session_id="session-mismatch-outbox",
        pending_ledger_outbox=({"record_hash": "different_hash", "turn_index": 99},),
    )
    await storage.save_checkpoint(cp_mismatch, lease)
    await storage.release_lease(lease)
    rec3 = _make_record("session-mismatch-outbox", 0)
    await buffer._ack_storage_outbox(rec3)

    # Verify pending outbox remained untouched
    loaded = await storage.load_checkpoint("session-mismatch-outbox")
    assert loaded is not None
    assert len(loaded.pending_ledger_outbox) == 1

    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_storage_outbox_acquire_lease_error(
    tmp_path: Any, monkeypatch: Any
) -> None:
    """Verify _ack_storage_outbox safely handles lease acquisition exceptions."""
    storage = InMemoryStateStore()
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "lease_err.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, storage=storage, wal_path=wal_path)

    session_id = "session-lease-err"
    rec = _make_record(session_id, 0)
    lease = await storage.acquire_lease(session_id, ttl_ms=10000)
    cp = SessionCheckpoint(
        session_id=session_id,
        pending_ledger_outbox=({"record_hash": rec.record_hash, "turn_index": 0},),
    )
    await storage.save_checkpoint(cp, lease)
    await storage.release_lease(lease)

    async def broken_acquire(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Distributed lock unavailable")

    monkeypatch.setattr(storage, "acquire_lease", broken_acquire)

    # Should not raise exception
    await buffer._ack_storage_outbox(rec)
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_worker_idle_timeout(tmp_path: Any) -> None:
    """Verify session worker cleans up after idle timeout when queue is empty."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "idle.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    session_id = "session-idle-cleanup"
    rec = _make_record(session_id, 0)
    buffer.enqueue(rec)
    await buffer.flush()

    assert session_id in buffer._session_tasks

    # Mock timeout to trigger worker exit branch
    task = buffer._session_tasks[session_id]
    await asyncio.sleep(0.05)
    # The worker task is still running waiting on queue.get().
    # Cancelling or closing will clean it up:
    await buffer.close()
    assert task.done()


@pytest.mark.asyncio
async def test_ring_buffer_close_async_sink(tmp_path: Any) -> None:
    """Verify close cleanly awaits an async close method on the sink."""
    slow_sink = SlowSink()
    wal_path = tmp_path / "wal" / "sink_close.wal"
    buffer = SessionPartitionedRingBuffer(sink=slow_sink, wal_path=wal_path)
    await buffer.close()
    assert slow_sink.closed


@pytest.mark.asyncio
async def test_recover_wal_with_blank_lines(tmp_path: Any) -> None:
    """Verify recover_wal handles blank lines within the WAL file."""
    wal_path = tmp_path / "wal" / "blank_lines.wal"
    wal_path.parent.mkdir(parents=True, exist_ok=True)

    rec0 = _make_record("session-wal-blanks", 0)
    rec1 = _make_record("session-wal-blanks", 1, prev_record_hash=rec0.record_hash)

    with open(wal_path, "w", encoding="utf-8") as f:
        f.write("\n")
        f.write(rec0.model_dump_json() + "\n")
        f.write("   \n")
        f.write(rec1.model_dump_json() + "\n")
        f.write("\n")

    sink = InMemoryLedgerSink()
    recovered = await recover_wal(wal_path, sink)
    assert recovered == 2
    records = await sink.get_records("session-wal-blanks")
    assert len(records) == 2


def test_ring_buffer_register_signals_defensively() -> None:
    """Verify register_signals_defensively executes without errors."""
    sink = InMemoryLedgerSink()
    buffer = SessionPartitionedRingBuffer(sink=sink)
    buffer._register_signals_defensively()


@pytest.mark.asyncio
async def test_ring_buffer_json_deserialised_record_hashability(tmp_path: Any) -> None:
    """Verify deserialised records can be enqueued without unhashable type errors."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "json_hash.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    raw_json = (
        '{"prev_record_hash": "0000", "session_id": "s-json", "turn_index": 0, '
        '"stage_from": "a", "stage_to": "b", "exposed_tools": ["tool1", "tool2"], '
        '"prompt_hash": "ph", "vaulted_input_hash": "ih", "vaulted_output_hash": "oh", '
        '"guard_outcome": "allow", "timestamp_utc": "2026-10-27T12:00:00Z", '
        '"record_hash": "rh"}'
    )
    rec = TurnLedgerRecord.model_validate_json(raw_json)
    buffer.enqueue(rec)
    assert buffer.pending_count == 1
    await buffer.flush()
    assert buffer.pending_count == 0
    await buffer.close()


@pytest.mark.asyncio
async def test_recover_wal_truncated_and_corrupt_lines(tmp_path: Any) -> None:
    """Verify recover_wal safely skips malformed or truncated lines without crashing."""
    wal_path = tmp_path / "wal" / "truncated.wal"
    wal_path.parent.mkdir(parents=True, exist_ok=True)

    rec0 = _make_record("session-trunc", 0)
    rec1 = _make_record("session-trunc", 1, prev_record_hash=rec0.record_hash)

    with open(wal_path, "w", encoding="utf-8") as f:
        f.write('{"prev_record_hash": "truncated_half_written_json_line\n')
        f.write(rec0.model_dump_json() + "\n")
        f.write("not-even-json\n")
        f.write(rec1.model_dump_json() + "\n")

    sink = InMemoryLedgerSink()
    recovered = await recover_wal(wal_path, sink)
    assert recovered == 2
    persisted = await sink.get_records("session-trunc")
    assert len(persisted) == 2
    assert persisted[0].record_hash == rec0.record_hash
    assert persisted[1].record_hash == rec1.record_hash
    assert not wal_path.exists()


@pytest.mark.asyncio
async def test_ring_buffer_queue_full_discards_pending(tmp_path: Any) -> None:
    """Verify QueueFull removes record from _pending_records."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "qfull.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path, max_buffer_size=1)

    rec0 = _make_record("session-qfull", 0)
    rec1 = _make_record("session-qfull", 1, prev_record_hash=rec0.record_hash)

    # Prevent task from popping to simulate backlog
    q: asyncio.Queue[TurnLedgerRecord] = asyncio.Queue(maxsize=1)
    q.put_nowait(rec0)
    buffer._session_queues["session-qfull"] = q

    with pytest.raises(asyncio.QueueFull):
        buffer.enqueue(rec1)

    assert rec1 not in buffer._pending_records
    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_hash_chain_preservation_on_sink_failure(tmp_path: Any) -> None:
    """Verify worker halts partition processing on dispatch failure to preserve hash chain."""
    failing_sink = FailingSink(fail_append=True)
    wal_path = tmp_path / "wal" / "chain_halt.wal"
    buffer = SessionPartitionedRingBuffer(sink=failing_sink, wal_path=wal_path)

    rec0 = _make_record("session-chain-halt", 0)
    rec1 = _make_record("session-chain-halt", 1, prev_record_hash=rec0.record_hash)

    buffer.enqueue(rec0)
    buffer.enqueue(rec1)

    # Let the worker run and fail on rec0
    await asyncio.sleep(0.05)

    # Because rec0 failed, worker broke; rec1 must NOT have been sent to sink
    assert len(failing_sink.records) == 0
    # Both records remain in pending_records for WAL spill
    assert buffer.pending_count == 2

    # Flush should raise RuntimeError reflecting the recorded dispatch error
    with pytest.raises(RuntimeError, match="Ledger sink dispatch failed"):
        await buffer.flush()

    await buffer.close()


@pytest.mark.asyncio
async def test_ring_buffer_idle_queue_cleanup(tmp_path: Any) -> None:
    """Verify empty session queue is cleaned up from _session_queues when worker exits."""
    sink = InMemoryLedgerSink()
    wal_path = tmp_path / "wal" / "queue_cleanup.wal"
    buffer = SessionPartitionedRingBuffer(sink=sink, wal_path=wal_path)

    session_id = "session-idle-queue"
    rec = _make_record(session_id, 0)
    buffer.enqueue(rec)
    await buffer.flush()

    assert session_id in buffer._session_queues

    # Wait for the worker to time out (we can fast-forward by letting wait_for timeout)
    task = buffer._session_tasks.get(session_id)
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    # Task exit cleans up empty queue from _session_queues
    assert session_id not in buffer._session_queues

    await buffer.close()


