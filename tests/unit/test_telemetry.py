"""Unit tests for OpenTelemetry GenAI 1.30 span emission and JSONL trace recorder/replayer."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from blockstate.adapters.telemetry.otel import (
    OpenTelemetryLedgerSink,
    OpenTelemetrySpanEmitter,
    TraceRecord,
    TraceRecorder,
    TraceReplayer,
)
from blockstate.ports.ledger import TurnLedgerRecord, compute_record_hash


@pytest.fixture
def sample_ledger_record() -> TurnLedgerRecord:
    """Construct a canonical TurnLedgerRecord for unit testing."""
    prev_hash = "0" * 64
    session_id = "sess_telemetry_test_1"
    turn_index = 1
    stage_from = "intake"
    stage_to = "verify_kyc"
    exposed_tools = ("tool_verify", "tool_lookup")
    prompt_hash = "p" * 64
    input_hash = "i" * 64
    output_hash = "o" * 64
    guard_outcome = "transition"
    timestamp = "2026-10-27T14:30:00Z"

    rec_hash = compute_record_hash(
        prev_record_hash=prev_hash,
        session_id=session_id,
        turn_index=turn_index,
        stage_from=stage_from,
        stage_to=stage_to,
        exposed_tools=exposed_tools,
        prompt_hash=prompt_hash,
        vaulted_input_hash=input_hash,
        vaulted_output_hash=output_hash,
        guard_outcome=guard_outcome,
        timestamp_utc=timestamp,
    )

    return TurnLedgerRecord(
        prev_record_hash=prev_hash,
        session_id=session_id,
        turn_index=turn_index,
        stage_from=stage_from,
        stage_to=stage_to,
        exposed_tools=exposed_tools,
        prompt_hash=prompt_hash,
        vaulted_input_hash=input_hash,
        vaulted_output_hash=output_hash,
        guard_outcome=guard_outcome,
        timestamp_utc=timestamp,
        record_hash=rec_hash,
    )


def test_trace_record_conversions(sample_ledger_record: TurnLedgerRecord) -> None:
    """Verify TraceRecord serialisation, deserialisation, and ledger conversion."""
    trace_rec = TraceRecord.from_ledger_record(
        sample_ledger_record,
        slot_deltas=["slot_a", "slot_b"],
        chain_valid=True,
    )

    assert trace_rec.session_id == sample_ledger_record.session_id
    assert trace_rec.turn_index == sample_ledger_record.turn_index
    assert trace_rec.stage_from == sample_ledger_record.stage_from
    assert trace_rec.stage_to == sample_ledger_record.stage_to
    assert trace_rec.exposed_tools == list(sample_ledger_record.exposed_tools)
    assert trace_rec.slot_deltas == ["slot_a", "slot_b"]
    assert trace_rec.chain_valid is True

    payload = trace_rec.to_dict()
    assert isinstance(payload, dict)

    reconstructed = TraceRecord.from_dict(payload)
    assert reconstructed == trace_rec


def test_trace_recorder_and_replayer_valid_chain(
    tmp_path: Path,
    sample_ledger_record: TurnLedgerRecord,
) -> None:
    """Verify recording turns to JSONL and verifying valid cryptographic hash chain."""
    trace_file = tmp_path / ".blockstate" / "traces.jsonl"
    recorder = TraceRecorder(trace_file=trace_file)

    # Append turn 1
    recorder.append(sample_ledger_record, slot_deltas=["slot_a"])

    # Construct and append turn 2
    t2_hash = compute_record_hash(
        prev_record_hash=sample_ledger_record.record_hash,
        session_id=sample_ledger_record.session_id,
        turn_index=2,
        stage_from="verify_kyc",
        stage_to="settle",
        exposed_tools=(),
        prompt_hash="p2" * 32,
        vaulted_input_hash="i2" * 32,
        vaulted_output_hash="o2" * 32,
        guard_outcome="end",
        timestamp_utc="2026-10-27T14:31:00Z",
    )
    rec2 = TurnLedgerRecord(
        prev_record_hash=sample_ledger_record.record_hash,
        session_id=sample_ledger_record.session_id,
        turn_index=2,
        stage_from="verify_kyc",
        stage_to="settle",
        exposed_tools=(),
        prompt_hash="p2" * 32,
        vaulted_input_hash="i2" * 32,
        vaulted_output_hash="o2" * 32,
        guard_outcome="end",
        timestamp_utc="2026-10-27T14:31:00Z",
        record_hash=t2_hash,
    )
    recorder.append(rec2)

    # Replay session
    replayer = TraceReplayer(trace_file=trace_file)
    traces = replayer.load_session_traces(sample_ledger_record.session_id)
    assert len(traces) == 2
    assert traces[0].chain_valid is True
    assert traces[1].chain_valid is True
    assert traces[0].turn_index == 1
    assert traces[1].turn_index == 2

    # Verify load_all_sessions
    all_sessions = replayer.load_all_sessions()
    assert sample_ledger_record.session_id in all_sessions
    assert len(all_sessions[sample_ledger_record.session_id]) == 2


def test_trace_replayer_broken_chain(
    tmp_path: Path,
    sample_ledger_record: TurnLedgerRecord,
) -> None:
    """Verify trace replayer flags tampered or broken prev_record_hash chains."""
    trace_file = tmp_path / "broken_traces.jsonl"
    recorder = TraceRecorder(trace_file=trace_file)

    recorder.append(sample_ledger_record)

    # Tampered turn 2 where prev_record_hash does not match turn 1 record_hash
    tampered_rec = TraceRecord(
        session_id=sample_ledger_record.session_id,
        turn_index=2,
        stage_from="stage_x",
        stage_to="stage_y",
        exposed_tools=[],
        input_hash="hash_in",
        output_hash="hash_out",
        slot_deltas=[],
        guard_outcome="stay",
        record_hash="forged_hash_2",
        prev_record_hash="corrupted_prev_hash",
        timestamp_utc="2026-10-27T14:35:00Z",
        chain_valid=True,
    )
    recorder.append(tampered_rec)

    # Turn 3 which correctly links to forged_hash_2, but must be invalidated due to cascade
    turn3_rec = TraceRecord(
        session_id=sample_ledger_record.session_id,
        turn_index=3,
        stage_from="stage_y",
        stage_to="stage_z",
        exposed_tools=[],
        input_hash="hash_in_3",
        output_hash="hash_out_3",
        slot_deltas=[],
        guard_outcome="stay",
        record_hash="hash_3",
        prev_record_hash="forged_hash_2",
        timestamp_utc="2026-10-27T14:36:00Z",
        chain_valid=True,
    )
    recorder.append(turn3_rec)

    replayer = TraceReplayer(trace_file=trace_file)
    traces = replayer.load_session_traces(sample_ledger_record.session_id)
    assert len(traces) == 3
    assert traces[0].chain_valid is True
    assert traces[1].chain_valid is False  # Forged predecessor caught
    assert traces[2].chain_valid is False  # Cascading invalidation across subsequent turns


def test_trace_replayer_missing_or_empty_file(tmp_path: Path) -> None:
    """Verify replayer handles missing or empty trace files cleanly."""
    missing_file = tmp_path / "does_not_exist.jsonl"
    replayer = TraceReplayer(trace_file=missing_file)
    assert replayer.load_session_traces("any_sess") == []
    assert replayer.load_all_sessions() == {}


def test_opentelemetry_span_emitter_genai_1_30_attributes(
    sample_ledger_record: TurnLedgerRecord,
) -> None:
    """Verify OpenTelemetry GenAI 1.30 semantic span attributes and zero PII."""
    mock_span = MagicMock()
    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    emitter = OpenTelemetrySpanEmitter(tracer=mock_tracer)
    assert emitter.is_available is True

    emitter.emit_turn_span(
        sample_ledger_record,
        slot_deltas=["slot_missing_1"],
        model_name="deterministic-statechart",
    )

    mock_tracer.start_as_current_span.assert_called_once()
    call_args, call_kwargs = mock_tracer.start_as_current_span.call_args
    span_name = call_args[0]
    attributes = call_kwargs["attributes"]

    assert span_name == "gen_ai.turn"
    assert attributes["gen_ai.system"] == "blockstate"
    assert attributes["gen_ai.operation.name"] == "turn"
    assert attributes["gen_ai.request.model"] == "deterministic-statechart"
    assert attributes["session.id"] == sample_ledger_record.session_id
    assert attributes["turn.index"] == sample_ledger_record.turn_index
    assert attributes["blockstate.stage.from"] == sample_ledger_record.stage_from
    assert attributes["blockstate.stage.to"] == sample_ledger_record.stage_to
    assert attributes["blockstate.guard.outcome"] == sample_ledger_record.guard_outcome
    assert attributes["blockstate.exposed_tools"] == list(sample_ledger_record.exposed_tools)
    assert attributes["blockstate.input_hash"] == sample_ledger_record.vaulted_input_hash
    assert attributes["blockstate.output_hash"] == sample_ledger_record.vaulted_output_hash
    assert attributes["blockstate.record_hash"] == sample_ledger_record.record_hash
    assert attributes["blockstate.prev_record_hash"] == sample_ledger_record.prev_record_hash
    assert attributes["blockstate.slot_deltas"] == ["slot_missing_1"]

    # Also test with TraceRecord
    trace_rec = TraceRecord(
        session_id="sess_trace_rec",
        turn_index=2,
        stage_from="s1",
        stage_to="s2",
        exposed_tools=["t1"],
        input_hash="ihash",
        output_hash="ohash",
        slot_deltas=["delta1"],
        guard_outcome="stay",
        record_hash="rhash",
        prev_record_hash="phash",
        timestamp_utc="now",
    )
    mock_tracer.reset_mock()
    emitter.emit_turn_span(trace_rec)
    mock_tracer.start_as_current_span.assert_called_once()


def test_opentelemetry_span_emitter_error_status() -> None:
    """Verify OpenTelemetry span status is set to ERROR when record indicates failure/aborted."""
    from opentelemetry.trace import StatusCode

    mock_span = MagicMock()
    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    emitter = OpenTelemetrySpanEmitter(tracer=mock_tracer)

    aborted_rec = TraceRecord(
        session_id="sess_abort",
        turn_index=1,
        stage_from="intake",
        stage_to="aborted",
        guard_outcome="security_violation",
    )
    emitter.emit_turn_span(aborted_rec)
    mock_span.set_status.assert_called_once()
    status_obj = mock_span.set_status.call_args[0][0]
    assert status_obj.status_code == StatusCode.ERROR


def test_opentelemetry_span_emitter_unavailable() -> None:
    """Verify emitter returns None safely when OpenTelemetry is unavailable."""
    emitter = OpenTelemetrySpanEmitter(tracer=None)
    # Monkey-patch tracer retrieval to return None
    emitter.get_tracer = lambda: None  # type: ignore[method-assign]

    trace_rec = TraceRecord(
        session_id="sess_no_otel",
        turn_index=1,
        stage_from="a",
        stage_to="b",
    )
    result = emitter.emit_turn_span(trace_rec)
    assert result is None


@pytest.mark.asyncio
async def test_opentelemetry_ledger_sink_append(
    tmp_path: Path,
    sample_ledger_record: TurnLedgerRecord,
) -> None:
    """Verify OpenTelemetryLedgerSink writes to trace file and emits span."""
    trace_file = tmp_path / "sink_traces.jsonl"
    mock_emitter = MagicMock(spec=OpenTelemetrySpanEmitter)
    sink = OpenTelemetryLedgerSink(trace_file=trace_file, span_emitter=mock_emitter)

    await sink.append(sample_ledger_record)
    await sink.flush()
    await sink.close()

    mock_emitter.emit_turn_span.assert_called_once_with(
        sample_ledger_record,
        model_name="deterministic-statechart",
    )
    assert trace_file.exists()
    lines = trace_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["session_id"] == sample_ledger_record.session_id
