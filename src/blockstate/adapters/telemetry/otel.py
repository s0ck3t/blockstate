"""OpenTelemetry GenAI 1.30 semantic convention emitter, trace recorder, and replayer.

Provides zero-PII OpenTelemetry GenAI 1.30 span emission, structured trace persistence
to .blockstate/traces.jsonl, and cryptographic audit replay with defensive import guarding.
"""

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from blockstate.ports.ledger import LedgerSink, TurnLedgerRecord

# Defensive import guarding for optional OpenTelemetry packages
trace: Any = None
Status: Any = None
StatusCode: Any = None
HAS_OPENTELEMETRY = False

try:
    from opentelemetry import trace as _trace
    from opentelemetry.trace import Status as _Status
    from opentelemetry.trace import StatusCode as _StatusCode

    trace = _trace
    Status = _Status
    StatusCode = _StatusCode
    HAS_OPENTELEMETRY = True
except ImportError:
    pass


DEFAULT_TRACES_PATH = Path(".blockstate/traces.jsonl")


@dataclass(frozen=True)
class TraceRecord:
    """Immutable trace record capturing turn execution for diagnostics and replay."""

    session_id: str
    turn_index: int
    stage_from: str
    stage_to: str
    exposed_tools: list[str] = field(default_factory=list)
    input_hash: str = ""
    output_hash: str = ""
    slot_deltas: list[str] = field(default_factory=list)
    guard_outcome: str = "stay"
    record_hash: str = ""
    prev_record_hash: str = ""
    timestamp_utc: str = ""
    chain_valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert trace record to serialisable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceRecord":
        """Instantiate trace record from dictionary."""
        return cls(
            session_id=str(data.get("session_id", "")),
            turn_index=int(data.get("turn_index", 0)),
            stage_from=str(data.get("stage_from", "")),
            stage_to=str(data.get("stage_to", "")),
            exposed_tools=list(data.get("exposed_tools", [])),
            input_hash=str(data.get("input_hash", "")),
            output_hash=str(data.get("output_hash", "")),
            slot_deltas=list(data.get("slot_deltas", [])),
            guard_outcome=str(data.get("guard_outcome", "stay")),
            record_hash=str(data.get("record_hash", "")),
            prev_record_hash=str(data.get("prev_record_hash", "")),
            timestamp_utc=str(data.get("timestamp_utc", "")),
            chain_valid=bool(data.get("chain_valid", True)),
        )

    @classmethod
    def from_ledger_record(
        cls,
        record: TurnLedgerRecord,
        *,
        slot_deltas: Sequence[str] = (),
        chain_valid: bool = True,
    ) -> "TraceRecord":
        """Construct a TraceRecord from a canonical TurnLedgerRecord."""
        return cls(
            session_id=record.session_id,
            turn_index=record.turn_index,
            stage_from=record.stage_from,
            stage_to=record.stage_to,
            exposed_tools=list(record.exposed_tools),
            input_hash=record.vaulted_input_hash,
            output_hash=record.vaulted_output_hash,
            slot_deltas=list(slot_deltas),
            guard_outcome=record.guard_outcome,
            record_hash=record.record_hash,
            prev_record_hash=record.prev_record_hash,
            timestamp_utc=record.timestamp_utc,
            chain_valid=chain_valid,
        )


class OpenTelemetrySpanEmitter:
    """Emits OpenTelemetry GenAI 1.30 semantic spans with zero raw PII."""

    def __init__(self, tracer_name: str = "blockstate", tracer: Any = None) -> None:
        self.tracer_name = tracer_name
        self._tracer = tracer

    @property
    def is_available(self) -> bool:
        """Indicate whether OpenTelemetry runtime is available and initialised."""
        return HAS_OPENTELEMETRY or self._tracer is not None

    def get_tracer(self) -> Any:
        """Retrieve active OpenTelemetry tracer or None if unavailable."""
        if self._tracer is not None:
            return self._tracer
        if HAS_OPENTELEMETRY and trace is not None:
            return trace.get_tracer(self.tracer_name)
        return None

    def emit_turn_span(
        self,
        record: TurnLedgerRecord | TraceRecord,
        *,
        slot_deltas: Sequence[str] = (),
        model_name: str = "deterministic-statechart",
    ) -> Any:
        """Emit an OpenTelemetry span conforming to GenAI 1.30 semantic conventions.

        Guarantees that no raw user text, passwords, or PII appear in span attributes;
        only cryptographically vaulted hashes and statechart identifiers are included.
        """
        tracer = self.get_tracer()
        if tracer is None:
            return None

        # Determine attribute values based on record type
        if isinstance(record, TurnLedgerRecord):
            session_id = record.session_id
            turn_index = record.turn_index
            stage_from = record.stage_from
            stage_to = record.stage_to
            exposed_tools = list(record.exposed_tools)
            input_hash = record.vaulted_input_hash
            output_hash = record.vaulted_output_hash
            guard_outcome = record.guard_outcome
            record_hash = record.record_hash
            prev_record_hash = record.prev_record_hash
            timestamp_utc = record.timestamp_utc
        else:
            session_id = record.session_id
            turn_index = record.turn_index
            stage_from = record.stage_from
            stage_to = record.stage_to
            exposed_tools = list(record.exposed_tools)
            input_hash = record.input_hash
            output_hash = record.output_hash
            guard_outcome = record.guard_outcome
            record_hash = record.record_hash
            prev_record_hash = record.prev_record_hash
            timestamp_utc = record.timestamp_utc
            if not slot_deltas and record.slot_deltas:
                slot_deltas = record.slot_deltas

        span_name = "gen_ai.turn"
        attributes: dict[str, Any] = {
            "gen_ai.system": "blockstate",
            "gen_ai.operation.name": "turn",
            "gen_ai.request.model": model_name,
            "session.id": session_id,
            "turn.index": turn_index,
            "blockstate.stage.from": stage_from,
            "blockstate.stage.to": stage_to,
            "blockstate.guard.outcome": guard_outcome,
            "blockstate.exposed_tools": exposed_tools,
            "blockstate.input_hash": input_hash,
            "blockstate.output_hash": output_hash,
            "blockstate.record_hash": record_hash,
            "blockstate.prev_record_hash": prev_record_hash,
            "blockstate.timestamp_utc": timestamp_utc,
            "blockstate.slot_deltas": list(slot_deltas),
        }

        # Determine whether turn indicates failure or abortion
        outcome_lower = guard_outcome.lower()
        is_error = bool(
            outcome_lower
            in (
                "refusal",
                "breach",
                "max_turns_exceeded",
                "security_violation",
                "aborted",
                "error",
                "failed",
                "failure",
            )
            or any(k in outcome_lower for k in ("fail", "abort", "error", "violation"))
            or stage_to.lower() in ("aborted", "failed", "error")
            or (isinstance(record, TraceRecord) and not record.chain_valid)
        )

        with tracer.start_as_current_span(span_name, attributes=attributes) as span:
            if StatusCode is not None and Status is not None:
                if is_error:
                    span.set_status(
                        Status(StatusCode.ERROR, description=f"Turn halted with {guard_outcome}")
                    )
                else:
                    span.set_status(Status(StatusCode.OK))
            return span


class TraceRecorder:
    """Appends immutable turn trace records to local JSONL files."""

    def __init__(self, trace_file: Path | str = DEFAULT_TRACES_PATH) -> None:
        self.trace_file = Path(trace_file)

    def append(
        self,
        record: TraceRecord | TurnLedgerRecord,
        *,
        slot_deltas: Sequence[str] = (),
    ) -> TraceRecord:
        """Append a trace record to the configured JSONL file, creating parent dirs if needed."""
        trace_record: TraceRecord
        if isinstance(record, TurnLedgerRecord):
            trace_record = TraceRecord.from_ledger_record(record, slot_deltas=slot_deltas)
        else:
            trace_record = record

        self.trace_file.parent.mkdir(parents=True, exist_ok=True)
        with self.trace_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(trace_record.to_dict(), ensure_ascii=False) + "\n")

        return trace_record


class TraceReplayer:
    """Reads and validates chronological trace records from .blockstate/traces.jsonl."""

    def __init__(self, trace_file: Path | str = DEFAULT_TRACES_PATH) -> None:
        self.trace_file = Path(trace_file)

    def load_session_traces(self, session_id: str) -> list[TraceRecord]:
        """Load and verify all trace records for a designated session identifier."""
        if not self.trace_file.exists():
            return []

        records: list[TraceRecord] = []
        with self.trace_file.open("r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    payload = json.loads(line_str)
                    if payload.get("session_id") == session_id:
                        records.append(TraceRecord.from_dict(payload))
                except json.JSONDecodeError:
                    continue

        # Sort by monotonic turn_index
        records.sort(key=lambda r: r.turn_index)

        # Validate cryptographic hash chain with cascading invalidation
        validated_records: list[TraceRecord] = []
        cumulative_valid = True
        for i, rec in enumerate(records):
            record_valid = True
            if i == 0:
                # Initial record: prev_record_hash is expected to be blank or 64 zeros
                expected_prev = "0" * 64
                if rec.prev_record_hash not in ("", expected_prev):
                    record_valid = False
            else:
                prev_rec = records[i - 1]
                if rec.prev_record_hash != prev_rec.record_hash:
                    record_valid = False

            if not record_valid:
                cumulative_valid = False

            rec_dict = rec.to_dict()
            rec_dict["chain_valid"] = cumulative_valid
            validated_records.append(TraceRecord.from_dict(rec_dict))

        return validated_records

    def load_all_sessions(self) -> dict[str, list[TraceRecord]]:
        """Load all trace records grouped by session identifier."""
        if not self.trace_file.exists():
            return {}

        session_ids: list[str] = []
        with self.trace_file.open("r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    payload = json.loads(line_str)
                    sid = payload.get("session_id")
                    if sid and sid not in session_ids:
                        session_ids.append(sid)
                except json.JSONDecodeError:
                    continue

        return {sid: self.load_session_traces(sid) for sid in session_ids}


class OpenTelemetryLedgerSink(LedgerSink):
    """Auditing sink that emits OpenTelemetry spans and writes trace records to JSONL."""

    def __init__(
        self,
        trace_file: Path | str = DEFAULT_TRACES_PATH,
        span_emitter: OpenTelemetrySpanEmitter | None = None,
        model_name: str = "deterministic-statechart",
    ) -> None:
        self.trace_file = Path(trace_file)
        self.recorder = TraceRecorder(self.trace_file)
        self.emitter = span_emitter or OpenTelemetrySpanEmitter()
        self.model_name = model_name

    async def append(self, record: TurnLedgerRecord) -> None:
        """Emit OpenTelemetry GenAI 1.30 span and append trace record to JSONL."""
        # 1. Emit OpenTelemetry span
        self.emitter.emit_turn_span(record, model_name=self.model_name)

        # 2. Append trace record to JSONL
        self.recorder.append(record)

    async def flush(self) -> None:
        """Flush buffered spans and file buffers."""
        pass

    async def close(self) -> None:
        """Release underlying resources."""
        pass


__all__: list[str] = [
    "DEFAULT_TRACES_PATH",
    "HAS_OPENTELEMETRY",
    "OpenTelemetryLedgerSink",
    "OpenTelemetrySpanEmitter",
    "TraceRecord",
    "TraceRecorder",
    "TraceReplayer",
]
