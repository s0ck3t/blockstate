"""TurnLedger audit stream protocol specifications and DTOs.

Defines the append-only, tamper-evident audit record and sink SPI for regulatory
non-repudiation and causal turn tracking.
"""

import hashlib
import json
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TurnLedgerRecord(BaseModel):
    """Immutable audit record for a single conversational turn."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    prev_record_hash: str
    session_id: str
    turn_index: int
    stage_from: str
    stage_to: str
    exposed_tools: tuple[str, ...] = Field(default_factory=tuple)
    prompt_hash: str
    vaulted_input_hash: str
    vaulted_output_hash: str
    guard_outcome: str
    timestamp_utc: str
    record_hash: str

    @field_validator("exposed_tools", mode="before")
    @classmethod
    def _validate_exposed_tools_tuple(cls, v: Any) -> tuple[str, ...]:
        """Convert input sequence into an immutable tuple to guarantee hashability."""
        if isinstance(v, tuple):
            return tuple(str(x) for x in v)
        if isinstance(v, (list, Sequence)) and not isinstance(v, (str, bytes)):
            return tuple(str(x) for x in v)
        if v is None:
            return ()
        return (str(v),)


def compute_record_hash(
    *,
    prev_record_hash: str,
    session_id: str,
    turn_index: int,
    stage_from: str,
    stage_to: str,
    exposed_tools: Sequence[str],
    prompt_hash: str,
    vaulted_input_hash: str,
    vaulted_output_hash: str,
    guard_outcome: str,
    timestamp_utc: str,
) -> str:
    """Compute SHA-256 digest over the RFC 8785 JCS canonicalisation of a turn record.

    Serialises the dictionary into deterministic JSON Canonicalisation Scheme bytes
    and produces the 64-character hexadecimal digest.
    """
    payload = {
        "exposed_tools": list(exposed_tools),
        "guard_outcome": guard_outcome,
        "prev_record_hash": prev_record_hash,
        "prompt_hash": prompt_hash,
        "session_id": session_id,
        "stage_from": stage_from,
        "stage_to": stage_to,
        "timestamp_utc": timestamp_utc,
        "turn_index": turn_index,
        "vaulted_input_hash": vaulted_input_hash,
        "vaulted_output_hash": vaulted_output_hash,
    }
    canonical_jcs = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_jcs).hexdigest()


def verify_record_hash(record: TurnLedgerRecord) -> bool:
    """Verify that a TurnLedgerRecord matches its internal SHA-256 digest."""
    expected = compute_record_hash(
        prev_record_hash=record.prev_record_hash,
        session_id=record.session_id,
        turn_index=record.turn_index,
        stage_from=record.stage_from,
        stage_to=record.stage_to,
        exposed_tools=record.exposed_tools,
        prompt_hash=record.prompt_hash,
        vaulted_input_hash=record.vaulted_input_hash,
        vaulted_output_hash=record.vaulted_output_hash,
        guard_outcome=record.guard_outcome,
        timestamp_utc=record.timestamp_utc,
    )
    return record.record_hash == expected


@runtime_checkable
class LedgerSink(Protocol):
    """Audit sink SPI for persisting TurnLedger records."""

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a validated turn record to the audit ledger sink."""
        ...

    async def flush(self) -> None:
        """Flush buffered turn records to durable storage."""
        ...

    async def close(self) -> None:
        """Close the sink and release underlying resources."""
        ...


__all__: list[str] = [
    "LedgerSink",
    "TurnLedgerRecord",
    "compute_record_hash",
    "verify_record_hash",
]
