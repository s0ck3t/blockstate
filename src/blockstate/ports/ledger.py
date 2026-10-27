"""TurnLedger audit stream protocol specifications and DTOs.

Defines the append-only, tamper-evident audit record and sink SPI for regulatory
non-repudiation and causal turn tracking.
"""

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


class TurnLedgerRecord(BaseModel):
    """Immutable audit record for a single conversational turn."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    prev_record_hash: str
    session_id: str
    turn_index: int
    stage_from: str
    stage_to: str
    exposed_tools: Sequence[str]
    prompt_hash: str
    vaulted_input_hash: str
    vaulted_output_hash: str
    guard_outcome: str
    timestamp_utc: str
    record_hash: str


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
