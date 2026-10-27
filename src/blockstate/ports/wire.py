"""Outer orchestrator enclave wire data transfer objects (DTOs).

Defines the discriminated union DTOs yielded or returned across the transactional
compliance execution enclave boundary:
- BlockstateTurnYield: Intermediate multi-turn response requiring user input
- BlockstateTurnAborted: Execution halted due to security violation or error
- BlockstateTurnComplete[T]: Successful workflow completion with typed result
"""

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class BlockstateTurnYield(BaseModel):
    """Enclave yield DTO representing an in-progress conversational turn."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    state: Literal["in_progress"] = "in_progress"
    message: str = ""
    choices: Sequence[str] | Sequence[Mapping[str, Any]] | None = None
    missing_slots: Sequence[str] = Field(default_factory=tuple)


class BlockstateTurnAborted(BaseModel):
    """Enclave terminal DTO representing an aborted execution flow."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    state: Literal["aborted"] = "aborted"
    error_code: str
    reason: str


class BlockstateTurnComplete[T](BaseModel):
    """Enclave terminal DTO representing successful completion with typed result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    state: Literal["completed"] = "completed"
    result: T
    ledger_head_hash: str
