"""StorageBackend Service Provider Interface (SPI) and persistence DTOs.

Defines the formal asynchronous storage protocol and frozen wire transfer
objects for session leasing, checkpointing, and turn dispatching.
"""

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class LeaseHandle(BaseModel):
    """Fenced distributed lease token for session concurrency control."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    lease_id: str
    expires_at_epoch_ms: int
    fence_token: int = 0


class SessionCheckpoint(BaseModel):
    """Atomic persistence unit for session state and execution stack."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    schema_version: int = 1
    revision_id: int = 0
    state: Mapping[str, Any] = Field(default_factory=dict)
    task_stack: tuple[Mapping[str, Any], ...] = Field(default_factory=tuple)
    last_ledger_hash: str = ""
    pending_ledger_outbox: tuple[Mapping[str, Any], ...] = Field(default_factory=tuple)
    vault_map: bytes = b""
    created_at: str = ""
    updated_at: str = ""


class TurnEnvelope(BaseModel):
    """Canonical envelope carrying turn input data across the pipeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    turn_index: int = 0
    user_message: str
    initial_context: Mapping[str, Any] = Field(default_factory=dict)
    timestamp_utc: str = ""


@runtime_checkable
class StorageBackend(Protocol):
    """Asynchronous StorageBackend Service Provider Interface (SPI)."""

    async def acquire_lease(
        self,
        session_id: str,
        ttl_ms: int = 30000,
        wait_timeout_ms: int = 2000,
    ) -> LeaseHandle:
        """Acquire an exclusive distributed lease for a session."""
        ...

    async def release_lease(self, lease: LeaseHandle) -> None:
        """Release an acquired session lease."""
        ...

    async def renew_lease(
        self,
        lease: LeaseHandle,
        ttl_ms: int = 30000,
    ) -> LeaseHandle:
        """Renew an active session lease heartbeat."""
        ...

    async def load_checkpoint(self, session_id: str) -> SessionCheckpoint | None:
        """Load the most recent session checkpoint, or None if not found."""
        ...

    async def save_checkpoint(
        self,
        checkpoint: SessionCheckpoint,
        lease: LeaseHandle,
    ) -> None:
        """Atomically save a session checkpoint verified by lease ownership."""
        ...


# Backwards compatibility alias for the StorageBackend SPI
StateStore = StorageBackend
