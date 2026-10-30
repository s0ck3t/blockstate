"""StorageBackend Service Provider Interface (SPI) and persistence DTOs.

Defines the formal asynchronous storage protocol and frozen wire transfer
objects for session leasing, checkpointing, and turn dispatching.
"""

import asyncio
import contextlib
from collections.abc import Callable, Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from blockstate.errors import StorageError


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


SchemaUpcaster = Callable[[dict[str, Any]], dict[str, Any]]


def upcast_checkpoint_payload(
    payload: dict[str, Any],
    upcasters: Mapping[int, SchemaUpcaster] | None = None,
    target_version: int | None = None,
) -> dict[str, Any]:
    """Chain pure SchemaUpcaster migrations across raw checkpoint payload dicts.

    Sequentially applies registered upcasters from current schema_version v_n -> v_n+1
    before hydrating a SessionCheckpoint instance.

    Raises StorageError (BLK-STO-001) if target_version is specified but cannot be
    reached due to missing upcasters.
    """
    if not upcasters:
        current_version = int(payload.get("schema_version", 1))
        if target_version is not None and current_version < target_version:
            raise StorageError(
                f"Missing schema upcaster from version {current_version} to {target_version}",
                code="BLK-STO-001",
                session_id=str(payload.get("session_id", "")),
            )
        return dict(payload)

    migrated = dict(payload)
    current_version = int(migrated.get("schema_version", 1))

    while (
        target_version is None or current_version < target_version
    ) and current_version in upcasters:
        upcaster = upcasters[current_version]
        migrated = upcaster(dict(migrated))
        next_version = int(migrated.get("schema_version", current_version + 1))
        if next_version <= current_version:
            migrated["schema_version"] = current_version + 1
            current_version = current_version + 1
        else:
            current_version = next_version

    if target_version is not None and current_version < target_version:
        raise StorageError(
            f"Missing schema upcaster from version {current_version} to {target_version}",
            code="BLK-STO-001",
            session_id=str(migrated.get("session_id", "")),
        )

    return migrated


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

    async def close(self) -> None:
        """Release backend resources and close connections."""
        ...


class SessionLeaseHeartbeat:
    """Asynchronous context manager for automated session lease heartbeat renewal.

    Renews the lease in the background every heartbeat_interval_ms (default 10000ms),
    extending expires_at_epoch_ms by ttl_ms (default 30000ms) until context exit.
    """

    def __init__(
        self,
        backend: StorageBackend,
        lease: LeaseHandle,
        heartbeat_interval_ms: int = 10000,
        ttl_ms: int = 30000,
    ) -> None:
        if heartbeat_interval_ms <= 0 or ttl_ms <= 0:
            raise ValueError("heartbeat_interval_ms and ttl_ms must be positive integers")
        if heartbeat_interval_ms >= ttl_ms:
            raise ValueError(
                f"heartbeat_interval_ms ({heartbeat_interval_ms}) must be strictly less than "
                f"ttl_ms ({ttl_ms})"
            )
        self._backend = backend
        self._lease = lease
        self._heartbeat_interval_ms = heartbeat_interval_ms
        self._ttl_ms = ttl_ms
        self._task: asyncio.Task[None] | None = None
        self._error: Exception | None = None

    @property
    def lease(self) -> LeaseHandle:
        """Return current active LeaseHandle."""
        return self._lease

    @property
    def session_id(self) -> str:
        """Session identifier of the leased session."""
        return self._lease.session_id

    @property
    def lease_id(self) -> str:
        """Unique lease identifier token."""
        return self._lease.lease_id

    @property
    def expires_at_epoch_ms(self) -> int:
        """Unix epoch expiration in milliseconds."""
        return self._lease.expires_at_epoch_ms

    @property
    def fence_token(self) -> int:
        """Monotonic fence token counter."""
        return self._lease.fence_token

    async def _heartbeat_loop(self) -> None:
        interval_s = max(0.005, self._heartbeat_interval_ms / 1000.0)
        try:
            while True:
                await asyncio.sleep(interval_s)
                self._lease = await self._backend.renew_lease(self._lease, ttl_ms=self._ttl_ms)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._error = exc

    async def __aenter__(self) -> "SessionLeaseHeartbeat":
        self._task = asyncio.create_task(self._heartbeat_loop())
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._error is not None and exc_val is None:
            raise self._error


# Backwards compatibility alias for the StorageBackend SPI
StateStore = StorageBackend

__all__: list[str] = [
    "LeaseHandle",
    "SchemaUpcaster",
    "SessionCheckpoint",
    "SessionLeaseHeartbeat",
    "StateStore",
    "StorageBackend",
    "TurnEnvelope",
    "upcast_checkpoint_payload",
]
