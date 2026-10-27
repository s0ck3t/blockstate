"""In-Memory StorageBackend SPI implementation for testing and ephemeral workflows.

Provides distributed lease fencing, TTL expiration, and optimistic CAS (revision_id)
concurrency control across session checkpoints in volatile worker memory.
"""

import time
import uuid

from blockstate.errors import (
    ConcurrentSessionError,
    LeaseTimeoutError,
    OptimisticLockError,
)
from blockstate.ports.storage import LeaseHandle, SessionCheckpoint


def _now_epoch_ms() -> int:
    """Return current Unix epoch timestamp in milliseconds."""
    return int(time.time() * 1000)


class InMemoryStorageBackend:
    """In-memory reference implementation of the asynchronous StorageBackend SPI."""

    def __init__(self) -> None:
        # session_id -> SessionCheckpoint
        self._checkpoints: dict[str, SessionCheckpoint] = {}
        # session_id -> LeaseHandle
        self._leases: dict[str, LeaseHandle] = {}
        # session_id -> monotonic fence counter
        self._fence_tokens: dict[str, int] = {}

    def _is_lease_active(self, lease: LeaseHandle) -> bool:
        """Check whether a lease handle is currently active and unexpired."""
        return _now_epoch_ms() < lease.expires_at_epoch_ms

    async def acquire_lease(
        self,
        session_id: str,
        ttl_ms: int = 30000,
        wait_timeout_ms: int = 2000,
    ) -> LeaseHandle:
        """Acquire an exclusive in-memory lease for a session.

        Raises ConcurrentSessionError (BLK-CON-409) if the session is currently
        leased by another active worker.
        """
        now = _now_epoch_ms()
        current_lease = self._leases.get(session_id)

        if current_lease is not None and self._is_lease_active(current_lease):
            raise ConcurrentSessionError(
                f"Session '{session_id}' is leased by active worker '{current_lease.lease_id}'",
                code="BLK-CON-409",
                session_id=session_id,
            )

        fence = self._fence_tokens.get(session_id, 0) + 1
        self._fence_tokens[session_id] = fence
        new_lease = LeaseHandle(
            session_id=session_id,
            lease_id=uuid.uuid4().hex,
            expires_at_epoch_ms=now + ttl_ms,
            fence_token=fence,
        )
        self._leases[session_id] = new_lease
        return new_lease

    async def release_lease(self, lease: LeaseHandle) -> None:
        """Release an acquired session lease if it matches the active token."""
        current_lease = self._leases.get(lease.session_id)
        if current_lease is not None and current_lease.lease_id == lease.lease_id:
            del self._leases[lease.session_id]

    async def renew_lease(
        self,
        lease: LeaseHandle,
        ttl_ms: int = 30000,
    ) -> LeaseHandle:
        """Renew an active session lease heartbeat.

        Raises LeaseTimeoutError (BLK-STO-003) if the lease expired or was stolen.
        """
        now = _now_epoch_ms()
        current_lease = self._leases.get(lease.session_id)

        if current_lease is None or current_lease.lease_id != lease.lease_id:
            raise LeaseTimeoutError(
                f"Cannot renew lease for session '{lease.session_id}': lease was stolen or lost",
                code="BLK-STO-003",
                session_id=lease.session_id,
            )

        updated_lease = LeaseHandle(
            session_id=lease.session_id,
            lease_id=lease.lease_id,
            expires_at_epoch_ms=now + ttl_ms,
            fence_token=lease.fence_token,
        )
        self._leases[lease.session_id] = updated_lease
        return updated_lease

    async def load_checkpoint(self, session_id: str) -> SessionCheckpoint | None:
        """Load the most recent session checkpoint from volatile memory, or None."""
        return self._checkpoints.get(session_id)

    async def save_checkpoint(
        self,
        checkpoint: SessionCheckpoint,
        lease: LeaseHandle,
    ) -> None:
        """Save a session checkpoint verifying lease ownership and optimistic CAS revision.

        Raises LeaseTimeoutError (BLK-STO-003) if the lease is invalid.
        Raises OptimisticLockError (BLK-STO-002) on CAS revision mismatch.
        """
        current_lease = self._leases.get(checkpoint.session_id)
        if (
            current_lease is None
            or current_lease.lease_id != lease.lease_id
            or not self._is_lease_active(current_lease)
        ):
            raise LeaseTimeoutError(
                f"Cannot save checkpoint for session '{checkpoint.session_id}': lease is invalid",
                code="BLK-STO-003",
                session_id=checkpoint.session_id,
            )

        existing = self._checkpoints.get(checkpoint.session_id)
        if existing is not None:
            expected_rev = existing.revision_id + 1
            if checkpoint.revision_id != expected_rev:
                raise OptimisticLockError(
                    f"Optimistic lock conflict on session '{checkpoint.session_id}': "
                    f"expected revision {expected_rev}, got {checkpoint.revision_id}",
                    code="BLK-STO-002",
                    session_id=checkpoint.session_id,
                )

        self._checkpoints[checkpoint.session_id] = checkpoint


# Canonical alias for StorageBackend SPI
InMemoryStateStore = InMemoryStorageBackend

__all__: list[str] = [
    "InMemoryStateStore",
    "InMemoryStorageBackend",
]
