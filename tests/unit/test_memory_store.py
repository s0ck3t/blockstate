"""Unit tests for InMemoryStorageBackend (InMemoryStateStore)."""

import pytest

from blockstate.adapters.storage.memory import InMemoryStateStore, InMemoryStorageBackend
from blockstate.errors import (
    ConcurrentSessionError,
    LeaseTimeoutError,
    OptimisticLockError,
)
from blockstate.ports.storage import LeaseHandle, SessionCheckpoint


@pytest.mark.asyncio
async def test_acquire_and_release_lease() -> None:
    """Verify acquiring and releasing a session lease."""
    store = InMemoryStorageBackend()
    lease = await store.acquire_lease("session_1", ttl_ms=10000)
    assert lease.session_id == "session_1"
    assert lease.lease_id != ""
    assert lease.fence_token == 1

    await store.release_lease(lease)

    # Can re-acquire immediately after release
    lease2 = await store.acquire_lease("session_1", ttl_ms=10000)
    assert lease2.fence_token == 2
    await store.release_lease(lease2)


@pytest.mark.asyncio
async def test_concurrent_lease_raises_error() -> None:
    """Verify concurrent lease acquisition raises ConcurrentSessionError (BLK-CON-409)."""
    store = InMemoryStorageBackend()
    lease1 = await store.acquire_lease("session_shared", ttl_ms=10000)
    assert lease1 is not None

    with pytest.raises(ConcurrentSessionError) as exc_info:
        await store.acquire_lease("session_shared", ttl_ms=10000)

    assert exc_info.value.code == "BLK-CON-409"
    assert exc_info.value.session_id == "session_shared"
    await store.release_lease(lease1)


@pytest.mark.asyncio
async def test_expired_lease_allows_reacquisition() -> None:
    """Verify that an expired lease can be acquired by a new worker."""
    store = InMemoryStorageBackend()
    # Expired lease with ttl_ms = -1
    await store.acquire_lease("session_expired", ttl_ms=-1)

    # Subsequent acquisition succeeds because previous lease expired
    new_lease = await store.acquire_lease("session_expired", ttl_ms=10000)
    assert new_lease is not None
    await store.release_lease(new_lease)


@pytest.mark.asyncio
async def test_renew_lease_lifecycle() -> None:
    """Verify renew_lease extends expiration or raises LeaseTimeoutError."""
    store = InMemoryStorageBackend()
    lease = await store.acquire_lease("session_renew", ttl_ms=5000)
    renewed = await store.renew_lease(lease, ttl_ms=10000)
    assert renewed.expires_at_epoch_ms > lease.expires_at_epoch_ms

    invalid_lease = LeaseHandle(
        session_id="session_renew",
        lease_id="invalid_id",
        expires_at_epoch_ms=0,
    )
    with pytest.raises(LeaseTimeoutError) as exc_info:
        await store.renew_lease(invalid_lease)

    assert exc_info.value.code == "BLK-STO-003"
    await store.release_lease(renewed)


@pytest.mark.asyncio
async def test_save_and_load_checkpoint_with_optimistic_cas() -> None:
    """Verify checkpoint persistence and optimistic CAS revision control."""
    store = InMemoryStateStore()
    lease = await store.acquire_lease("session_cas", ttl_ms=10000)

    assert await store.load_checkpoint("session_cas") is None

    cp1 = SessionCheckpoint(
        session_id="session_cas",
        schema_version=1,
        revision_id=1,
        state={"key": "val1"},
    )
    await store.save_checkpoint(cp1, lease)

    loaded = await store.load_checkpoint("session_cas")
    assert loaded is not None
    assert loaded.revision_id == 1
    assert loaded.state == {"key": "val1"}

    # Next valid save requires revision_id = 2
    cp2 = SessionCheckpoint(
        session_id="session_cas",
        schema_version=1,
        revision_id=2,
        state={"key": "val2"},
    )
    await store.save_checkpoint(cp2, lease)

    # Attempting to save with wrong revision_id raises OptimisticLockError (BLK-STO-002)
    cp_stale = SessionCheckpoint(
        session_id="session_cas",
        schema_version=1,
        revision_id=2,  # Should be 3
        state={"key": "val_stale"},
    )
    with pytest.raises(OptimisticLockError) as exc_info:
        await store.save_checkpoint(cp_stale, lease)

    assert exc_info.value.code == "BLK-STO-002"
    await store.release_lease(lease)


@pytest.mark.asyncio
async def test_save_checkpoint_with_invalid_lease_fails() -> None:
    """Verify saving checkpoint with invalid lease raises LeaseTimeoutError."""
    store = InMemoryStateStore()
    fake_lease = LeaseHandle(
        session_id="session_unleased",
        lease_id="fake_lease",
        expires_at_epoch_ms=100000,
    )
    cp = SessionCheckpoint(session_id="session_unleased", revision_id=1)

    with pytest.raises(LeaseTimeoutError) as exc_info:
        await store.save_checkpoint(cp, fake_lease)

    assert exc_info.value.code == "BLK-STO-003"
