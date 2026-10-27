"""Unit and contract tests for InMemoryStorageBackend (InMemoryStateStore)."""

from collections.abc import Mapping

import pytest

from blockstate.adapters.storage.memory import (
    InMemoryStateStore,
    InMemoryStorageBackend,
)
from blockstate.ports.storage import SchemaUpcaster, SessionCheckpoint
from blockstate.testing.contracts import StateStoreContractSuite


class TestInMemoryStorageBackendContract(StateStoreContractSuite):
    """Execute complete StateStoreContractSuite against InMemoryStorageBackend."""

    __test__ = True

    def create_backend(
        self,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> InMemoryStorageBackend:
        return InMemoryStorageBackend(
            upcasters=upcasters,
            target_schema_version=target_schema_version,
        )


@pytest.mark.asyncio
async def test_memory_store_alias_equality() -> None:
    """Verify InMemoryStateStore is a direct alias for InMemoryStorageBackend."""
    assert InMemoryStateStore is InMemoryStorageBackend


@pytest.mark.asyncio
async def test_memory_store_register_upcaster_method() -> None:
    """Verify registering an upcaster dynamically via register_upcaster()."""
    store = InMemoryStorageBackend()
    store.register_upcaster(1, lambda d: {**d, "schema_version": 2, "state": {"upgraded": True}})

    lease = await store.acquire_lease("dyn-upcast", ttl_ms=10000)
    cp = SessionCheckpoint(session_id="dyn-upcast", schema_version=1, revision_id=0)
    await store.save_checkpoint(cp, lease)

    loaded = await store.load_checkpoint("dyn-upcast")
    assert loaded is not None
    assert loaded.schema_version == 2
    assert loaded.state.get("upgraded") is True
    await store.release_lease(lease)


@pytest.mark.asyncio
async def test_memory_store_close_clears_resources() -> None:
    """Verify close() cleans up all in-memory collections."""
    store = InMemoryStorageBackend()
    lease = await store.acquire_lease("session_close", ttl_ms=10000)
    cp = SessionCheckpoint(session_id="session_close", schema_version=1, revision_id=0)
    await store.save_checkpoint(cp, lease)

    await store.close()
    assert await store.load_checkpoint("session_close") is None
