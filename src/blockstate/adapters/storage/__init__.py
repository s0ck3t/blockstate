"""StorageBackend adapter implementations."""

from blockstate.adapters.storage.memory import (
    InMemoryStateStore,
    InMemoryStorageBackend,
)

try:
    from blockstate.adapters.storage.sqlite import (
        SQLiteStateStore,
        SQLiteStorageBackend,
    )
except ImportError:  # pragma: no cover
    SQLiteStateStore = None  # type: ignore[assignment, misc]
    SQLiteStorageBackend = None  # type: ignore[assignment, misc]

try:
    from blockstate.adapters.storage.postgres import (
        PostgresStateStore,
        PostgresStorageBackend,
    )
except ImportError:  # pragma: no cover
    PostgresStateStore = None  # type: ignore[assignment, misc]
    PostgresStorageBackend = None  # type: ignore[assignment, misc]

__all__: list[str] = [
    "InMemoryStateStore",
    "InMemoryStorageBackend",
    "PostgresStateStore",
    "PostgresStorageBackend",
    "SQLiteStateStore",
    "SQLiteStorageBackend",
]
