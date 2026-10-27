"""TurnLedger audit stream sink and ring buffer adapters.

Provides FileLedgerSink, PostgresLedgerSink, S3LedgerSink, and
SessionPartitionedRingBuffer with WAL drain and recovery capabilities.
"""

from blockstate.adapters.ledger.file import FileLedgerSink
from blockstate.adapters.ledger.ring_buffer import (
    SessionPartitionedRingBuffer,
    recover_wal,
)

try:
    from blockstate.adapters.ledger.postgres import PostgresLedgerSink
except ImportError:  # pragma: no cover
    PostgresLedgerSink = None  # type: ignore[assignment, misc]

try:
    from blockstate.adapters.ledger.s3 import S3LedgerSink
except ImportError:  # pragma: no cover
    S3LedgerSink = None  # type: ignore[assignment, misc]

__all__: list[str] = [
    "FileLedgerSink",
    "PostgresLedgerSink",
    "S3LedgerSink",
    "SessionPartitionedRingBuffer",
    "recover_wal",
]
