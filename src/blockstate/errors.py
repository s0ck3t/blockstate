"""Blockstate structured error hierarchy and taxonomy.

All framework exceptions derive from BlockstateError with deterministic error
codes partitioned by domain namespace:
- BLK-CFG-*: Configuration and setup errors
- BLK-AST-*: Declarative Control Grammar (DCG) AST errors, including [Blockstate E014]
- BLK-SEC-*: Security boundaries, tool gating, and unauthorised mutation errors
- BLK-VAL-*: Slot collection and schema validation errors
- BLK-CON-*: Concurrency and distributed lease errors
- BLK-STO-*: StorageBackend SPI and persistence errors
- BLK-MOD-*: Intent classification and response renderer errors
"""

from typing import Any


class BlockstateError(Exception):
    """Base exception for all Blockstate framework errors."""

    default_code: str = "BLK-GEN-001"

    def __init__(
        self,
        message: str = "",
        code: str | None = None,
        *,
        stage: str | None = None,
        session_id: str | None = None,
        turn_index: int | None = None,
        **context: Any,
    ) -> None:
        # Support positional (code, message) invocation if first argument is a code pattern
        is_code_pattern = message.startswith(("BLK-", "[Blockstate"))
        if is_code_pattern and code is not None and not code.startswith("BLK-"):
            self.code = message
            self.message = code
        else:
            self.message = message
            self.code = code if code is not None else self.default_code

        self.stage = stage
        self.session_id = session_id
        self.turn_index = turn_index
        self.context = context
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts: list[str] = []
        if self.stage is not None:
            parts.append(f"stage={self.stage}")
        if self.session_id is not None:
            parts.append(f"session_id={self.session_id}")
        if self.turn_index is not None:
            parts.append(f"turn_index={self.turn_index}")
        for k, v in sorted(self.context.items()):
            parts.append(f"{k}={v}")

        context_str = f" ({', '.join(parts)})" if parts else ""
        if self.code in ("BLK-AST-014", "[Blockstate E014]"):
            prefix = "[Blockstate E014]"
        else:
            prefix = f"[{self.code}]"
        return f"{prefix} {self.message}{context_str}"

    def __str__(self) -> str:
        return self._format_message()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(code={self.code!r}, "
            f"message={self.message!r}, stage={self.stage!r}, "
            f"session_id={self.session_id!r}, turn_index={self.turn_index!r})"
        )


# =============================================================================
# BLK-CFG-*: Configuration & Declarative Grammar Errors
# =============================================================================


class ConfigurationError(BlockstateError):
    """Raised when declarative configuration is invalid or missing."""

    default_code = "BLK-CFG-002"


class DuplicateStageError(ConfigurationError):
    """Raised when two or more stages declare identical identifiers."""

    default_code = "BLK-CFG-001"


# =============================================================================
# BLK-AST-*: AST Analysis & Dominator Proof Errors
# =============================================================================


class ASTError(BlockstateError):
    """Base exception for Declarative Control Grammar AST compilation failures."""

    default_code = "BLK-AST-001"


class InvalidStageGraphError(ASTError):
    """Raised when stage transitions form an invalid graph or violate syntax."""

    default_code = "BLK-AST-001"


class UnreachableStageError(ASTError):
    """Raised when one or more declared stages cannot be reached from root."""

    default_code = "BLK-AST-002"


class DynamicTransitionError(ASTError):
    """Raised when dynamic transition destinations violate DCG static analysis."""

    default_code = "BLK-AST-014"


# =============================================================================
# BLK-SEC-*: Security Boundaries, Gating & Stack Protection Errors
# =============================================================================


class SecurityViolationError(BlockstateError):
    """Raised when an unwhitelisted tool invocation is attempted."""

    default_code = "BLK-SEC-001"


class UnauthorisedMutationError(SecurityViolationError):
    """Raised when a child frame attempts an unauthorised mutation of parent state."""

    default_code = "BLK-SEC-002"


class StackOverflowError(SecurityViolationError):
    """Raised when TaskStack push exceeds max_stack_depth limit."""

    default_code = "BLK-SEC-003"


# =============================================================================
# BLK-VAL-*: Slot Collection & Schema Validation Errors
# =============================================================================


class SlotValidationError(BlockstateError):
    """Base exception for slot extraction and validation failures."""

    default_code = "BLK-VAL-001"


class FieldValidationError(SlotValidationError):
    """Raised when individual slot leaf fields breach validation constraints."""

    default_code = "BLK-VAL-002"


# =============================================================================
# BLK-CON-*: Concurrency & Distributed Lease Errors
# =============================================================================


class ConcurrentSessionError(BlockstateError):
    """Raised when failing to acquire a distributed session lease within timeout."""

    default_code = "BLK-CON-409"


# =============================================================================
# BLK-STO-*: StorageBackend SPI Errors
# =============================================================================


class StorageError(BlockstateError):
    """Base exception for storage backend operations."""

    default_code = "BLK-STO-001"


class OptimisticLockError(StorageError):
    """Raised when revision_id mismatch occurs during Compare-And-Swap store."""

    default_code = "BLK-STO-002"


class LeaseTimeoutError(StorageError):
    """Raised when an active session lease expires before turn completion."""

    default_code = "BLK-STO-003"


class CheckpointNotFoundError(StorageError):
    """Raised when a requested session checkpoint does not exist."""

    default_code = "BLK-STO-004"


# =============================================================================
# BLK-MOD-*: Model & Pipeline Errors
# =============================================================================


class ModelError(BlockstateError):
    """Base exception for model extraction and rendering operations."""

    default_code = "BLK-MOD-001"


class ModelRefusalError(ModelError):
    """Raised when an upstream model issues an AI safety refusal."""

    default_code = "BLK-MOD-002"


class Pass1TimeoutError(ModelError):
    """Raised when Pass 1 intent classification exceeds latency budget."""

    default_code = "BLK-MOD-003"
