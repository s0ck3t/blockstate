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

    @property
    def stage_id(self) -> str | None:
        """Alias for stage identifier."""
        return self.stage

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

    def __init__(
        self,
        message: str = "Field validation failed",
        code: str | None = None,
        *,
        errors: list[dict[str, Any]] | None = None,
        field_path: str | None = None,
        **context: Any,
    ) -> None:
        self.errors: list[dict[str, Any]] = list(errors) if errors is not None else []
        self.field_path = field_path
        if field_path is not None and "field_path" not in context:
            context["field_path"] = field_path
        super().__init__(message=message, code=code, **context)

    @classmethod
    def from_pydantic_error(
        cls,
        exc: Any,
        *,
        field_path: str | None = None,
        stage: str | None = None,
        stage_id: str | None = None,
        frame: Any = None,
        session_id: str | None = None,
        turn_index: int | None = None,
        **context: Any,
    ) -> "FieldValidationError":
        """Construct a sanitised FieldValidationError from a Pydantic ValidationError.

        Guarantees that raw rejected inputs and context are omitted (include_input=False,
        include_context=False) to prevent data leakage.
        """
        if frame is not None and stage is None and stage_id is None:
            stage = getattr(frame, "stage_id", None)
        effective_stage = stage if stage is not None else stage_id
        sanitised = sanitise_validation_errors(exc)
        first_msg = sanitised[0]["msg"] if sanitised else (str(exc) or "Field validation failed")
        first_loc = (
            ".".join(str(p) for p in sanitised[0]["loc"])
            if sanitised and "loc" in sanitised[0] and sanitised[0]["loc"]
            else field_path
        )
        return cls(
            message=first_msg,
            errors=sanitised,
            field_path=field_path or first_loc,
            stage=effective_stage,
            session_id=session_id,
            turn_index=turn_index,
            **context,
        )


class DisqualifyingBreachError(SlotValidationError):
    """Raised when candidate input violates an explicit stage qualification constraint."""

    default_code = "BLK-VAL-003"

    def __init__(
        self,
        message: str = "Disqualifying validation breach detected",
        code: str | None = None,
        *,
        field_name: str | None = None,
        target_stage: str | None = None,
        **context: Any,
    ) -> None:
        self.field_name = field_name
        self.target_stage = target_stage
        if field_name is not None and "field_name" not in context:
            context["field_name"] = field_name
        if target_stage is not None and "target_stage" not in context:
            context["target_stage"] = target_stage
        super().__init__(message=message, code=code, **context)


def sanitise_validation_errors(exc: Any) -> list[dict[str, Any]]:
    """Sanitise Pydantic validation error entries, stripping raw input and context.

    Ensures that no raw rejected input or unvaulted PII is leaked into error logs,
    telemetry, or prompt payloads.
    """
    if hasattr(exc, "errors") and callable(exc.errors):
        raw_errors = exc.errors(include_input=False, include_context=False, include_url=False)
    elif isinstance(exc, list):
        raw_errors = exc
    else:
        raw_errors = [{"msg": str(exc), "type": "value_error"}]

    sanitised: list[dict[str, Any]] = []
    # Lazy import to avoid circular dependency
    from blockstate.security.pii_patterns import detect_pii_spans

    for err in raw_errors:
        cleaned: dict[str, Any] = dict(err)
        cleaned.pop("input", None)
        cleaned.pop("ctx", None)
        cleaned.pop("url", None)

        msg = str(cleaned.get("msg", ""))
        spans = detect_pii_spans(msg)
        if spans:
            chars = list(msg)
            for span in sorted(spans, key=lambda s: s.start, reverse=True):
                chars[span.start : span.end] = list("[REDACTED_PII]")
            cleaned["msg"] = "".join(chars)

        sanitised.append(cleaned)

    return sanitised


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


__all__: list[str] = [
    "ASTError",
    "BlockstateError",
    "CheckpointNotFoundError",
    "ConcurrentSessionError",
    "ConfigurationError",
    "DisqualifyingBreachError",
    "DuplicateStageError",
    "DynamicTransitionError",
    "FieldValidationError",
    "InvalidStageGraphError",
    "LeaseTimeoutError",
    "ModelError",
    "ModelRefusalError",
    "OptimisticLockError",
    "Pass1TimeoutError",
    "SecurityViolationError",
    "SlotValidationError",
    "StackOverflowError",
    "StorageError",
    "UnauthorisedMutationError",
    "UnreachableStageError",
    "sanitise_validation_errors",
]

