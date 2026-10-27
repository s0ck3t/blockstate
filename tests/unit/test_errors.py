"""Unit tests for Blockstate structured error taxonomy and diagnostics."""

import pytest

from blockstate.errors import (
    ASTError,
    BlockstateError,
    CheckpointNotFoundError,
    ConcurrentSessionError,
    ConfigurationError,
    DuplicateStageError,
    DynamicTransitionError,
    FieldValidationError,
    InvalidStageGraphError,
    LeaseTimeoutError,
    ModelError,
    ModelRefusalError,
    OptimisticLockError,
    Pass1TimeoutError,
    SecurityViolationError,
    SlotValidationError,
    StackOverflowError,
    StorageError,
    UnauthorisedMutationError,
    UnreachableStageError,
)


def test_blockstate_error_string_formatting_with_stage() -> None:
    """Verify BlockstateError formats correctly with deterministic code, message, and stage."""
    err = BlockstateError(code="BLK-CFG-001", message="Duplicate stage", stage="login")
    rendered = str(err)

    assert "[BLK-CFG-001] Duplicate stage (stage=login)" in rendered
    assert err.code == "BLK-CFG-001"
    assert err.message == "Duplicate stage"
    assert err.stage == "login"


def test_blockstate_e014_error_formatting() -> None:
    """Verify dynamic transition errors format with [Blockstate E014] diagnostic prefix."""
    err = BlockstateError(code="BLK-AST-014", message="Dynamic transition detected")
    assert "[Blockstate E014] Dynamic transition detected" in str(err)

    err_custom = DynamicTransitionError("Dynamic transition destination detected at flow.py:42")
    assert err_custom.code == "BLK-AST-014"
    expected_msg = "[Blockstate E014] Dynamic transition destination detected at flow.py:42"
    assert expected_msg in str(err_custom)

    err_literal_prefix = BlockstateError(code="[Blockstate E014]", message="Dynamic target found")
    assert "[Blockstate E014] Dynamic target found" in str(err_literal_prefix)


def test_blockstate_error_full_context_formatting() -> None:
    """Verify session_id, turn_index, and arbitrary context kwargs are formatted."""
    err = BlockstateError(
        message="Lease contention detected",
        code="BLK-CON-409",
        stage="kyc_verification",
        session_id="session-xyz-123",
        turn_index=3,
        fenced_owner="worker-01",
        retry_after_ms=500,
    )
    rendered = str(err)

    assert "[BLK-CON-409] Lease contention detected" in rendered
    assert "stage=kyc_verification" in rendered
    assert "session_id=session-xyz-123" in rendered
    assert "turn_index=3" in rendered
    assert "fenced_owner=worker-01" in rendered
    assert "retry_after_ms=500" in rendered


def test_blockstate_error_positional_swapped_calling() -> None:
    """Verify positional invocation (code, message) is supported gracefully."""
    err = BlockstateError("BLK-CFG-001", "Duplicate stage detected")
    assert err.code == "BLK-CFG-001"
    assert err.message == "Duplicate stage detected"


def test_blockstate_error_repr() -> None:
    """Verify __repr__ provides clear diagnostic attributes."""
    err = DuplicateStageError("Duplicate stage 'login'", stage="login")
    rep = repr(err)

    assert "DuplicateStageError" in rep
    assert "BLK-CFG-001" in rep
    assert "stage='login'" in rep


@pytest.mark.parametrize(
    ("cls", "expected_code", "base_cls"),
    [
        (ConfigurationError, "BLK-CFG-002", BlockstateError),
        (DuplicateStageError, "BLK-CFG-001", ConfigurationError),
        (ASTError, "BLK-AST-001", BlockstateError),
        (InvalidStageGraphError, "BLK-AST-001", ASTError),
        (UnreachableStageError, "BLK-AST-002", ASTError),
        (DynamicTransitionError, "BLK-AST-014", ASTError),
        (SecurityViolationError, "BLK-SEC-001", BlockstateError),
        (UnauthorisedMutationError, "BLK-SEC-002", SecurityViolationError),
        (StackOverflowError, "BLK-SEC-003", SecurityViolationError),
        (SlotValidationError, "BLK-VAL-001", BlockstateError),
        (FieldValidationError, "BLK-VAL-002", SlotValidationError),
        (ConcurrentSessionError, "BLK-CON-409", BlockstateError),
        (StorageError, "BLK-STO-001", BlockstateError),
        (OptimisticLockError, "BLK-STO-002", StorageError),
        (LeaseTimeoutError, "BLK-STO-003", StorageError),
        (CheckpointNotFoundError, "BLK-STO-004", StorageError),
        (ModelError, "BLK-MOD-001", BlockstateError),
        (ModelRefusalError, "BLK-MOD-002", ModelError),
        (Pass1TimeoutError, "BLK-MOD-003", ModelError),
    ],
)
def test_domain_subclass_hierarchy_and_default_codes(
    cls: type[BlockstateError],
    expected_code: str,
    base_cls: type[BlockstateError],
) -> None:
    """Verify all domain exception classes inherit correctly and expose default codes."""
    assert issubclass(cls, base_cls)
    assert issubclass(cls, BlockstateError)

    instance = cls("Test failure description")
    assert instance.code == expected_code
    assert "Test failure description" in str(instance)


def test_catch_subclass_as_blockstate_error() -> None:
    """Verify domain exceptions can be caught polymorphically via BlockstateError."""
    with pytest.raises(BlockstateError) as exc_info:
        raise UnauthorisedMutationError(
            "Child frame tried to mutate parent slot",
            stage="digression_1",
        )

    assert exc_info.value.code == "BLK-SEC-002"
    assert "stage=digression_1" in str(exc_info.value)
