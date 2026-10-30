"""Unit tests for two-tier memory isolation, TaskStack limits, and slot mutations."""

import pytest

from blockstate.core.stack import (
    ReadOnlySessionView,
    SessionState,
    TaskFrame,
    TaskFrameState,
    TaskStack,
)
from blockstate.core.transitions import SlotMutation
from blockstate.errors import StackOverflowError, UnauthorisedMutationError


def test_session_state_crud() -> None:
    """Verify SessionState stores and isolates cross-flow verified session facts."""
    session = SessionState()
    session.set("user_id", "usr_123")
    session.set("auth_level", "tier_2")
    session.update({"risk_score": 0.15, "tags": {"trusted", "uk"}})

    assert session.get("user_id") == "usr_123"
    assert session["auth_level"] == "tier_2"
    assert "risk_score" in session
    assert len(session) == 4

    snapshot = session.to_dict()
    assert snapshot["user_id"] == "usr_123"
    # Mutations to snapshot do not affect session
    snapshot["user_id"] = "tampered"
    assert session.get("user_id") == "usr_123"

    ro = session.as_readonly()
    assert ro["user_id"] == "usr_123"
    assert "trusted" in ro["tags"]


@pytest.mark.patent_invariant
def test_readonly_session_view_immutability() -> None:
    """Verify ReadOnlySessionView is completely frozen and prevents in-place mutations."""
    view = ReadOnlySessionView.create(
        session_id="sess_001",
        state={
            "customer_id": "cust_456",
            "roles": ["viewer", "editor"],
            "meta": {"ip": "127.0.0.1"},
            "permissions": {"read", "write"},
        },
        current_stage="verify_identity",
        stack_depth=1,
    )

    assert view.session_id == "sess_001"
    assert view.current_stage == "verify_identity"
    assert view.stack_depth == 1
    assert view.get("customer_id") == "cust_456"
    assert view["customer_id"] == "cust_456"
    assert "roles" in view
    assert len(view) == 4

    # Direct mutation attempts fail
    with pytest.raises((TypeError, AttributeError)):
        view.state["customer_id"] = "mutated"  # type: ignore[index]

    with pytest.raises((TypeError, AttributeError)):
        view.state["meta"]["ip"] = "0.0.0.0"


def test_task_frame_state_snapshot() -> None:
    """Verify TaskFrameState data container."""
    frame_state = TaskFrameState(
        stage_id="stage_one",
        slots={"name": "Alice"},
        locked_slots={"name"},
        turn_count=2,
    )
    assert frame_state.stage_id == "stage_one"
    assert frame_state.slots == {"name": "Alice"}
    assert frame_state.locked_slots == {"name"}
    assert frame_state.turn_count == 2


def test_task_frame_slot_navigation_and_copy() -> None:
    """Verify TaskFrame nested slot retrieval, unlocking, and deep copying."""
    frame = TaskFrame(stage_id="stage_test")
    frame.set_slot("user.profile.age", 25, lock=True)
    assert frame.get_slot("user.profile.age") == 25
    assert frame.is_locked("user.profile.age")
    assert frame.is_locked("user.profile")
    assert frame.is_locked("user")

    frame.unlock_slot("user.profile.age")
    assert not frame.is_locked("user.profile.age")

    frame.lock_slots(["a", "b"])
    assert frame.is_locked("a")
    assert frame.is_locked("b")

    copied = frame.copy()
    assert copied.stage_id == frame.stage_id
    assert copied.get_slot("user.profile.age") == 25
    copied.set_slot("user.profile.age", 30)
    assert frame.get_slot("user.profile.age") == 25
    assert copied.get_slot("user.profile.age") == 30


@pytest.mark.patent_invariant
def test_task_stack_pushdown_depth_limit() -> None:
    """Verify TaskStack enforces maximum stack depth of 6 and raises StackOverflowError."""
    stack = TaskStack(max_stack_depth=6)
    assert len(stack) == 0
    assert stack.top is None
    assert stack.peek() is None

    # Push 6 frames successfully
    for i in range(1, 7):
        frame = TaskFrame(stage_id=f"stage_{i}")
        stack.push(frame)
        assert len(stack) == i
        assert stack.top is not None
        assert stack.top.stage_id == f"stage_{i}"

    # Attempting to push a 7th frame raises StackOverflowError
    overflow_frame = TaskFrame(stage_id="stage_overflow")
    with pytest.raises(StackOverflowError) as exc_info:
        stack.push(overflow_frame)

    assert exc_info.value.code == "BLK-SEC-003"
    assert exc_info.value.stage == "stage_overflow"
    assert "exceeds maximum limit of 6" in str(exc_info.value)
    assert len(stack) == 6


def test_task_stack_pop_and_peek() -> None:
    """Verify TaskStack pop and peek operations."""
    stack = TaskStack(max_stack_depth=6)
    f1 = TaskFrame(stage_id="s1")
    f2 = TaskFrame(stage_id="s2")

    stack.push(f1)
    stack.push(f2)

    assert stack.peek() == f2
    popped = stack.pop()
    assert popped == f2
    assert stack.top == f1
    assert len(stack) == 1

    popped_last = stack.pop()
    assert popped_last == f1
    assert len(stack) == 0

    with pytest.raises(IndexError):
        stack.pop()


def test_task_stack_iteration_and_repr() -> None:
    """Verify TaskStack iterates from bottom to top and has informative repr."""
    stack = TaskStack(max_stack_depth=6)
    stack.push(TaskFrame(stage_id="main"))
    stack.push(TaskFrame(stage_id="digression"))

    stages = [f.stage_id for f in stack]
    assert stages == ["main", "digression"]
    assert "TaskStack(depth=2, max_depth=6" in repr(stack)


@pytest.mark.patent_invariant
def test_parent_frame_rejects_child_mutation_without_overrides() -> None:
    """Verify parent TaskFrame rejects child mutation when allow_slot_overrides is False."""
    parent = TaskFrame(stage_id="parent_stage", allow_slot_overrides=False, slots={"amount": 50})
    mutation = SlotMutation(updates={"amount": 100}, force=False)

    with pytest.raises(UnauthorisedMutationError) as exc_info:
        parent.apply_child_mutation(mutation)

    assert exc_info.value.code == "BLK-SEC-002"
    assert exc_info.value.stage == "parent_stage"
    assert parent.get_slot("amount") == 50


@pytest.mark.patent_invariant
def test_parent_frame_accepts_child_mutation_with_allow_slot_overrides() -> None:
    """Verify parent TaskFrame applies child mutation when allow_slot_overrides is True."""
    parent = TaskFrame(stage_id="parent_stage", allow_slot_overrides=True, slots={"amount": 50})
    mutation = SlotMutation(updates={"amount": 100, "note": "approved"})

    parent.apply_child_mutation(mutation)
    assert parent.get_slot("amount") == 100
    assert parent.get_slot("note") == "approved"
    assert parent.is_locked("amount")
    assert parent.is_locked("note")


@pytest.mark.patent_invariant
def test_parent_frame_accepts_forced_child_mutation() -> None:
    """Verify parent TaskFrame applies child mutation when force is True."""
    parent = TaskFrame(stage_id="parent_stage", allow_slot_overrides=False, slots={"amount": 50})
    mutation = SlotMutation(updates={"amount": 200}, force=True)

    parent.apply_child_mutation(mutation)
    assert parent.get_slot("amount") == 200
