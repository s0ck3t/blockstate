"""Unit tests for declarative Transition primitives and ChoicePayload."""

from typing import Any

import pytest
from pydantic import ValidationError

from blockstate.core.transitions import (
    ChoicePayload,
    SlotDelta,
    SlotMutation,
    Transition,
    VaultDelta,
)


def test_transition_to_valid_target() -> None:
    """Verify Transition.to constructs a forward transition."""
    trans = Transition.to("collect_details", reason="initial")
    assert trans.target == "collect_details"
    assert trans.is_stay is False
    assert trans.is_pop is False
    assert trans.is_end is False
    assert trans.metadata == {"reason": "initial"}
    assert repr(trans) == "Transition.to('collect_details')"


def test_transition_to_empty_target_raises_value_error() -> None:
    """Verify Transition.to rejects empty destination strings."""
    with pytest.raises(ValueError, match="non-empty string identifier"):
        Transition.to("")


def test_transition_stay() -> None:
    """Verify Transition.stay retains the current stage."""
    trans = Transition.stay(retry=True)
    assert trans.target is None
    assert trans.is_stay is True
    assert trans.is_pop is False
    assert trans.is_end is False
    assert trans.metadata == {"retry": True}
    assert repr(trans) == "Transition.stay()"


def test_transition_pop_frame() -> None:
    """Verify Transition.pop_frame with and without mutation payload."""
    trans_empty = Transition.pop_frame()
    assert trans_empty.target is None
    assert trans_empty.is_pop is True
    assert trans_empty.mutation is None
    assert repr(trans_empty) == "Transition.pop_frame(mutation=None)"

    mutation = SlotMutation(updates={"verified": True})
    trans_mut = Transition.pop_frame(mutation=mutation)
    assert trans_mut.is_pop is True
    assert trans_mut.mutation == mutation


def test_transition_end() -> None:
    """Verify Transition.end denotes terminal state with result."""
    trans = Transition.end(result={"status": "approved"})
    assert trans.target is None
    assert trans.is_end is True
    assert trans.result == {"status": "approved"}
    assert repr(trans) == "Transition.end(result={'status': 'approved'})"


def test_transition_decorator_and_equality_repr() -> None:
    """Verify Transition decorator usage, equality comparisons, and repr formats."""
    t_dec: Transition[Any] = Transition(targets=["s1", "s2"])
    assert t_dec.declared_targets == ("s1", "s2")
    assert repr(t_dec) == "Transition(targets=('s1', 's2'))"

    def dummy() -> None:
        pass

    decorated = t_dec(dummy)
    assert getattr(decorated, "_blockstate_targets") == ("s1", "s2")  # noqa: B009

    t_empty: Transition[Any] = Transition()
    assert repr(t_empty) == "Transition()"

    t1 = Transition.to("stage_a")
    t2 = Transition.to("stage_a")
    t3 = Transition.to("stage_b")
    assert t1 == t2
    assert t1 != t3
    assert t1 != "not_a_transition"


def test_slot_mutation_immutability() -> None:
    """Verify SlotMutation is frozen and immutable."""
    mutation = SlotMutation(updates={"amount": 100}, force=False)
    assert mutation.updates == {"amount": 100}
    assert mutation.force is False
    with pytest.raises(AttributeError):
        mutation.force = True  # type: ignore[misc]


def test_slot_delta_completion() -> None:
    """Verify SlotDelta tracks missing leaf paths and completion status."""
    incomplete = SlotDelta(missing=("name", "age"), hydrated={"postcode": "SW1A 1AA"})
    assert incomplete.is_complete is False
    assert len(incomplete.missing) == 2

    complete = SlotDelta(missing=(), hydrated={"name": "Alice", "age": 30})
    assert complete.is_complete is True


def test_vault_delta() -> None:
    """Verify VaultDelta tracks newly tokenised session items."""
    delta = VaultDelta(new_tokens={"<VAULT:NINO_01>": "QQ123456C"})
    assert delta.new_tokens["<VAULT:NINO_01>"] == "QQ123456C"


def test_choice_payload_creation_and_immutability() -> None:
    """Verify ChoicePayload model structure and immutability."""
    payload = ChoicePayload(
        prompt="Select your preferred contact method:",
        options=["Email", "SMS", "Post"],
        allow_custom=False,
    )
    assert payload.prompt == "Select your preferred contact method:"
    assert payload.options == ["Email", "SMS", "Post"]
    assert payload.allow_custom is False

    with pytest.raises(ValidationError):
        # extra="forbid" prevents arbitrary attributes
        ChoicePayload(prompt="Test", options=["A"], unexpected=123)  # type: ignore[call-arg]
