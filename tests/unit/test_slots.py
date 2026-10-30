"""Unit tests and Hypothesis property fuzzers for recursive slot hydration.

Verifies UNSET sentinel, PartialSlotMetaclass, SlotHydrator, leaf-path Delta-Hydration,
TaskFrame locked-slot immutability, in-memory Vaulted[T] detokenisation, sanitised validation
errors, DisqualifyingBreachError on_breach routing, and property fuzzing across >=500 examples.
"""

import copy
import re
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel, field_validator

from blockstate.core.slots import (
    UNSET,
    PartialSlotMetaclass,
    PartialSlotModel,
    SlotHydrator,
    active_vault_context,
    compute_required_leaf_paths,
    get_leaf_value,
    get_schema_depth,
    is_unset,
)
from blockstate.core.stack import TaskFrame, TaskStack
from blockstate.errors import (
    ConfigurationError,
    DisqualifyingBreachError,
    FieldValidationError,
    StackOverflowError,
    UnauthorisedMutationError,
    sanitise_validation_errors,
)
from blockstate.security.annotations import Vaulted
from blockstate.security.vault import PIIVault
from blockstate.testing.strategies import (
    get_leaf_annotation,
    st_candidate_slots,
    st_nested_model,
    st_vaulted_model,
)

# =============================================================================
# 1. UNSET Sentinel Invariants
# =============================================================================


@pytest.mark.patent_invariant
def test_unset_singleton_behaviour() -> None:
    """Verify UNSET singleton semantics, falsiness, repr, and copy preservation."""
    assert is_unset(UNSET)
    assert not UNSET  # bool(UNSET) is False
    assert repr(UNSET) == "UNSET"
    assert str(UNSET) == "UNSET"

    # Preserves singleton identity across shallow and deep copy
    assert copy.copy(UNSET) is UNSET
    assert copy.deepcopy(UNSET) is UNSET

    # Verify is_unset helper
    assert not is_unset(None)
    assert not is_unset(0)
    assert not is_unset("")
    assert not is_unset(False)


# =============================================================================
# 2. Schema Nesting Depth Limit (max_nesting_depth=8)
# =============================================================================


def test_schema_nesting_depth_calculation() -> None:
    """Verify schema depth calculation across flat and deeply nested models."""

    class Leaf(BaseModel):
        val: int

    class Level2(BaseModel):
        child: Leaf

    class Level3(BaseModel):
        sub: Level2

    assert get_schema_depth(Leaf) == 1
    assert get_schema_depth(Level2) == 2
    assert get_schema_depth(Level3) == 3


@pytest.mark.patent_invariant
def test_exceeding_max_nesting_depth_raises_configuration_error() -> None:
    """Verify models nested beyond max_nesting_depth=8 raise ConfigurationError (BLK-CFG-002)."""
    # Dynamically build a 9-level nested model
    current: type[BaseModel] = type("L1", (BaseModel,), {"__annotations__": {"x": int}})
    for i in range(2, 10):
        current = type(
            f"L{i}",
            (BaseModel,),
            {"__annotations__": {"child": current}},
        )

    # get_schema_depth on 9-level model must raise ConfigurationError
    with pytest.raises(ConfigurationError) as exc_info:
        get_schema_depth(current, max_nesting_depth=8)

    assert exc_info.value.code == "BLK-CFG-002"
    assert "exceeds max_nesting_depth=8" in str(exc_info.value)

    # Transforming via PartialSlotMetaclass must also reject depth 9
    with pytest.raises(ConfigurationError) as exc_info2:
        PartialSlotMetaclass.from_model(current, max_nesting_depth=8)
    assert exc_info2.value.code == "BLK-CFG-002"

    # Initialising SlotHydrator must also reject depth 9
    with pytest.raises(ConfigurationError) as exc_info3:
        SlotHydrator(current, max_nesting_depth=8)
    assert exc_info3.value.code == "BLK-CFG-002"


def test_exactly_max_nesting_depth_8_succeeds() -> None:
    """Verify schemas nested to exactly depth 8 succeed without error."""
    current: type[BaseModel] = type("L1", (BaseModel,), {"__annotations__": {"x": int}})
    for i in range(2, 9):
        current = type(
            f"L{i}",
            (BaseModel,),
            {"__annotations__": {"child": current}},
        )

    assert get_schema_depth(current, max_nesting_depth=8) == 8
    partial_cls = PartialSlotMetaclass.from_model(current, max_nesting_depth=8)
    assert issubclass(partial_cls, PartialSlotModel)


# =============================================================================
# 3. PartialSlotMetaclass & PartialSlotModel Hydration
# =============================================================================


class SimplePerson(BaseModel):
    name: str
    age: int


class AddressModel(BaseModel):
    postcode: str
    city: str = "London"


class TwoLevelUser(BaseModel):
    name: str
    address: AddressModel


@pytest.mark.patent_invariant
def test_single_valid_leaf_partial_model_hydration() -> None:
    """Scenario: Single valid leaf provided: {"name": "Alice"} for model requiring name and age.

    Partial model succeeds, name="Alice", age=UNSET, Delta = {'age'}.
    """
    partial_cls = PartialSlotMetaclass.from_model(SimplePerson)
    instance: Any = partial_cls(name="Alice")

    assert instance.name == "Alice"
    assert is_unset(instance.age)

    hydrator = SlotHydrator(SimplePerson)
    res = hydrator.hydrate({"name": "Alice"})

    assert not res.is_complete
    assert res.delta == {"age"}
    assert res.hydrated_slots["name"] == "Alice"
    assert "name" in res.locked_slots
    assert res.target_model_instance is None


def test_nested_model_partial_hydration() -> None:
    """Scenario: Nested model partial hydration: {"address": {"postcode": "SW1A 1AA"}}.

    Partial model hydrates address.postcode, other fields remain UNSET.
    """
    hydrator = SlotHydrator(TwoLevelUser)
    res = hydrator.hydrate({"address": {"postcode": "SW1A 1AA"}})

    assert not res.is_complete
    assert "address.postcode" in res.hydrated_slots
    assert res.hydrated_slots["address.postcode"] == "SW1A 1AA"
    assert "address.postcode" in res.locked_slots
    assert res.delta == {"name"}
    assert res.target_model_instance is None


def test_metaclass_direct_subclass_creation() -> None:
    """Verify PartialSlotMetaclass handles direct subclass definitions."""

    class CustomPartial(BaseModel, metaclass=PartialSlotMetaclass, target_model=SimplePerson):
        pass

    assert issubclass(CustomPartial, PartialSlotModel)
    inst = CustomPartial(name="Bob")
    assert inst.name == "Bob"  # type: ignore[attr-defined]
    assert is_unset(inst.age)  # type: ignore[attr-defined]


# =============================================================================
# 4. Validation Errors, Sanitisation & Sibling Isolation
# =============================================================================


class ValidatedCandidate(BaseModel):
    name: str
    age: int

    @field_validator("age", mode="after")
    @classmethod
    def validate_age(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"Age cannot be negative: received {v}")
        return v


def test_invalid_candidate_field_sanitised_error() -> None:
    """Scenario: Invalid candidate field: {"age": -5} where validator requires age >= 0.

    Captures sanitised FieldValidationError without leaking raw input -5 or ctx.
    """
    hydrator = SlotHydrator(ValidatedCandidate)
    res = hydrator.hydrate({"age": -5})

    assert not res.is_complete
    assert len(res.validation_errors) == 1
    err = res.validation_errors[0]

    assert err.code == "BLK-VAL-002"
    assert err.field_path == "age"
    # Ensure raw input -5 is omitted from errors dictionary
    for e in err.errors:
        assert "input" not in e
        assert "ctx" not in e


@pytest.mark.patent_invariant
def test_sibling_slot_isolation_on_partial_failure() -> None:
    """Verify valid leaf paths lock even when a sibling field in the same turn fails validation."""
    hydrator = SlotHydrator(ValidatedCandidate)
    res = hydrator.hydrate({"name": "Alice", "age": -5})

    assert not res.is_complete
    # Valid leaf 'name' must be locked and persisted
    assert res.hydrated_slots.get("name") == "Alice"
    assert "name" in res.locked_slots
    # Invalid leaf 'age' must be omitted from hydrated slots
    assert "age" not in res.hydrated_slots
    assert "age" not in res.locked_slots
    # Validation error captured for age
    assert len(res.validation_errors) == 1
    assert res.validation_errors[0].field_path == "age"


# =============================================================================
# 5. Locked Slot Overwrite Protection & TaskFrame Integration
# =============================================================================


@pytest.mark.patent_invariant
def test_locked_slot_overwrite_raises_unauthorised_mutation_error() -> None:
    """Scenario: Locked slot overwrite rejection.

    Attempting to overwrite previously validated and locked slot raises
    UnauthorisedMutationError (BLK-SEC-002).
    """
    frame = TaskFrame(stage_id="personal_details", target_model=SimplePerson)
    hydrator = SlotHydrator(SimplePerson)

    # First turn hydrates and locks 'name'
    hydrator.hydrate({"name": "Alice"}, frame=frame)
    assert "name" in frame.locked_slots
    assert frame.get_slot("name") == "Alice"

    # Second turn attempts unauthorised overwrite of locked 'name'
    with pytest.raises(UnauthorisedMutationError) as exc_info:
        hydrator.hydrate({"name": "Eve"}, frame=frame)

    assert exc_info.value.code == "BLK-SEC-002"
    assert "Cannot overwrite locked slot 'name'" in str(exc_info.value)
    # Frame slot remains unmutated
    assert frame.get_slot("name") == "Alice"


def test_locked_slot_overwrite_with_explicit_override_succeeds() -> None:
    """Verify locked slot overwrite succeeds when allow_overrides=True or frame permits it."""
    frame = TaskFrame(stage_id="personal_details", target_model=SimplePerson)
    hydrator = SlotHydrator(SimplePerson)

    hydrator.hydrate({"name": "Alice"}, frame=frame)
    assert frame.get_slot("name") == "Alice"

    # Allow override explicitly via parameter
    res2 = hydrator.hydrate({"name": "Alice Updated"}, frame=frame, allow_overrides=True)
    assert frame.get_slot("name") == "Alice Updated"
    assert res2.hydrated_slots["name"] == "Alice Updated"

    # Allow override via frame flag
    frame.allow_slot_overrides = True
    hydrator.hydrate({"name": "Alice Final"}, frame=frame)
    assert frame.get_slot("name") == "Alice Final"


def test_task_frame_direct_mutation_protection() -> None:
    """Verify TaskFrame.set_slot and update_slots enforce lock boundaries."""
    frame = TaskFrame(stage_id="test_stage")
    frame.set_slot("email", "alice@example.com", lock=True)
    assert frame.is_locked("email")

    with pytest.raises(UnauthorisedMutationError) as exc_info:
        frame.set_slot("email", "eve@example.com")
    assert exc_info.value.code == "BLK-SEC-002"

    with pytest.raises(UnauthorisedMutationError) as exc_info2:
        frame.update_slots({"email": "eve@example.com", "other": 1})
    assert exc_info2.value.code == "BLK-SEC-002"

    # Force bypass works
    frame.set_slot("email", "alice2@example.com", force=True)
    assert frame.get_slot("email") == "alice2@example.com"

    # Copy isolation
    clone = frame.copy()
    assert clone.get_slot("email") == "alice2@example.com"
    assert clone.is_locked("email")
    clone.unlock_slot("email")
    assert not clone.is_locked("email")
    assert frame.is_locked("email")  # Original remains locked


# =============================================================================
# 6. TaskStack Bounded Pushdown Automata
# =============================================================================


def test_task_stack_push_pop_and_depth_limits() -> None:
    """Verify TaskStack push, pop, peek, and StackOverflowError (BLK-SEC-003)."""
    stack = TaskStack(max_stack_depth=3)
    assert len(stack) == 0
    assert stack.peek() is None

    f1 = TaskFrame(stage_id="s1")
    f2 = TaskFrame(stage_id="s2")
    f3 = TaskFrame(stage_id="s3")
    f4 = TaskFrame(stage_id="s4")

    stack.push(f1)
    stack.push(f2)
    stack.push(f3)
    assert len(stack) == 3
    assert stack.top is f3

    # Exceeding max_stack_depth=3 raises StackOverflowError
    with pytest.raises(StackOverflowError) as exc_info:
        stack.push(f4)
    assert exc_info.value.code == "BLK-SEC-003"
    assert "exceeds maximum limit of 3" in str(exc_info.value)

    # Pop frames
    assert stack.pop() is f3
    assert stack.pop() is f2
    assert stack.pop() is f1
    assert len(stack) == 0

    with pytest.raises(IndexError):
        stack.pop()


# =============================================================================
# 7. Vaulted[T] Validator Detokenisation & Re-binding
# =============================================================================


class KycVerificationModel(BaseModel):
    user_id: str
    nino: Vaulted[str]

    @field_validator("nino", mode="after")
    @classmethod
    def validate_nino(cls, v: str) -> str:
        # Requires valid UK NINo format
        if not re.match(r"^[A-Z]{2}\s?\d{6}\s?[A-D]$", v):
            raise ValueError(f"Invalid National Insurance number: {v}")
        return v


@pytest.mark.patent_invariant
def test_vaulted_validator_detokenisation_and_token_rebinding() -> None:
    """Scenario: Vaulted[T] validator detokenisation: {"nino": "<VAULT:NINO_01>"}.

    Detokenises in-memory for validator, passes validation, slot retains <VAULT:NINO_01>.
    """
    token = "<VAULT:NINO_01>"
    plaintext = "QQ123456C"
    vault_map = {token: plaintext}

    vault = PIIVault()
    vault.seed_vault_map("sess_1", vault_map)

    hydrator = SlotHydrator(KycVerificationModel, vault=vault, vault_map=vault_map)
    res = hydrator.hydrate({"user_id": "usr_99", "nino": token})

    # Passes validation with zero errors
    assert not res.validation_errors
    assert res.is_complete
    assert res.delta == set()

    # Slot attribute strictly retains the opaque token
    assert res.hydrated_slots["nino"] == token
    assert isinstance(res.target_model_instance, KycVerificationModel)
    assert res.target_model_instance.nino == token


@pytest.mark.patent_invariant
def test_vaulted_validator_error_does_not_leak_raw_pii() -> None:
    """Verify that when a Vaulted[T] field validator fails, plaintext PII is not leaked."""
    token = "<VAULT:NINO_02>"
    invalid_plaintext = "INVALID_NINO"
    vault_map = {token: invalid_plaintext}

    hydrator = SlotHydrator(KycVerificationModel, vault_map=vault_map)
    res = hydrator.hydrate({"user_id": "usr_99", "nino": token})

    assert len(res.validation_errors) == 1
    err = res.validation_errors[0]
    err_msg = str(err)

    # Raw plaintext must never appear in the error message
    assert invalid_plaintext not in err_msg
    assert token in err_msg


# =============================================================================
# 8. On-Breach Validation Failure (DisqualifyingBreachError)
# =============================================================================


class AgeBreachModel(BaseModel):
    name: str
    age: int

    @field_validator("age", mode="after")
    @classmethod
    def check_age(cls, v: int) -> int:
        if v < 18:
            raise DisqualifyingBreachError(
                "Applicant under 18 is disqualified",
                field_name="age",
                target_stage="ineligible_age_stage",
            )
        return v


@pytest.mark.patent_invariant
def test_disqualifying_breach_error_signals_on_breach_routing() -> None:
    """Scenario: On-breach validation failure.

    Field validator raises DisqualifyingBreachError on ineligible value.
    Triggers early stage breach transition flag; signals on_breach routing.
    """
    hydrator = SlotHydrator(AgeBreachModel)
    res = hydrator.hydrate({"name": "Bob", "age": 16})

    assert res.is_breach is True
    assert res.breach_error is not None
    assert res.breach_error.field_name == "age"
    assert res.breach_error.target_stage == "ineligible_age_stage"
    assert res.target_model_instance is None


# =============================================================================
# 9. All Delta Fields Complete (Delta == Empty)
# =============================================================================


@pytest.mark.patent_invariant
def test_all_delta_fields_complete_instantiates_strict_target_model() -> None:
    """Scenario: All delta fields complete (Delta == Empty).

    All required leaf paths hydrated and valid -> Instantiates strict TargetModel.
    """
    hydrator = SlotHydrator(TwoLevelUser)

    # Step 1: Supply name only
    res1 = hydrator.hydrate({"name": "Alice"})
    assert res1.delta == {"address.postcode"}
    assert res1.target_model_instance is None

    # Step 2: Supply remaining required slot 'address.postcode'
    res2 = hydrator.hydrate(
        {"address.postcode": "SW1A 1AA"},
        existing_slots=res1.hydrated_slots,
        locked_slots=res1.locked_slots,
    )
    assert res2.delta == set()
    assert res2.is_complete is True
    assert res2.target_model_instance is not None
    assert isinstance(res2.target_model_instance, TwoLevelUser)
    assert res2.target_model_instance.name == "Alice"
    assert res2.target_model_instance.address.postcode == "SW1A 1AA"
    assert res2.target_model_instance.address.city == "London"  # Default preserved


# =============================================================================
# 10. Sanitise Validation Errors Utility & Additional Edge Cases
# =============================================================================


def test_sanitise_validation_errors_utility() -> None:
    """Verify sanitise_validation_errors scrubs input, ctx, and detected PII."""
    raw_mock_error = [
        {
            "loc": ("nino",),
            "msg": "Value error, NINo QQ123456C invalid",
            "type": "value_error",
            "input": "QQ123456C",
            "ctx": {"raw": "QQ123456C"},
        }
    ]
    cleaned = sanitise_validation_errors(raw_mock_error)
    assert len(cleaned) == 1
    assert "input" not in cleaned[0]
    assert "ctx" not in cleaned[0]
    # NINo PII should be redacted
    assert "QQ123456C" not in cleaned[0]["msg"]
    assert "[REDACTED_PII]" in cleaned[0]["msg"]


class InfoVaultedModel(BaseModel):
    user_id: str
    nino: Vaulted[str]

    @field_validator("nino", mode="after")
    @classmethod
    def val_info(cls, v: str, info: Any) -> str:
        if v == "BREACH":
            raise DisqualifyingBreachError("Breach triggered in info validator")
        if not re.match(r"^[A-Z]{2}\d{6}[A-D]$", v):
            raise ValueError(f"Bad NINo in info validator: {v}")
        return v


def test_info_vaulted_validator_takes_info_path() -> None:
    """Verify field validator taking ValidationInfo detokenises and re-binds properly."""
    token = "<VAULT:NINO_55>"
    vault_map = {token: "QQ123456C"}
    hydrator = SlotHydrator(InfoVaultedModel, vault_map=vault_map)
    res = hydrator.hydrate({"user_id": "usr_1", "nino": token})
    assert res.is_complete
    assert isinstance(res.target_model_instance, InfoVaultedModel)
    assert res.target_model_instance.nino == token

    # Test error sanitisation with info validator
    bad_token = "<VAULT:NINO_BAD>"
    bad_map = {bad_token: "INVALID_NINO"}
    res_err = hydrator.hydrate({"user_id": "usr_1", "nino": bad_token}, vault_map=bad_map)
    assert len(res_err.validation_errors) == 1
    assert "INVALID_NINO" not in str(res_err.validation_errors[0])
    assert bad_token in str(res_err.validation_errors[0])

    # Test breach with info validator
    breach_token = "<VAULT:NINO_BREACH>"
    breach_map = {breach_token: "BREACH"}
    res_breach = hydrator.hydrate(
        {"user_id": "usr_1", "nino": breach_token},
        vault_map=breach_map,
    )
    assert res_breach.is_breach


class TargetDirectInfoModel(BaseModel):
    nino: Vaulted[str]

    @field_validator("nino", mode="after")
    @classmethod
    def val_info(cls, v: str, info: Any) -> str:
        if v == "BREACH":
            raise DisqualifyingBreachError("Direct target breach info")
        if v == "BAD":
            raise ValueError(f"Secret leaked: {v}")
        return v


class TargetDirectPlainModel(BaseModel):
    nino: Vaulted[str]

    @field_validator("nino", mode="after")
    @classmethod
    def val_plain(cls, v: str) -> str:
        if v == "BREACH":
            raise DisqualifyingBreachError("Direct target breach plain")
        if v == "BAD":
            raise ValueError(f"Secret leaked: {v}")
        return v


def test_target_model_direct_vaulted_validation_error_and_breach() -> None:
    """Verify target model patched validators sanitise errors and handle breaches."""
    SlotHydrator(TargetDirectInfoModel)
    SlotHydrator(TargetDirectPlainModel)

    with active_vault_context(
        vault_map={"<VAULT:NINO_01>": "BREACH", "<VAULT:NINO_02>": "BAD"}
    ):
        with pytest.raises(DisqualifyingBreachError):
            TargetDirectInfoModel(nino="<VAULT:NINO_01>")
        with pytest.raises(ValueError) as exc1:
            TargetDirectInfoModel(nino="<VAULT:NINO_02>")
        assert "BAD" not in str(exc1.value)
        assert "<VAULT:NINO_02>" in str(exc1.value)

        with pytest.raises(DisqualifyingBreachError):
            TargetDirectPlainModel(nino="<VAULT:NINO_01>")
        with pytest.raises(ValueError) as exc2:
            TargetDirectPlainModel(nino="<VAULT:NINO_02>")
        assert "BAD" not in str(exc2.value)
        assert "<VAULT:NINO_02>" in str(exc2.value)


class OptionalChildSub(BaseModel):
    field1: str


class OptionalChildParent(BaseModel):
    id: str
    optional_child: OptionalChildSub | None = None


def test_optional_child_model_and_model_instance_property() -> None:
    """Verify models with optional sub-models and model_instance property alias."""
    hydrator = SlotHydrator(OptionalChildParent)
    assert hydrator.required_leaf_paths == ["id"]

    res = hydrator.hydrate({"id": "1"})
    assert res.is_complete
    assert isinstance(res.target_model_instance, OptionalChildParent)
    assert res.target_model_instance.id == "1"
    assert res.target_model_instance.optional_child is None
    assert res.model_instance is res.target_model_instance

    partial_cls = PartialSlotModel.from_model(OptionalChildParent)
    inst: Any = partial_cls()
    assert inst.optional_child is None


def test_positional_hydrate_arguments_and_unset_candidate() -> None:
    """Verify SlotHydrator.hydrate supports positional frame variations and UNSET skips."""
    hydrator = SlotHydrator(SimplePerson)
    frame1 = TaskFrame(stage_id="s1")

    # Positional (frame, candidate)
    r1 = hydrator.hydrate(frame1, {"name": "Alice"})
    assert r1.hydrated_slots["name"] == "Alice"

    # Positional (candidate, frame)
    frame2 = TaskFrame(stage_id="s2")
    r2 = hydrator.hydrate({"name": "Bob"}, frame2)
    assert r2.hydrated_slots["name"] == "Bob"

    # Passing UNSET explicitly in candidate
    r3 = hydrator.hydrate({"name": UNSET})
    assert not r3.is_complete


def test_dictionary_helpers_edge_cases() -> None:
    """Verify flatten_dict, unflatten_dict, and get_leaf_value across edge cases."""
    from blockstate.core.slots import (
        _extract_model_types,
        flatten_dict,
        get_leaf_value,
        unflatten_dict,
    )

    class Sub(BaseModel):
        b: int

    class Top(BaseModel):
        a: int
        sub: Sub

    top = Top(a=1, sub=Sub(b=2))
    flat = flatten_dict({"top": top, "direct": 10})
    assert flat["top.a"] == 1
    assert flat["top.sub.b"] == 2
    assert flat["direct"] == 10

    unflat = unflatten_dict({"top": Sub(b=3), "nested.sub": {"x": 1}})
    assert unflat["top"] == {"b": 3}
    assert unflat["nested"]["sub"]["x"] == 1

    unflat2 = unflatten_dict({"a.b": 1, "a": {"c": 2}})
    assert unflat2["a"]["b"] == 1
    assert unflat2["a"]["c"] == 2

    # Object with attributes
    class CustomObj:
        def __init__(self) -> None:
            self.attr = "hello"

    obj = CustomObj()
    found, val = get_leaf_value({"o": obj}, "o.attr")
    assert found and val == "hello"

    found_miss, val_miss = get_leaf_value({"o": obj}, "o.missing")
    assert not found_miss and val_miss is None

    # _extract_model_types with None and type alias
    assert _extract_model_types(None) == []
    type MySubAlias = Sub
    assert _extract_model_types(MySubAlias) == [Sub]


def test_targeted_branch_coverage_edges() -> None:
    """Target specific branches to guarantee >=90% branch coverage on slots.py."""
    from blockstate.core.slots import (
        _detokenise_string,
        _patch_target_model_vaulted_validators,
        _sanitise_error_message,
        _UnsetType,
    )

    # 1. _UnsetType second instantiation and equality
    u2 = _UnsetType()
    assert u2 is UNSET
    assert u2 == UNSET
    assert UNSET != "other"

    # 2. get_schema_depth visited circular guard
    class CircModel(BaseModel):
        x: int

    assert get_schema_depth(CircModel, visited={CircModel}) == 1

    # 3. compute_required_leaf_paths exceeding max depth
    with pytest.raises(ConfigurationError):
        compute_required_leaf_paths(CircModel, current_depth=9, max_nesting_depth=8)

    # 4. _detokenise_string with vault_map and no vault
    s = _detokenise_string("Val <VAULT:A_01>", vault=None, vault_map={"<VAULT:A_01>": "plain"})
    assert s == "Val plain"
    # empty or no tokens
    assert _detokenise_string("", None, None) == ""
    assert _detokenise_string("No tokens", None, None) == "No tokens"

    # 5. _sanitise_error_message with PII spans
    san = _sanitise_error_message("Contact 07123456789", plaintext="", token="")
    assert "[REDACTED_PII]" in san

    # 6. Model with mode="before" validator
    class ModeBeforeModel(BaseModel):
        y: int

        @field_validator("y", mode="before")
        @classmethod
        def val_before(cls, v: Any) -> Any:
            return v

    SlotHydrator(ModeBeforeModel)

    # 7. Model without decorators
    class NoDecModel(BaseModel):
        z: int

    _patch_target_model_vaulted_validators(NoDecModel)

    # 8. Validators with plain inputs (not tokens) and UNSET in partial instances
    partial_info_cls = PartialSlotMetaclass.from_model(InfoVaultedModel)
    inst_unset: Any = partial_info_cls(nino=UNSET)
    assert inst_unset.nino is UNSET

    partial_plain_cls = PartialSlotMetaclass.from_model(TargetDirectPlainModel)
    inst_unset_plain: Any = partial_plain_cls(nino=UNSET)
    assert inst_unset_plain.nino is UNSET

    # 9. Plain input without token passed to validator
    inst_plain_val: Any = partial_info_cls(user_id="u1", nino="QQ123456C")
    assert inst_plain_val.nino == "QQ123456C"

    inst_plain_val2: Any = partial_plain_cls(nino="QQ123456C")
    assert inst_plain_val2.nino == "QQ123456C"

    # 10. Non-string exception raising in validator
    class ErrorVaultModel(BaseModel):
        flag: Vaulted[str]

        @field_validator("flag", mode="after")
        @classmethod
        def check_flag(cls, v: str) -> str:
            raise RuntimeError("Non-value error occurred")

    hydrator_err = SlotHydrator(ErrorVaultModel)
    res_err = hydrator_err.hydrate({"flag": "something"})
    assert len(res_err.validation_errors) == 1


class _StrategyDemoModel(BaseModel):
    a: int
    b: str


def test_stack_and_strategies_additional_coverage() -> None:
    """Verify TaskStack and testing strategies edge cases."""
    frame = TaskFrame(stage_id="stg")
    assert frame.partial_slots == {}
    frame.lock_slots(["x", "y"])
    assert frame.is_locked("x") and frame.is_locked("y")
    frame.set_slot("nested.key", 123, lock=True)
    assert frame.get_slot("nested.key") == 123
    assert frame.is_locked("nested.key")

    stack = TaskStack(max_stack_depth=5)
    assert stack.max_stack_depth == 5
    stack.push(frame)
    assert len(stack.frames) == 1
    assert list(stack) == [frame]
    assert "TaskStack" in repr(stack)


@given(
    v_tuple=st_vaulted_model(),
    c_comp=st_candidate_slots(_StrategyDemoModel, complete=True),
    c_incomp=st_candidate_slots(_StrategyDemoModel, complete=False),
)
@settings(max_examples=5, deadline=None)
def test_hypothesis_strategies_integration(
    v_tuple: tuple[type[BaseModel], dict[str, Any], dict[str, str]],
    c_comp: dict[str, Any],
    c_incomp: dict[str, Any],
) -> None:
    _v_model, v_cand, _v_map = v_tuple
    assert "nino" in v_cand
    assert "a" in c_comp or "a" in str(c_comp)
    assert isinstance(c_incomp, dict)
    unk_anno = get_leaf_annotation(_StrategyDemoModel, "nonexistent.child")
    assert unk_anno is not None


# =============================================================================
# 11. TaskFrame Overwrites, Progressive Hydration & Error Binding
# =============================================================================


def test_task_frame_update_slots_updates_and_locks() -> None:
    """Verify TaskFrame.update_slots updates and locks slots, enforcing boundaries."""
    frame = TaskFrame(stage_id="test_stage")

    # Update flat and nested slots with lock=True
    frame.update_slots({"user": {"name": "Alice", "city": "London"}, "active": True}, lock=True)
    assert frame.get_slot("user.name") == "Alice"
    assert frame.get_slot("user.city") == "London"
    assert frame.get_slot("active") is True

    # Both leaf keys and parent keys should be recognised as locked
    assert frame.is_locked("user.name")
    assert frame.is_locked("user.city")
    assert frame.is_locked("user")
    assert frame.is_locked("active")

    # Attempting to mutate locked child raises UnauthorisedMutationError
    with pytest.raises(UnauthorisedMutationError) as exc_info:
        frame.update_slots({"user.name": "Bob"})
    assert exc_info.value.code == "BLK-SEC-002"

    # Attempting to mutate locked parent raises UnauthorisedMutationError
    with pytest.raises(UnauthorisedMutationError) as exc_info:
        frame.update_slots({"user": {"name": "Charlie"}})
    assert exc_info.value.code == "BLK-SEC-002"

    # Attempting mutation via set_slot on parent or child also blocked
    with pytest.raises(UnauthorisedMutationError):
        frame.set_slot("user", {"name": "Dave"})
    with pytest.raises(UnauthorisedMutationError):
        frame.set_slot("user.name", "Dave")

    # Override allowed when force=True
    frame.update_slots({"user.name": "Eve"}, force=True)
    assert frame.get_slot("user.name") == "Eve"


def test_multi_turn_progressive_hydration_to_completion() -> None:
    """Verify multi-turn progressive hydration to completion with an active TaskFrame."""
    class Address(BaseModel):
        city: str
        postcode: str

    class Profile(BaseModel):
        full_name: str
        address: Address

    frame = TaskFrame(stage_id="stage_onboarding", target_model=Profile)
    hydrator = SlotHydrator(Profile)

    # Turn 1: provide top-level field full_name
    r1 = hydrator.hydrate({"full_name": "Dr John Watson"}, frame=frame)
    assert r1.delta == {"address.city", "address.postcode"}
    assert r1.target_model_instance is None
    assert frame.get_slot("full_name") == "Dr John Watson"
    assert frame.is_locked("full_name")

    # Turn 2: provide address.city via nested dictionary from previous turn
    r2 = hydrator.hydrate({"address": {"city": "London"}}, frame=frame)
    assert r2.delta == {"address.postcode"}
    assert r2.target_model_instance is None
    assert frame.get_slot("address.city") == "London"
    assert frame.is_locked("address.city")

    # Turn 3: provide remaining address.postcode via dot-notation
    r3 = hydrator.hydrate({"address.postcode": "NW1 6XE"}, frame=frame)
    assert r3.delta == set()
    assert r3.target_model_instance is not None
    assert isinstance(r3.target_model_instance, Profile)
    assert r3.target_model_instance.full_name == "Dr John Watson"
    assert r3.target_model_instance.address.city == "London"
    assert r3.target_model_instance.address.postcode == "NW1 6XE"


def test_field_validation_error_from_pydantic_error_binds_stage_id_from_task_frame() -> None:
    """Verify FieldValidationError.from_pydantic_error binds stage_id from TaskFrame."""
    from pydantic import ValidationError

    class StrictPerson(BaseModel):
        age: int

    frame = TaskFrame(stage_id="stage_kyc")
    try:
        StrictPerson(age="not-an-integer")  # type: ignore[arg-type]
    except ValidationError as exc:
        err = FieldValidationError.from_pydantic_error(exc, frame=frame)
        assert err.stage == "stage_kyc"
        assert err.stage_id == "stage_kyc"
        assert "stage=stage_kyc" in str(err)

        # Also verify explicit stage_id keyword
        err2 = FieldValidationError.from_pydantic_error(exc, stage_id="custom_stage")
        assert err2.stage == "custom_stage"
        assert err2.stage_id == "custom_stage"


def test_partial_slot_metaclass_preserves_constraints_and_default_factory() -> None:
    """Verify PartialSlotMetaclass preserves field constraints, metadata, and default_factory."""
    from pydantic import Field

    class SchemaWithMeta(BaseModel):
        score: int = Field(..., ge=1, le=10, description="Rating score")
        tags: list[str] = Field(default_factory=list, description="Tags list")

    partial_cls = PartialSlotMetaclass.from_model(SchemaWithMeta)
    assert partial_cls.model_fields["score"].description == "Rating score"
    assert partial_cls.model_fields["tags"].default_factory is list
    assert any(hasattr(m, "ge") for m in partial_cls.model_fields["score"].metadata)

    instance: Any = partial_cls()
    assert is_unset(instance.score)
    assert instance.tags == []


def test_target_model_instantiation_failure_is_sanitised() -> None:
    """Verify target_model instantiation failure at delta=empty is caught and sanitised."""
    from pydantic import model_validator

    class CrossValidated(BaseModel):
        x: int
        y: int

        @model_validator(mode="after")
        def validate_total(self) -> "CrossValidated":
            if self.x + self.y > 100:
                raise ValueError("Total cannot exceed 100")
            return self

    hydrator = SlotHydrator(CrossValidated)
    res = hydrator.hydrate({"x": 60, "y": 60})
    assert res.delta == set()
    assert res.target_model_instance is None
    assert len(res.validation_errors) == 1
    assert "Total cannot exceed 100" in res.validation_errors[0].message


def test_breach_delta_includes_unset_fields() -> None:
    """Verify delta calculation on DisqualifyingBreachError includes UNSET fields."""
    class TwoFieldModel(BaseModel):
        first: str
        second: str

        @field_validator("second", mode="after")
        @classmethod
        def check_disqualification(cls, v: str) -> str:
            if v == "disqualified":
                raise DisqualifyingBreachError("Candidate is disqualified", field_name="second")
            return v

    hydrator = SlotHydrator(TwoFieldModel)
    frame = TaskFrame(stage_id="stage_eval", target_model=TwoFieldModel)

    # First is hydrated
    r1 = hydrator.hydrate({"first": "valid_first"}, frame=frame)
    assert r1.delta == {"second"}

    # Second triggers breach
    r2 = hydrator.hydrate({"second": "disqualified"}, frame=frame)
    assert r2.is_breach is True
    # 'second' must remain in delta because it is unset/unhydrated
    assert "second" in r2.delta


# =============================================================================
# 12. Hypothesis Property Fuzzing Suite (>= 500 Examples)
# =============================================================================


@settings(max_examples=200, deadline=None)
@given(model_cls=st_nested_model(min_depth=1, max_depth=3))
def test_hypothesis_partial_model_instantiation(model_cls: type[BaseModel]) -> None:
    """Property Fuzzing: PartialSlotMetaclass synthesises valid partial models for any schema."""
    partial_cls = PartialSlotMetaclass.from_model(model_cls)
    assert issubclass(partial_cls, PartialSlotModel)

    # Empty instantiation defaults all required fields to UNSET
    instance = partial_cls()
    req_paths = compute_required_leaf_paths(model_cls)
    for p in req_paths:
        val = getattr(instance, p.split(".")[0])
        assert val is not None


@settings(max_examples=500, deadline=None)
@given(model_cls=st_nested_model(min_depth=1, max_depth=3), data=st.data())
def test_hypothesis_delta_invariant_and_strict_model_instantiation(
    model_cls: type[BaseModel],
    data: st.DataObject,
) -> None:
    """Property Fuzzing: Delta = RequiredLeafPaths \\ HydratedLeafPaths invariant always holds."""
    hydrator = SlotHydrator(model_cls)
    candidate = data.draw(st_candidate_slots(model_cls))

    res = hydrator.hydrate(candidate)
    req_paths = set(hydrator.required_leaf_paths)
    hydrated_paths = {p for p in req_paths if get_leaf_value(res.hydrated_slots, p)[0]}

    # Delta definition invariant
    expected_delta = req_paths - hydrated_paths
    assert res.delta == expected_delta

    # Target model is instantiated if and only if delta is empty and no errors
    if len(res.delta) == 0 and not res.validation_errors:
        assert res.target_model_instance is not None
        assert isinstance(res.target_model_instance, model_cls)
    else:
        assert res.target_model_instance is None


@settings(max_examples=150, deadline=None)
@given(model_cls=st_nested_model(min_depth=1, max_depth=3), data=st.data())
def test_hypothesis_locked_slots_protection(
    model_cls: type[BaseModel],
    data: st.DataObject,
) -> None:
    """Property Fuzzing: Once a leaf slot is locked, overwrites without authorisation fail."""
    hydrator = SlotHydrator(model_cls)
    candidate = data.draw(st_candidate_slots(model_cls))

    frame = TaskFrame(stage_id="fuzz_stage", target_model=model_cls)
    res = hydrator.hydrate(candidate, frame=frame)

    if res.locked_slots:
        # Pick one locked slot and attempt overwrite
        locked_key = next(iter(res.locked_slots))
        with pytest.raises(UnauthorisedMutationError) as exc_info:
            hydrator.hydrate({locked_key: "MUTATED_VALUE"}, frame=frame, allow_overrides=False)
        assert exc_info.value.code == "BLK-SEC-002"
