"""Hypothesis strategies for recursive schemas, partial inputs, and property fuzzing.

Provides reusable property fuzzing generators for dynamic Pydantic v2 models,
arbitrary nesting depths up to max_nesting_depth=8, partial slot candidate payloads,
and Vaulted[T] tokenised structures.
"""

from typing import Any

from hypothesis import strategies as st
from pydantic import BaseModel, create_model

from blockstate.core.slots import (
    _extract_model_types,
    compute_required_leaf_paths,
    unflatten_dict,
)
from blockstate.security.annotations import Vaulted

FIELD_NAMES_POOL: list[str] = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    "zeta",
    "eta",
    "theta",
    "postcode",
    "city",
    "amount",
    "status",
]


def get_leaf_annotation(model_cls: type[BaseModel], path: str) -> Any:
    """Resolve the leaf type annotation for a given dot-separated path."""
    parts = path.split(".")
    current: Any = model_cls
    for part in parts[:-1]:
        if part not in current.model_fields:
            return Any
        field_info = current.model_fields[part]
        child_models = _extract_model_types(field_info.annotation)
        if not child_models:
            return Any
        current = child_models[0]
    if parts[-1] not in current.model_fields:
        return Any
    return current.model_fields[parts[-1]].annotation


@st.composite
def st_leaf_value(draw: st.DrawFn, annotation: Any) -> Any:
    """Generate a valid candidate value for a specified leaf field annotation."""
    if annotation is int:
        return draw(st.integers(min_value=-1000, max_value=1000))
    if annotation is str:
        return draw(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)
        )
    if annotation is bool:
        return draw(st.booleans())
    if annotation is float:
        return draw(
            st.floats(
                min_value=-1000.0,
                max_value=1000.0,
                allow_nan=False,
                allow_infinity=False,
            )
        )
    return draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8))


@st.composite
def st_primitive_model(
    draw: st.DrawFn,
    *,
    prefix: str = "LeafModel",
    min_fields: int = 1,
    max_fields: int = 3,
) -> type[BaseModel]:
    """Generate a single-level Pydantic BaseModel with randomised primitive fields."""
    num_fields = draw(st.integers(min_value=min_fields, max_value=max_fields))
    selected_names = draw(
        st.lists(
            st.sampled_from(FIELD_NAMES_POOL),
            min_size=num_fields,
            max_size=num_fields,
            unique=True,
        )
    )
    field_defs: dict[str, Any] = {}
    for name in selected_names:
        field_type = draw(st.sampled_from([int, str, bool, float]))
        field_defs[name] = (field_type, ...)

    suffix = draw(st.integers(min_value=10000, max_value=99999))
    return create_model(f"{prefix}_{suffix}", **field_defs)


@st.composite
def st_nested_model(
    draw: st.DrawFn,
    *,
    min_depth: int = 1,
    max_depth: int = 4,
    prefix: str = "RootModel",
) -> type[BaseModel]:
    """Generate a nested Pydantic BaseModel with schema depth between min_depth and max_depth."""
    depth = draw(st.integers(min_value=min_depth, max_value=max_depth))
    current_model = draw(st_primitive_model(prefix=f"{prefix}Level1"))

    for d in range(2, depth + 1):
        field_defs: dict[str, Any] = {"child": (current_model, ...)}
        has_extra_primitive = draw(st.booleans())
        if has_extra_primitive:
            extra_type = draw(st.sampled_from([int, str, bool]))
            field_defs["extra_val"] = (extra_type, ...)

        suffix = draw(st.integers(min_value=10000, max_value=99999))
        current_model = create_model(f"{prefix}Level{d}_{suffix}", **field_defs)

    return current_model


@st.composite
def st_candidate_slots(
    draw: st.DrawFn,
    model_cls: type[BaseModel],
    *,
    complete: bool | None = None,
) -> dict[str, Any]:
    """Generate valid candidate slot mappings (flat or nested, complete or partial)."""
    leaf_paths = compute_required_leaf_paths(model_cls)
    if not leaf_paths:
        return {}

    if complete is True:
        chosen_paths = leaf_paths
    elif complete is False:
        if len(leaf_paths) > 1:
            num_to_pick = draw(st.integers(min_value=1, max_value=len(leaf_paths) - 1))
            chosen_paths = draw(
                st.lists(
                    st.sampled_from(leaf_paths),
                    min_size=num_to_pick,
                    max_size=num_to_pick,
                    unique=True,
                )
            )
        else:
            chosen_paths = []
    else:
        num_to_pick = draw(st.integers(min_value=1, max_value=len(leaf_paths)))
        chosen_paths = draw(
            st.lists(
                st.sampled_from(leaf_paths),
                min_size=num_to_pick,
                max_size=num_to_pick,
                unique=True,
            )
        )

    flat_data: dict[str, Any] = {}
    for path in chosen_paths:
        annotation = get_leaf_annotation(model_cls, path)
        flat_data[path] = draw(st_leaf_value(annotation))

    as_nested = draw(st.booleans())
    if as_nested:
        return unflatten_dict(flat_data)
    return flat_data


@st.composite
def st_vaulted_model(
    draw: st.DrawFn,
    *,
    prefix: str = "VaultedModel",
) -> tuple[type[BaseModel], dict[str, str], dict[str, str]]:
    """Generate a model containing a Vaulted[str] field, alongside matching tokens and vault map."""
    suffix = draw(st.integers(min_value=10000, max_value=99999))
    model_cls = create_model(
        f"{prefix}_{suffix}",
        user_id=(str, ...),
        nino=(Vaulted[str], ...),
    )
    token = f"<VAULT:NINO_{draw(st.integers(min_value=1, max_value=99)):02d}>"
    plaintext = f"QQ{draw(st.integers(min_value=100000, max_value=999999))}A"
    vault_map = {token: plaintext}
    candidate_slots = {
        "user_id": draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=3, max_size=8)),
        "nino": token,
    }
    return model_cls, candidate_slots, vault_map


__all__: list[str] = [
    "FIELD_NAMES_POOL",
    "get_leaf_annotation",
    "st_candidate_slots",
    "st_leaf_value",
    "st_nested_model",
    "st_primitive_model",
    "st_vaulted_model",
]
