"""Recursive PartialSlotModel metaclass, leaf-path Delta-Hydration, and Vaulted[T] isolation.

Provides progressive Pydantic v2 slot collection, UNSET sentinels, schema depth validation
up to max_nesting_depth=8, in-memory zero-persistence Vaulted[T] validator detokenisation,
locked leaf-path protection, and deterministic delta computation.
"""

import contextlib
import contextvars
import copy
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import (
    Annotated,
    Any,
    Final,
    get_args,
    get_origin,
)

from pydantic import BaseModel, create_model, field_validator
from pydantic._internal._decorators import inspect_validator
from pydantic._internal._model_construction import ModelMetaclass

from blockstate.core.stack import TaskFrame
from blockstate.errors import (
    ConfigurationError,
    DisqualifyingBreachError,
    FieldValidationError,
    UnauthorisedMutationError,
)
from blockstate.security.annotations import is_vaulted
from blockstate.security.pii_patterns import VAULT_TOKEN_PATTERN, detect_pii_spans
from blockstate.security.vault import PIIVault


class _UnsetType:
    """Sentinel singleton representing uncollected or unhydrated slot fields."""

    _instance: "_UnsetType | None" = None

    def __new__(cls) -> "_UnsetType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNSET"

    def __str__(self) -> str:
        return "UNSET"

    def __bool__(self) -> bool:
        return False

    def __copy__(self) -> "_UnsetType":
        return self

    def __deepcopy__(self, memo: Any) -> "_UnsetType":
        return self

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _UnsetType)

    def __hash__(self) -> int:
        return hash("UNSET_SINGLETON")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: Any
    ) -> Any:
        from pydantic_core import core_schema

        return core_schema.is_instance_schema(cls)


UNSET: Final[_UnsetType] = _UnsetType()


def is_unset(value: object) -> bool:
    """Check whether a given value is the UNSET sentinel."""
    return value is UNSET or isinstance(value, _UnsetType)


# Context variable holding active vault detokenisation context during validator execution
_active_vault_context: contextvars.ContextVar[tuple[PIIVault | None, Mapping[str, str] | None]] = (
    contextvars.ContextVar("active_vault_context", default=(None, None))
)


@contextlib.contextmanager
def active_vault_context(
    vault: PIIVault | None = None,
    vault_map: Mapping[str, str] | None = None,
) -> Iterator[None]:
    """Scoped context manager binding an ephemeral vault and token map for detokenisation."""
    token = _active_vault_context.set((vault, vault_map))
    try:
        yield
    finally:
        _active_vault_context.reset(token)


def _extract_model_types(annotation: Any) -> list[type[BaseModel]]:
    """Extract nested BaseModel types from a type annotation."""
    if annotation is None:
        return []
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]

    origin = get_origin(annotation)
    if origin is not None:
        models: list[type[BaseModel]] = []
        for arg in get_args(annotation):
            models.extend(_extract_model_types(arg))
        return models

    if hasattr(annotation, "__value__"):
        return _extract_model_types(annotation.__value__)

    return []


def get_schema_depth(
    model_cls: type[BaseModel],
    *,
    max_nesting_depth: int = 8,
    current_depth: int = 1,
    visited: set[type[BaseModel]] | None = None,
) -> int:
    """Recursively compute model nesting depth and enforce max_nesting_depth limit.

    Raises ConfigurationError (BLK-CFG-002) if schema nesting depth exceeds max_nesting_depth.
    """
    if current_depth > max_nesting_depth:
        raise ConfigurationError(
            f"Model '{model_cls.__name__}' schema nesting depth ({current_depth}) "
            f"exceeds max_nesting_depth={max_nesting_depth}",
            code="BLK-CFG-002",
            model_name=model_cls.__name__,
            depth=current_depth,
            max_nesting_depth=max_nesting_depth,
        )

    if visited is None:
        visited = set()
    if model_cls in visited:
        return current_depth

    visited.add(model_cls)
    max_child_depth = current_depth

    for field_info in model_cls.model_fields.values():
        child_models = _extract_model_types(field_info.annotation)
        for child in child_models:
            child_depth = get_schema_depth(
                child,
                max_nesting_depth=max_nesting_depth,
                current_depth=current_depth + 1,
                visited=visited.copy(),
            )
            if child_depth > max_child_depth:
                max_child_depth = child_depth

    return max_child_depth


def compute_required_leaf_paths(
    model_cls: type[BaseModel],
    prefix: str = "",
    *,
    max_nesting_depth: int = 8,
    current_depth: int = 1,
) -> list[str]:
    """Compute dot-separated leaf paths for all required fields in declaration order."""
    if current_depth > max_nesting_depth:
        raise ConfigurationError(
            f"Model '{model_cls.__name__}' schema nesting depth exceeds "
            f"max_nesting_depth={max_nesting_depth}",
            code="BLK-CFG-002",
        )

    paths: list[str] = []
    for name, field_info in model_cls.model_fields.items():
        field_path = f"{prefix}{name}"
        annotation = field_info.annotation
        child_models = _extract_model_types(annotation)

        if child_models:
            # Composite nested model
            child_cls = child_models[0]
            if field_info.is_required():
                child_paths = compute_required_leaf_paths(
                    child_cls,
                    prefix=f"{field_path}.",
                    max_nesting_depth=max_nesting_depth,
                    current_depth=current_depth + 1,
                )
                paths.extend(child_paths)
        else:
            # Primitive leaf field
            if field_info.is_required():
                paths.append(field_path)

    return paths


def get_leaf_value(data: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    """Retrieve a leaf value from a flat or nested dictionary.

    Returns (True, value) if the path exists, or (False, None) if absent.
    """
    if path in data:
        return True, data[path]

    parts = path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return False, None
    return True, current


def unflatten_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    """Convert dot-separated flat slot paths into a structured nested dictionary.

    Excludes UNSET sentinel values.
    """
    result: dict[str, Any] = {}
    for key, value in data.items():
        if is_unset(value):
            continue
        parts = key.split(".")
        current = result
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        last = parts[-1]
        if isinstance(value, Mapping) and not isinstance(value, BaseModel):
            nested = unflatten_dict(value)
            if last in current and isinstance(current[last], dict):
                current[last].update(nested)
            else:
                curr_last = current.get(last)
                if isinstance(curr_last, dict):
                    curr_last.update(nested)
                else:
                    current[last] = nested
        elif isinstance(value, BaseModel):
            current[last] = value.model_dump()
        else:
            current[last] = value
    return result


def flatten_dict(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dictionary into dot-separated paths."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        full_key = f"{prefix}{key}"
        if isinstance(value, Mapping) and not isinstance(value, BaseModel):
            result.update(flatten_dict(value, prefix=f"{full_key}."))
        elif isinstance(value, BaseModel):
            result.update(flatten_dict(value.model_dump(), prefix=f"{full_key}."))
        else:
            result[full_key] = value
    return result


def _detokenise_string(
    text: str,
    vault: PIIVault | None,
    vault_map: Mapping[str, str] | None,
) -> str:
    """Detokenise any <VAULT:CATEGORY_NN> tokens in text using available vault resources."""
    if not text or not VAULT_TOKEN_PATTERN.search(text):
        return text

    if vault is not None:
        return vault.detokenise(text, vault_map=vault_map)
    if vault_map is not None:
        for tok, plaintext in vault_map.items():
            text = text.replace(tok, plaintext)
    return text


def _sanitise_error_message(msg: str, plaintext: str, token: str) -> str:
    """Ensure raw plaintext or PII never leaks into validation error messages."""
    if plaintext and plaintext in msg:
        msg = msg.replace(plaintext, token)

    spans = detect_pii_spans(msg)
    if spans:
        chars = list(msg)
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            chars[span.start : span.end] = list("[REDACTED_PII]")
        msg = "".join(chars)
    return msg


def wrap_detokenising_validator(
    orig_func: Any,
    *,
    is_field_vaulted: bool,
    takes_info: bool,
) -> Any:
    """Wrap a Pydantic field validator to support UNSET and isolated Vaulted[T] detokenisation."""
    if takes_info:

        def validator_with_info(cls: Any, v: Any, info: Any) -> Any:
            if is_unset(v):
                return UNSET

            token = v
            v_to_validate = v
            active_vault, active_map = _active_vault_context.get()

            # Perform isolated in-memory detokenisation for Vaulted fields or tokens
            if isinstance(v, str) and (is_field_vaulted or VAULT_TOKEN_PATTERN.search(v)):
                v_to_validate = _detokenise_string(v, active_vault, active_map)

            try:
                res = orig_func(v_to_validate, info)
            except DisqualifyingBreachError:
                raise
            except Exception as exc:
                if isinstance(v, str) and v_to_validate != token:
                    sanitised_msg = _sanitise_error_message(str(exc), str(v_to_validate), token)
                    raise type(exc)(sanitised_msg) from None
                raise

            # Immediately re-bind original token
            if isinstance(v, str) and token != v_to_validate:
                return token
            return res

        return validator_with_info

    else:

        def validator_plain(cls: Any, v: Any) -> Any:
            if is_unset(v):
                return UNSET

            token = v
            v_to_validate = v
            active_vault, active_map = _active_vault_context.get()

            if isinstance(v, str) and (is_field_vaulted or VAULT_TOKEN_PATTERN.search(v)):
                v_to_validate = _detokenise_string(v, active_vault, active_map)

            try:
                res = orig_func(v_to_validate)
            except DisqualifyingBreachError:
                raise
            except Exception as exc:
                if isinstance(v, str) and v_to_validate != token:
                    sanitised_msg = _sanitise_error_message(str(exc), str(v_to_validate), token)
                    raise type(exc)(sanitised_msg) from None
                raise

            if isinstance(v, str) and token != v_to_validate:
                return token
            return res

        return validator_plain


def _patch_target_model_vaulted_validators(model_cls: type[BaseModel]) -> None:
    """Ensure target model validators also perform in-memory Vaulted[T] detokenisation."""
    decorators = getattr(model_cls, "__pydantic_decorators__", None)
    if not decorators:
        return

    modified = False
    for dec in decorators.field_validators.values():
        any_vaulted = False
        for f in dec.info.fields:
            finfo = model_cls.model_fields.get(f)
            if finfo and is_vaulted(finfo.annotation):
                any_vaulted = True
                break

        if any_vaulted and not getattr(dec.func, "_is_blockstate_wrapped", False):
            orig_func = dec.func
            takes_info = inspect_validator(orig_func, mode="after", type="field")

            if takes_info:

                def make_wrapper_info(fn: Any) -> Any:
                    def wrapped(v: Any, info: Any) -> Any:
                        token = v
                        v_to_validate = v
                        active_vault, active_map = _active_vault_context.get()
                        if isinstance(v, str):
                            v_to_validate = _detokenise_string(v, active_vault, active_map)
                        try:
                            res = fn(v_to_validate, info)
                        except DisqualifyingBreachError:
                            raise
                        except Exception as exc:
                            if isinstance(v, str) and v_to_validate != token:
                                sanitised = _sanitise_error_message(
                                    str(exc), str(v_to_validate), token
                                )
                                raise type(exc)(sanitised) from None
                            raise
                        if isinstance(v, str) and token != v_to_validate:
                            return token
                        return res

                    wrapped._is_blockstate_wrapped = True  # type: ignore[attr-defined]
                    return wrapped

                dec.func = make_wrapper_info(orig_func)
            else:

                def make_wrapper_plain(fn: Any) -> Any:
                    def wrapped(v: Any) -> Any:
                        token = v
                        v_to_validate = v
                        active_vault, active_map = _active_vault_context.get()
                        if isinstance(v, str):
                            v_to_validate = _detokenise_string(v, active_vault, active_map)
                        try:
                            res = fn(v_to_validate)
                        except DisqualifyingBreachError:
                            raise
                        except Exception as exc:
                            if isinstance(v, str) and v_to_validate != token:
                                sanitised = _sanitise_error_message(
                                    str(exc), str(v_to_validate), token
                                )
                                raise type(exc)(sanitised) from None
                            raise
                        if isinstance(v, str) and token != v_to_validate:
                            return token
                        return res

                    wrapped._is_blockstate_wrapped = True  # type: ignore[attr-defined]
                    return wrapped

                dec.func = make_wrapper_plain(orig_func)

            modified = True

    if modified:
        model_cls.model_rebuild(force=True)


# Cache for generated partial models
_partial_model_cache: dict[tuple[type[BaseModel], int], type[BaseModel]] = {}


class PartialSlotMetaclass(ModelMetaclass):
    """Metaclass that transforms strict schemas into recursive partial slot models.

    Defaults unsupplied required fields to UNSET sentinel while preserving all
    field constraints, regex patterns, and field-level validators up to max_nesting_depth=8.
    """

    def __new__(
        mcs,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, Any],
        **kwargs: Any,
    ) -> type:
        target_model = kwargs.pop("target_model", None)
        max_nesting_depth = kwargs.pop("max_nesting_depth", 8)
        cls = super().__new__(mcs, name, bases, namespace, **kwargs)

        if (
            target_model is not None
            and isinstance(target_model, type)
            and issubclass(target_model, BaseModel)
        ):
            return mcs.from_model(target_model, max_nesting_depth=max_nesting_depth)
        return cls

    @classmethod
    def from_model(
        mcs,
        target_model: type[BaseModel],
        max_nesting_depth: int = 8,
    ) -> type[BaseModel]:
        """Synthesise a recursive partial slot model from a strict target model.

        Enforces max_nesting_depth=8; raises ConfigurationError (BLK-CFG-002) if exceeded.
        """
        cache_key = (target_model, max_nesting_depth)
        if cache_key in _partial_model_cache:
            return _partial_model_cache[cache_key]

        # Enforce max nesting depth limit
        get_schema_depth(target_model, max_nesting_depth=max_nesting_depth)

        # Ensure target model validators also handle detokenisation
        _patch_target_model_vaulted_validators(target_model)

        fields: dict[str, Any] = {}
        validators: dict[str, Any] = {}

        for field_name, field_info in target_model.model_fields.items():
            orig_annotation = field_info.annotation
            child_models = _extract_model_types(orig_annotation)
            meta = field_info.metadata
            new_info = copy.copy(field_info)

            if child_models:
                # Recursively transform child model
                child_target = child_models[0]
                child_partial = mcs.from_model(
                    child_target,
                    max_nesting_depth=max_nesting_depth,
                )
                constrained_child = Annotated[child_partial, *meta] if meta else child_partial
                if field_info.is_required():
                    new_info.default = UNSET
                    new_info.default_factory = None
                    new_info.metadata = []
                    fields[field_name] = (constrained_child | _UnsetType, new_info)
                else:
                    new_info.metadata = []
                    fields[field_name] = (constrained_child | _UnsetType | None, new_info)
            else:
                constrained_base = Annotated[orig_annotation, *meta] if meta else orig_annotation
                if field_info.is_required():
                    new_info.default = UNSET
                    new_info.default_factory = None
                    new_info.metadata = []
                    fields[field_name] = (constrained_base | _UnsetType, new_info)
                else:
                    new_info.metadata = []
                    fields[field_name] = (constrained_base | _UnsetType, new_info)

        # Transfer and wrap field validators
        decorators = getattr(target_model, "__pydantic_decorators__", None)
        if decorators:
            for val_name, dec in decorators.field_validators.items():
                if dec.info.mode != "after":
                    continue

                any_vaulted = False
                for f in dec.info.fields:
                    finfo = target_model.model_fields.get(f)
                    if finfo and is_vaulted(finfo.annotation):
                        any_vaulted = True
                        break

                takes_info = inspect_validator(dec.func, mode="after", type="field")
                wrapped = wrap_detokenising_validator(
                    dec.func,
                    is_field_vaulted=any_vaulted,
                    takes_info=takes_info,
                )
                validators[val_name] = field_validator(*dec.info.fields, mode="after")(wrapped)

        partial_cls = create_model(
            f"Partial{target_model.__name__}",
            __base__=PartialSlotModel,
            __validators__=validators,
            **fields,
        )

        for fname, finfo in target_model.model_fields.items():
            if finfo.metadata:
                partial_cls.model_fields[fname].metadata = list(finfo.metadata)

        _partial_model_cache[cache_key] = partial_cls
        return partial_cls


class PartialSlotModel(BaseModel, metaclass=PartialSlotMetaclass):
    """Base model for partial slot collection schemas."""

    @classmethod
    def from_model(
        cls,
        target_model: type[BaseModel],
        max_nesting_depth: int = 8,
    ) -> type[BaseModel]:
        """Synthesise a recursive partial slot model for a given target model."""
        return PartialSlotMetaclass.from_model(target_model, max_nesting_depth=max_nesting_depth)


@dataclass(frozen=True)
class HydrationResult:
    """Outcome of a slot hydration evaluation pass."""

    delta: set[str]
    hydrated_slots: dict[str, Any]
    locked_slots: set[str]
    target_model_instance: BaseModel | None = None
    validation_errors: list[FieldValidationError] = field(default_factory=list)
    is_breach: bool = False
    breach_error: DisqualifyingBreachError | None = None

    @property
    def model_instance(self) -> BaseModel | None:
        """Alias for target_model_instance."""
        return self.target_model_instance

    @property
    def is_complete(self) -> bool:
        """Check whether all required slots are collected with zero errors or breaches."""
        return len(self.delta) == 0 and not self.validation_errors and not self.is_breach


class SlotHydrator:
    """Progressive schema hydration engine.

    Computes leaf-path delta, enforces locked leaf-path immutability,
    detokenises Vaulted[T] fields in-memory during validator execution,
    captures sanitised FieldValidationErrors, signals early on_breach routing,
    and instantiates the strict TargetModel strictly when Delta is empty.
    """

    def __init__(
        self,
        target_model: type[BaseModel],
        *,
        vault: PIIVault | None = None,
        vault_map: Mapping[str, str] | None = None,
        max_nesting_depth: int = 8,
    ) -> None:
        self.target_model = target_model
        self.vault = vault
        self.vault_map = dict(vault_map) if vault_map is not None else None
        self.max_nesting_depth = max_nesting_depth

        # Enforce max nesting depth limit at construction time
        get_schema_depth(target_model, max_nesting_depth=max_nesting_depth)

        # Pre-synthesise companion partial model
        self.partial_model = PartialSlotMetaclass.from_model(
            target_model,
            max_nesting_depth=max_nesting_depth,
        )

        # Pre-compute required leaf paths in deterministic declaration order
        self.required_leaf_paths = compute_required_leaf_paths(
            target_model,
            max_nesting_depth=max_nesting_depth,
        )

    def hydrate(
        self,
        candidate_slots: Mapping[str, Any] | TaskFrame,
        second_arg: Mapping[str, Any] | TaskFrame | None = None,
        *,
        frame: TaskFrame | None = None,
        existing_slots: Mapping[str, Any] | None = None,
        locked_slots: set[str] | None = None,
        vault: PIIVault | None = None,
        vault_map: Mapping[str, str] | None = None,
        allow_overrides: bool = False,
    ) -> HydrationResult:
        """Evaluate candidate slots, update locks, compute Delta, and return HydrationResult.

        Raises UnauthorisedMutationError (BLK-SEC-002) if an unpermitted overwrite
        of a locked slot is attempted.
        """
        # Resolve positional flexibility: hydrate(frame, candidate) or hydrate(candidate, frame)
        resolved_frame = frame
        resolved_candidates: Mapping[str, Any]

        if isinstance(candidate_slots, TaskFrame):
            resolved_frame = candidate_slots
            resolved_candidates = second_arg if isinstance(second_arg, Mapping) else {}
        else:
            resolved_candidates = candidate_slots
            if isinstance(second_arg, TaskFrame):
                resolved_frame = second_arg

        effective_vault = vault if vault is not None else self.vault
        if vault_map is not None:
            effective_map: dict[str, str] | None = dict(vault_map)
        elif self.vault_map is not None:
            effective_map = dict(self.vault_map)
        else:
            effective_map = None

        if resolved_frame is not None:
            hydrated = flatten_dict(resolved_frame.slots)
            current_locked = set(resolved_frame.locked_slots)
            overrides_allowed = allow_overrides or resolved_frame.allow_slot_overrides
        else:
            hydrated = flatten_dict(existing_slots or {})
            current_locked = set(locked_slots or set())
            overrides_allowed = allow_overrides

        flattened_candidates = flatten_dict(resolved_candidates)

        # 1. Enforce locked-slot immutability
        if not overrides_allowed:
            for leaf_path in flattened_candidates:
                if leaf_path in current_locked:
                    stage_id = resolved_frame.stage_id if resolved_frame else None
                    msg = (
                        f"Cannot overwrite locked slot '{leaf_path}' without explicit authorisation"
                    )
                    raise UnauthorisedMutationError(
                        msg,
                        code="BLK-SEC-002",
                        stage=stage_id,
                        field_path=leaf_path,
                    )

        # 2. Validate candidate fields individually to isolate errors from valid siblings
        validation_errors: list[FieldValidationError] = []
        is_breach = False
        breach_error: DisqualifyingBreachError | None = None
        newly_valid_leaves: dict[str, Any] = {}

        with active_vault_context(effective_vault, effective_map):
            for leaf_path, raw_value in flattened_candidates.items():
                if is_unset(raw_value):
                    continue

                single_candidate = unflatten_dict({leaf_path: raw_value})
                try:
                    self.partial_model(**single_candidate)
                    newly_valid_leaves[leaf_path] = raw_value
                except DisqualifyingBreachError as breach:
                    is_breach = True
                    breach_error = breach
                    break
                except Exception as exc:
                    stage_id = resolved_frame.stage_id if resolved_frame else None
                    error_record = FieldValidationError.from_pydantic_error(
                        exc,
                        field_path=leaf_path,
                        stage=stage_id,
                    )
                    validation_errors.append(error_record)

        if is_breach:
            # Breach halts slot collection immediately
            current_delta: set[str] = set()
            for p in self.required_leaf_paths:
                found, val = get_leaf_value(hydrated, p)
                if not found or is_unset(val):
                    current_delta.add(p)
            return HydrationResult(
                delta=current_delta,
                hydrated_slots=hydrated,
                locked_slots=current_locked,
                target_model_instance=None,
                validation_errors=validation_errors,
                is_breach=True,
                breach_error=breach_error,
            )

        # 3. Persist and lock valid leaf paths
        for valid_path, valid_val in newly_valid_leaves.items():
            hydrated[valid_path] = valid_val
            current_locked.add(valid_path)
            if resolved_frame is not None:
                resolved_frame.set_slot(valid_path, valid_val, lock=True, force=True)

        # 4. Compute Delta = RequiredLeafPaths \ HydratedLeafPaths
        hydrated_leaf_paths: set[str] = set()
        for req_path in self.required_leaf_paths:
            found, val = get_leaf_value(hydrated, req_path)
            if found and not is_unset(val):
                hydrated_leaf_paths.add(req_path)

        delta = {p for p in self.required_leaf_paths if p not in hydrated_leaf_paths}

        # 5. Instantiate strict TargetModel if and only if Delta is empty and zero validation errors
        target_model_instance: BaseModel | None = None
        if len(delta) == 0 and not validation_errors:
            unflattened = unflatten_dict(hydrated)
            with active_vault_context(effective_vault, effective_map):
                try:
                    target_model_instance = self.target_model(**unflattened)
                except Exception as exc:
                    stage_id = resolved_frame.stage_id if resolved_frame else None
                    error_record = FieldValidationError.from_pydantic_error(
                        exc,
                        field_path="",
                        stage=stage_id,
                    )
                    validation_errors.append(error_record)
                    target_model_instance = None

        return HydrationResult(
            delta=delta,
            hydrated_slots=hydrated,
            locked_slots=current_locked,
            target_model_instance=target_model_instance,
            validation_errors=validation_errors,
            is_breach=False,
            breach_error=None,
        )


__all__: list[str] = [
    "UNSET",
    "HydrationResult",
    "PartialSlotMetaclass",
    "PartialSlotModel",
    "SlotHydrator",
    "active_vault_context",
    "compute_required_leaf_paths",
    "flatten_dict",
    "get_leaf_value",
    "get_schema_depth",
    "is_unset",
    "unflatten_dict",
    "wrap_detokenising_validator",
]
