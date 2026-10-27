"""Declarative transition primitives, choice payloads, and mutation commands.

Defines the core transition control objects returned by stage guards and
statechart evaluation steps, including Transition[T], ChoicePayload,
SlotMutation, SlotDelta, and VaultDelta.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from blockstate.errors import ConfigurationError

FnT = TypeVar("FnT")


@dataclass(frozen=True, slots=True)
class SlotMutation:
    """Typed mutation command for explicitly updating parent TaskFrame slots.

    Used when a child digression frame resolves and returns validated values
    back to the parent frame under allow_slot_overrides=True authorisation.
    """

    updates: Mapping[str, Any]
    force: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SlotDelta:
    """Delta calculation summary of required versus hydrated leaf paths."""

    missing: tuple[str, ...] = ()
    hydrated: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_complete(self) -> bool:
        """Return True if all required leaf paths are hydrated."""
        return len(self.missing) == 0


@dataclass(frozen=True, slots=True)
class VaultDelta:
    """Session vault delta tracking newly allocated HMAC-SHA256 tokens."""

    new_tokens: Mapping[str, str] = field(default_factory=dict)


class Transition[T]:
    """Pure declarative stage transition directive and DCG decorator.

    Can be used as:
    1. A decorator declaring static transition targets: @Transition(targets=[...])
    2. A return value from stage guards: Transition.to(...), Transition.stay(), etc.
    3. A type annotation: Transition[TargetStage]
    """

    def __init__(
        self,
        targets: Sequence[str] | str | None = None,
        *,
        target: str | None = None,
        is_stay: bool = False,
        is_pop: bool = False,
        is_end: bool = False,
        mutation: SlotMutation | None = None,
        result: Any = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.target = target
        self.is_stay = is_stay
        self.is_pop = is_pop
        self.is_end = is_end
        self.mutation = mutation
        self.result = result
        self.metadata = metadata or {}

        # If targets provided, this instance can act as a decorator
        resolved_targets: tuple[str, ...] = ()
        if targets is not None:
            resolved_targets = (targets,) if isinstance(targets, str) else tuple(targets)
            for t in resolved_targets:
                if not t or not isinstance(t, str):
                    raise ConfigurationError(
                        f"Transition destination must be a non-empty string identifier: {t!r}",
                        code="BLK-CFG-002",
                    )
        self.declared_targets = resolved_targets

    def __call__(self, fn: FnT) -> FnT:
        """Apply transition target declarations to a stage handler or guard."""
        setattr(fn, "_blockstate_targets", self.declared_targets)  # noqa: B010
        return fn

    @classmethod
    def to(cls, target: str, **metadata: Any) -> "Transition[Any]":
        """Construct a transition routing to a declared target stage."""
        if not target or not isinstance(target, str):
            raise ValueError("Transition target must be a non-empty string identifier")
        return Transition[Any](
            target=target,
            is_stay=False,
            is_pop=False,
            is_end=False,
            metadata=metadata,
        )

    @classmethod
    def stay(cls, **metadata: Any) -> "Transition[None]":
        """Construct a transition retaining the current active stage."""
        return Transition[None](
            target=None,
            is_stay=True,
            is_pop=False,
            is_end=False,
            metadata=metadata,
        )

    @classmethod
    def pop_frame(
        cls,
        mutation: SlotMutation | None = None,
        **metadata: Any,
    ) -> "Transition[Any]":
        """Construct a transition popping the current digression TaskFrame."""
        return Transition[Any](
            target=None,
            is_stay=False,
            is_pop=True,
            is_end=False,
            mutation=mutation,
            metadata=metadata,
        )

    @classmethod
    def end(cls, result: Any = None, **metadata: Any) -> "Transition[Any]":
        """Construct a terminal transition concluding workflow execution."""
        return Transition[Any](
            target=None,
            is_stay=False,
            is_pop=False,
            is_end=True,
            result=result,
            metadata=metadata,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Transition):
            return False
        return (
            self.target == other.target
            and self.is_stay == other.is_stay
            and self.is_pop == other.is_pop
            and self.is_end == other.is_end
            and self.mutation == other.mutation
            and self.result == other.result
        )

    def __repr__(self) -> str:
        if self.is_end:
            return f"Transition.end(result={self.result!r})"
        if self.is_pop:
            return f"Transition.pop_frame(mutation={self.mutation!r})"
        if self.is_stay:
            return "Transition.stay()"
        if self.target is not None:
            return f"Transition.to({self.target!r})"
        if self.declared_targets:
            return f"Transition(targets={self.declared_targets!r})"
        return "Transition()"


class ChoicePayload(BaseModel):
    """Structured multiple-choice response rendered deterministically in Pass 2.

    Enables high-speed regulatory disclosures and interactive option menus
    without invoking an external Large Language Model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt: str
    options: Sequence[str] | Sequence[Mapping[str, Any]]
    allow_custom: bool = False
    metadata: Mapping[str, Any] = Field(default_factory=dict)


__all__: list[str] = [
    "ChoicePayload",
    "SlotDelta",
    "SlotMutation",
    "Transition",
    "VaultDelta",
]
