"""Declarative Control Grammar (DCG) Agent and decorator registry.

Provides @Stage, @Transition, and @Guard decorators for static statechart
definition, enforcing compile-time and initialisation-time invariants:
- Rejection of duplicate stage names via DuplicateStageError (BLK-CFG-001)
- Rejection of missing/empty stage names via ConfigurationError (BLK-CFG-002)
- Rejection of dynamic runtime stage creation via ConfigurationError (BLK-CFG-002)
- Scoped ToolGatekeeper construction without global callable registries
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeVar

from pydantic import BaseModel

from blockstate.core.gatekeeper import ToolGatekeeper
from blockstate.core.transitions import ChoicePayload, Transition
from blockstate.errors import ConfigurationError, DuplicateStageError

T = TypeVar("T")
AgentT = TypeVar("AgentT", bound="Agent")


@dataclass(frozen=True, slots=True)
class StageDefinition:
    """Immutable declarative definition of a conversational statechart stage."""

    name: str
    collect: type[BaseModel] | None = None
    tools: tuple[str, ...] = ()
    max_turns: int | None = 5
    allow_digressions: tuple[str, ...] = ()
    allow_slot_overrides: bool = False
    terminal: bool = False
    canned_response: str | None = None
    choice_options: ChoicePayload | None = None
    on_breach: str | None = None
    on_max_turns_exceeded: str | None = None
    on_refusal: str | None = None
    on_security_violation: str | None = None
    targets: tuple[str, ...] = ()
    handler: Callable[..., Any] | None = None
    guards: tuple[Callable[..., Any], ...] = ()


def Stage(
    name: str | None = None,
    *,
    collect: type[BaseModel] | None = None,
    tools: Sequence[str | Callable[..., Any]] = (),
    max_turns: int | None = 5,
    allow_digressions: Sequence[str] = (),
    allow_slot_overrides: bool = False,
    terminal: bool = False,
    canned_response: str | None = None,
    choice_options: ChoicePayload | Sequence[str] | Sequence[Mapping[str, Any]] | None = None,
    on_breach: str | None = None,
    on_max_turns_exceeded: str | None = None,
    on_refusal: str | None = None,
    on_security_violation: str | None = None,
) -> Callable[[T], T]:
    """Decorate a method or class as a Declarative Control Grammar stage.

    Raises ConfigurationError (BLK-CFG-002) if stage identifier is omitted or empty.
    """
    if name is not None and not str(name).strip():
        raise ConfigurationError("Stage name cannot be empty or blank", code="BLK-CFG-002")

    tool_names: list[str] = []
    for tool_item in tools:
        if isinstance(tool_item, str):
            tool_names.append(tool_item)
        elif callable(tool_item):
            tool_names.append(getattr(tool_item, "__name__", str(tool_item)))
        else:
            raise ConfigurationError(
                f"Invalid tool specification in stage '{name}': {tool_item!r}",
                code="BLK-CFG-002",
            )

    resolved_choice: ChoicePayload | None = None
    if isinstance(choice_options, ChoicePayload):
        resolved_choice = choice_options
    elif choice_options is not None:
        resolved_choice = ChoicePayload(
            prompt=canned_response or f"Please choose an option for {name}:",
            options=choice_options,
        )

    def decorator(target: T) -> T:
        resolved_name = name
        if resolved_name is None:
            if hasattr(target, "__name__"):
                resolved_name = target.__name__
            else:
                raise ConfigurationError(
                    "Stage identifier must be provided",
                    code="BLK-CFG-002",
                )

        if not str(resolved_name).strip():
            raise ConfigurationError("Stage name cannot be empty or blank", code="BLK-CFG-002")

        stage_def = StageDefinition(
            name=str(resolved_name),
            collect=collect,
            tools=tuple(tool_names),
            max_turns=max_turns,
            allow_digressions=tuple(allow_digressions),
            allow_slot_overrides=allow_slot_overrides,
            terminal=terminal,
            canned_response=canned_response,
            choice_options=resolved_choice,
            on_breach=on_breach,
            on_max_turns_exceeded=on_max_turns_exceeded,
            on_refusal=on_refusal,
            on_security_violation=on_security_violation,
            handler=target if callable(target) else None,
        )

        setattr(target, "_blockstate_stage", stage_def)  # noqa: B010
        return target

    return decorator


def Guard(
    stage: str | None = None,
    *,
    targets: Sequence[str] | str | None = None,
) -> Callable[[T], T]:
    """Decorate a pure deterministic stage guard method returning Transition[T]."""
    resolved_targets: tuple[str, ...] = ()
    if targets is not None:
        resolved_targets = (targets,) if isinstance(targets, str) else tuple(targets)

    def decorator(fn: T) -> T:
        setattr(fn, "_blockstate_guard", True)  # noqa: B010
        if stage is not None:
            setattr(fn, "_blockstate_guard_stage", stage)  # noqa: B010
        if resolved_targets:
            setattr(fn, "_blockstate_targets", resolved_targets)  # noqa: B010
        return fn

    return decorator


class Agent:
    """Base class for Blockstate deterministic statechart agents.

    Scans Declarative Control Grammar decorators (@Stage, @Transition, @Guard)
    at class initialisation time, validating uniqueness, stage identifiers,
    and static topology while providing isolated ToolGatekeeper scoping.
    """

    _stages: dict[str, StageDefinition]
    _initial_stage: str | None
    _gatekeeper: ToolGatekeeper

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        stages: dict[str, StageDefinition] = {}
        guards_by_stage: dict[str, list[Callable[..., Any]]] = {}

        # First collect all stage-annotated and guard-annotated attributes
        for _attr_name, member in list(cls.__dict__.items()):
            stage_meta: StageDefinition | None = getattr(member, "_blockstate_stage", None)
            if stage_meta is not None:
                if stage_meta.name in stages:
                    msg = (
                        f"Duplicate stage identifier '{stage_meta.name}' declared in "
                        f"{cls.__name__}"
                    )
                    raise DuplicateStageError(
                        msg,
                        code="BLK-CFG-001",
                        stage=stage_meta.name,
                    )
                # Check for explicit transition targets attached via @Transition
                explicit_targets: tuple[str, ...] = getattr(member, "_blockstate_targets", ())
                if explicit_targets:
                    stage_meta = StageDefinition(
                        name=stage_meta.name,
                        collect=stage_meta.collect,
                        tools=stage_meta.tools,
                        max_turns=stage_meta.max_turns,
                        allow_digressions=stage_meta.allow_digressions,
                        allow_slot_overrides=stage_meta.allow_slot_overrides,
                        terminal=stage_meta.terminal,
                        canned_response=stage_meta.canned_response,
                        choice_options=stage_meta.choice_options,
                        on_breach=stage_meta.on_breach,
                        on_max_turns_exceeded=stage_meta.on_max_turns_exceeded,
                        on_refusal=stage_meta.on_refusal,
                        on_security_violation=stage_meta.on_security_violation,
                        targets=explicit_targets,
                        handler=stage_meta.handler,
                    )
                stages[stage_meta.name] = stage_meta

            is_guard: bool = getattr(member, "_blockstate_guard", False)
            if is_guard:
                guard_stage: str | None = getattr(member, "_blockstate_guard_stage", None)
                if guard_stage:
                    guards_by_stage.setdefault(guard_stage, []).append(member)

        # Attach gathered guards to corresponding stages
        for stage_name, guard_list in guards_by_stage.items():
            if stage_name in stages:
                existing = stages[stage_name]
                stages[stage_name] = StageDefinition(
                    name=existing.name,
                    collect=existing.collect,
                    tools=existing.tools,
                    max_turns=existing.max_turns,
                    allow_digressions=existing.allow_digressions,
                    allow_slot_overrides=existing.allow_slot_overrides,
                    terminal=existing.terminal,
                    canned_response=existing.canned_response,
                    choice_options=existing.choice_options,
                    on_breach=existing.on_breach,
                    on_max_turns_exceeded=existing.on_max_turns_exceeded,
                    on_refusal=existing.on_refusal,
                    on_security_violation=existing.on_security_violation,
                    targets=existing.targets,
                    handler=existing.handler,
                    guards=tuple(guard_list),
                )

        cls._stages = stages
        cls._initial_stage = next(iter(stages.keys())) if stages else None

    def __init__(self, tools: Mapping[str, Callable[..., Any]] | None = None) -> None:
        self._instance_stages = dict(self._stages)
        self._gatekeeper = ToolGatekeeper()

        # Register instance methods marked as tools or supplied in tools dict
        if tools:
            self._gatekeeper.register_tools(tools)

        for attr_name in dir(self):
            if attr_name.startswith("_"):
                continue
            val = getattr(self, attr_name)
            if callable(val) and getattr(val, "_blockstate_tool", False):
                self._gatekeeper.register_tool(attr_name, val)

    @property
    def stages(self) -> MappingProxyType[str, StageDefinition]:
        """Access the frozen map of declarative stage definitions."""
        return MappingProxyType(self._instance_stages)

    @property
    def initial_stage(self) -> str | None:
        """Return the root entry stage for this agent."""
        return self._initial_stage

    @property
    def gatekeeper(self) -> ToolGatekeeper:
        """Access the isolated ToolGatekeeper instance for this agent."""
        return self._gatekeeper

    def get_stage(self, name: str) -> StageDefinition:
        """Retrieve a stage definition by identifier.

        Raises ConfigurationError (BLK-CFG-002) if stage is not registered.
        """
        if name not in self._instance_stages:
            raise ConfigurationError(
                f"Stage '{name}' is not registered on agent {self.__class__.__name__}",
                code="BLK-CFG-002",
                stage=name,
            )
        return self._instance_stages[name]

    def register_dynamic_stage(self, *args: Any, **kwargs: Any) -> None:
        """Disallow dynamic runtime stage registration under Declarative Control Grammar rules."""
        raise ConfigurationError(
            "Dynamic runtime stage creation is prohibited by Declarative Control Grammar. "
            "All stages must be statically declared via @Stage.",
            code="BLK-CFG-002",
        )

    def as_tool(self, *args: Any, **kwargs: Any) -> Any:
        """Mount this agent as a transactional compliance execution enclave tool."""
        # Enclave adapter hook connecting to outer orchestrators
        tool_name = kwargs.get("name") or (args[0] if args else self.__class__.__name__)
        return {"name": tool_name, "enclave": self}

    async def run_as_subflow(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute a sub-flow conversational turn within this agent enclave."""
        # Sub-flow entrypoint for enclave invocation
        session_id = kwargs.get("session_id") or (args[0] if len(args) > 0 else "default_session")
        user_message = kwargs.get("user_message") or (args[1] if len(args) > 1 else "")
        initial_context = kwargs.get("initial_context") or (args[2] if len(args) > 2 else {})
        return {
            "session_id": session_id,
            "user_message": user_message,
            "initial_context": initial_context or {},
        }


__all__: list[str] = [
    "Agent",
    "Guard",
    "Stage",
    "StageDefinition",
    "Transition",
]
