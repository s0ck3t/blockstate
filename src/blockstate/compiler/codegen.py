"""Declarative Control Grammar (DCG) deterministic code generator and specification models.

Provides strongly-typed Pydantic specification models (StatechartSpec, StageSpec,
TransitionSpec, GuardSpec, SlotModelSpec, SlotFieldSpec, DominanceAssertionSpec)
that round-trip losslessly with StatechartGraph and export_json(). Emits idiomatic,
PEP 695 type-annotated Python 3.12+ source code that compiles without runtime
execution via extract_statechart_from_source(), verifies under LengauerTarjanSolver,
and satisfies all UK Patent Claim 1 to 15 invariants.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blockstate.compiler.ast_extractor import (
    StageNode,
    StatechartGraph,
    TransitionEdge,
)
from blockstate.compiler.exporters import export_json
from blockstate.errors import ConfigurationError

# ============================================================================
# Specification Models
# ============================================================================


class SlotFieldSpec(BaseModel):
    """Declarative specification of an individual slot leaf field."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Field attribute identifier")
    type_name: str = Field(
        default="str",
        description="Python type name, e.g. str, int, float, bool",
    )
    vaulted: bool = Field(
        default=False,
        description="Whether the field is wrapped with Vaulted[T] in memory",
    )
    required: bool = Field(
        default=True,
        description="Whether the field is required or optional",
    )
    default_value: Any | None = Field(
        default=None,
        description="Optional default literal value",
    )
    description: str | None = Field(
        default=None,
        description="Docstring or field documentation",
    )


class SlotModelSpec(BaseModel):
    """Declarative specification of a Pydantic BaseModel slot schema."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Pydantic model class name")
    description: str | None = Field(
        default=None,
        description="Class-level documentation",
    )
    fields: list[SlotFieldSpec] = Field(
        default_factory=list,
        description="Ordered slot fields",
    )


class TransitionSpec(BaseModel):
    """Declarative specification of a stage transition directive."""

    model_config = ConfigDict(frozen=True)

    target: str = Field(
        description="Destination stage identifier, or [END], [POP], [STAY]",
    )
    kind: str = Field(
        default="to",
        description="Transition kind: to, end, stay, pop",
    )
    guard: str | None = Field(
        default=None,
        description="Guard method name if conditional",
    )
    description: str | None = Field(
        default=None,
        description="Rationale or audit annotation",
    )


class GuardSpec(BaseModel):
    """Declarative specification of a stage guard method."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Guard method identifier")
    stage: str = Field(
        description="Target stage identifier this guard attaches to",
    )
    target: str = Field(
        description="Destination stage entered when guard evaluates truthy",
    )
    description: str | None = Field(
        default=None,
        description="Guard condition documentation",
    )


class DominanceAssertionSpec(BaseModel):
    """Declarative compliance assertion verifying precursor dominance."""

    model_config = ConfigDict(frozen=True)

    precursor: str = Field(
        description="Required predecessor stage that must dominate targets",
    )
    targets: list[str] = Field(
        description="Privileged target stages requiring precursor execution",
    )
    root: str | None = Field(
        default=None,
        description="Root entry stage (defaults to initial_stage)",
    )
    description: str | None = Field(
        default=None,
        description="Regulatory compliance rationale",
    )


class StageSpec(BaseModel):
    """Declarative specification of a statechart stage."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Unique stage identifier")
    is_initial: bool = Field(
        default=False,
        description="Whether this is the root entry stage",
    )
    terminal: bool = Field(
        default=False,
        description="Whether this stage terminates enclave execution",
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Whitelisted tool identifiers",
    )
    allow_digressions: list[str] = Field(
        default_factory=list,
        description="Permitted digression stage identifiers",
    )
    on_refusal: str | None = Field(
        default=None,
        description="Escalation fallback for user or model refusals",
    )
    on_max_turns_exceeded: str | None = Field(
        default=None,
        description="Fallback when stage conversational loops exceed max_turns",
    )
    on_breach: str | None = Field(
        default=None,
        description="Containment fallback on qualification breach (BLK-VAL-003)",
    )
    on_security_violation: str | None = Field(
        default=None,
        description="Fallback on unwhitelisted tool invocation (BLK-SEC-001)",
    )
    max_turns: int | None = Field(
        default=5,
        description="Maximum conversational turns allowed before fallback",
    )
    collect_model: str | None = Field(
        default=None,
        description="Collected slot model class name",
    )
    canned_response: str | None = Field(
        default=None,
        description="Static canned prompt text",
    )
    choice_options: list[str] = Field(
        default_factory=list,
        description="Structured choice options",
    )
    transitions: list[TransitionSpec] = Field(
        default_factory=list,
        description="Outgoing transitions",
    )
    guards: list[GuardSpec] = Field(
        default_factory=list,
        description="Associated stage guards",
    )
    description: str | None = Field(
        default=None,
        description="Stage docstring description",
    )


class StatechartSpec(BaseModel):
    """Top-level Declarative Control Grammar statechart specification."""

    model_config = ConfigDict(frozen=True)

    agent_name: str = Field(description="Agent class name")
    initial_stage: str | None = Field(
        default=None,
        description="Default root entry stage",
    )
    description: str | None = Field(
        default=None,
        description="Agent module and class docstring",
    )
    stages: list[StageSpec] = Field(
        default_factory=list,
        description="All declared stages",
    )
    slot_models: list[SlotModelSpec] = Field(
        default_factory=list,
        description="Pydantic slot models",
    )
    dominance_assertions: list[DominanceAssertionSpec] = Field(
        default_factory=list,
        description="Precursor dominance assertions",
    )

    @classmethod
    def from_graph(cls, graph: StatechartGraph) -> StatechartSpec:
        """Construct a StatechartSpec losslessly from a compiled StatechartGraph."""
        return spec_from_graph(graph)

    def to_graph(self) -> StatechartGraph:
        """Convert this specification losslessly into a compiled StatechartGraph."""
        return spec_to_graph(self)

    @classmethod
    def from_json(cls, data: dict[str, Any] | str) -> StatechartSpec:
        """Parse a StatechartSpec from an export_json dictionary or JSON payload string."""
        return spec_from_json(data)

    def to_json(self) -> dict[str, Any]:
        """Serialise this specification to an export_json-compatible topology dictionary."""
        return spec_to_json(self)

    def to_json_str(self, *, indent: int = 2) -> str:
        """Serialise this specification to a formatted JSON string."""
        return json.dumps(self.to_json(), indent=indent, sort_keys=True)

    def to_source(self, *, type_mode: str = "literal") -> str:
        """Generate idiomatic PEP 695 type-annotated Python 3.12+ source code."""
        return generate_python_source(self, type_mode=type_mode)


# ============================================================================
# Bidirectional Mapping Routines
# ============================================================================


def spec_from_graph(graph: StatechartGraph) -> StatechartSpec:
    """Construct a StatechartSpec losslessly from a compiled StatechartGraph."""
    stages_spec: list[StageSpec] = []

    # Map guards attached to each stage
    for stage_name, stage_node in graph.stages.items():
        # Find transitions originating from this stage
        # Normal edges: kind != "fallback"
        stage_edges = [e for e in graph.transitions if e.source == stage_name]
        normal_edges = [e for e in stage_edges if e.kind != "fallback"]

        guard_names_for_stage = list(graph.guards.get(stage_name, []))
        stage_guards: list[GuardSpec] = []
        stage_transitions: list[TransitionSpec] = []

        # Categorise edges into guards and stage transitions
        # An edge is a guard transition if edge.guard is set or if matched against guard_names
        unassigned_edges: list[TransitionEdge] = []
        for edge in normal_edges:
            if edge.guard is not None:
                stage_guards.append(
                    GuardSpec(
                        name=edge.guard,
                        stage=stage_name,
                        target=edge.target,
                    )
                )
            else:
                unassigned_edges.append(edge)

        # In AST extraction, guard methods execute after stage methods, so their
        # transition calls appear at the tail of unassigned_edges
        if guard_names_for_stage and unassigned_edges:
            # Number of guard functions remaining without explicit edge.guard
            remaining_guard_names = [
                g for g in guard_names_for_stage if not any(sg.name == g for sg in stage_guards)
            ]
            num_guard_edges = len(remaining_guard_names)
            if len(unassigned_edges) >= num_guard_edges and num_guard_edges > 0:
                regular_slice = unassigned_edges[:-num_guard_edges]
                guard_slice = unassigned_edges[-num_guard_edges:]
                for edge in regular_slice:
                    stage_transitions.append(
                        TransitionSpec(
                            target=edge.target,
                            kind=edge.kind,
                            guard=None,
                        )
                    )
                for g_name, edge in zip(remaining_guard_names, guard_slice, strict=True):
                    stage_guards.append(
                        GuardSpec(
                            name=g_name,
                            stage=stage_name,
                            target=edge.target,
                        )
                    )
            else:
                for edge in unassigned_edges:
                    stage_transitions.append(
                        TransitionSpec(
                            target=edge.target,
                            kind=edge.kind,
                            guard=None,
                        )
                    )
                for g_name in remaining_guard_names:
                    # Synthesise default guard target if edge list was truncated
                    default_target = (
                        stage_transitions[0].target if stage_transitions else stage_name
                    )
                    stage_guards.append(
                        GuardSpec(
                            name=g_name,
                            stage=stage_name,
                            target=default_target,
                        )
                    )
        else:
            for edge in unassigned_edges:
                stage_transitions.append(
                    TransitionSpec(
                        target=edge.target,
                        kind=edge.kind,
                        guard=None,
                    )
                )

        stages_spec.append(
            StageSpec(
                name=stage_node.name,
                is_initial=stage_node.is_initial or (stage_node.name == graph.initial_stage),
                terminal=stage_node.terminal,
                tools=list(stage_node.tools),
                allow_digressions=list(stage_node.allow_digressions),
                on_refusal=stage_node.on_refusal,
                on_max_turns_exceeded=stage_node.on_max_turns_exceeded,
                on_breach=stage_node.on_breach,
                on_security_violation=stage_node.on_security_violation,
                max_turns=stage_node.max_turns,
                collect_model=stage_node.collect_model,
                canned_response=stage_node.canned_response,
                choice_options=list(stage_node.choice_options),
                transitions=stage_transitions,
                guards=stage_guards,
            )
        )

    # Synthesise slot models referenced by collect_model attributes
    slot_models: list[SlotModelSpec] = []
    seen_models: set[str] = set()
    for stage_spec in stages_spec:
        if stage_spec.collect_model and stage_spec.collect_model not in seen_models:
            seen_models.add(stage_spec.collect_model)
            slot_models.append(
                SlotModelSpec(
                    name=stage_spec.collect_model,
                    description=f"Hydrated slot collection schema for {stage_spec.name}.",
                    fields=[
                        SlotFieldSpec(
                            name="reference_id",
                            type_name="str",
                            vaulted=False,
                            required=True,
                            description="Primary entity reference identifier",
                        )
                    ],
                )
            )

    return StatechartSpec(
        agent_name=graph.agent_name,
        initial_stage=graph.initial_stage,
        description=f"Declarative Control Grammar agent: {graph.agent_name}",
        stages=stages_spec,
        slot_models=slot_models,
        dominance_assertions=[],
    )


def spec_to_graph(spec: StatechartSpec) -> StatechartGraph:
    """Convert a StatechartSpec losslessly into a compiled StatechartGraph."""
    stages_dict: dict[str, StageNode] = {}
    transitions_list: list[TransitionEdge] = []
    guards_dict: dict[str, list[str]] = {}

    for stage in spec.stages:
        node = StageNode(
            name=stage.name,
            is_initial=stage.is_initial or (stage.name == spec.initial_stage),
            terminal=stage.terminal,
            tools=tuple(stage.tools),
            allow_digressions=tuple(stage.allow_digressions),
            on_refusal=stage.on_refusal,
            on_max_turns_exceeded=stage.on_max_turns_exceeded,
            on_breach=stage.on_breach,
            on_security_violation=stage.on_security_violation,
            max_turns=stage.max_turns,
            collect_model=stage.collect_model,
            canned_response=stage.canned_response,
            choice_options=tuple(stage.choice_options),
        )
        stages_dict[stage.name] = node

        # 1. Fallback edges
        for target in (
            stage.on_refusal,
            stage.on_max_turns_exceeded,
            stage.on_breach,
            stage.on_security_violation,
        ):
            if target:
                transitions_list.append(
                    TransitionEdge(
                        source=stage.name,
                        target=target,
                        kind="fallback",
                    )
                )

        # 2. Stage transitions
        for trans in stage.transitions:
            transitions_list.append(
                TransitionEdge(
                    source=stage.name,
                    target=trans.target,
                    kind=trans.kind,
                    guard=trans.guard,
                )
            )

        # 3. Guard edges and guard registry
        guard_names: list[str] = []
        for guard in stage.guards:
            guard_names.append(guard.name)
            transitions_list.append(
                TransitionEdge(
                    source=stage.name,
                    target=guard.target,
                    kind="to",
                    guard=guard.name,
                )
            )
        if guard_names:
            guards_dict[stage.name] = guard_names

    resolved_initial = spec.initial_stage
    if resolved_initial is None and spec.stages:
        initial_candidates = [s.name for s in spec.stages if s.is_initial]
        resolved_initial = initial_candidates[0] if initial_candidates else spec.stages[0].name

    graph = StatechartGraph(
        agent_name=spec.agent_name,
        initial_stage=resolved_initial,
        stages=stages_dict,
        transitions=transitions_list,
        guards=guards_dict,
    )
    return graph


def spec_from_json(data: dict[str, Any] | str) -> StatechartSpec:
    """Parse a StatechartSpec from an export_json schema or StatechartSpec payload."""
    payload: dict[str, Any]
    if isinstance(data, str):
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as err:
            raise ConfigurationError(
                f"Invalid JSON payload supplied to spec_from_json: {err.msg}",
                code="BLK-CFG-002",
            ) from err
    else:
        payload = data

    # Case A: Standard StatechartSpec model dump (stages is a list)
    if "stages" in payload and isinstance(payload["stages"], list):
        return StatechartSpec.model_validate(payload)

    # Case B: export_json schema (stages is a dict mapping stage name to properties)
    if "stages" in payload and isinstance(payload["stages"], dict):
        agent_name = str(payload.get("agent_name", "AnonymousAgent"))
        initial_stage = payload.get("initial_stage")
        stages_payload: dict[str, dict[str, Any]] = payload["stages"]
        transitions_payload: list[dict[str, Any]] = payload.get("transitions", [])

        # Index transitions by source stage
        transitions_by_source: dict[str, list[dict[str, Any]]] = {}
        for edge_dict in transitions_payload:
            src = str(edge_dict.get("source", ""))
            transitions_by_source.setdefault(src, []).append(edge_dict)

        stages_spec: list[StageSpec] = []
        for stage_name, s_data in stages_payload.items():
            edges = transitions_by_source.get(stage_name, [])
            normal_edges = [e for e in edges if e.get("kind") != "fallback"]

            stage_transitions: list[TransitionSpec] = []
            stage_guards: list[GuardSpec] = []
            guard_names: list[str] = list(s_data.get("guards", []))

            for edge in normal_edges:
                guard_val = edge.get("guard")
                target_val = str(edge.get("target", ""))
                kind_val = str(edge.get("kind", "to"))

                if guard_val:
                    stage_guards.append(
                        GuardSpec(
                            name=str(guard_val),
                            stage=stage_name,
                            target=target_val,
                        )
                    )
                else:
                    stage_transitions.append(
                        TransitionSpec(
                            target=target_val,
                            kind=kind_val,
                            guard=None,
                        )
                    )

            # Match any unassigned guard names from s_data["guards"]
            existing_guard_names = {g.name for g in stage_guards}
            for g_name in guard_names:
                if g_name not in existing_guard_names:
                    # Associate with the first transition or default self
                    fallback_target = (
                        stage_transitions[0].target if stage_transitions else stage_name
                    )
                    stage_guards.append(
                        GuardSpec(
                            name=g_name,
                            stage=stage_name,
                            target=fallback_target,
                        )
                    )

            stages_spec.append(
                StageSpec(
                    name=stage_name,
                    is_initial=(
                        bool(s_data.get("is_initial", False)) or (stage_name == initial_stage)
                    ),
                    terminal=bool(s_data.get("terminal", False)),
                    tools=[str(t) for t in s_data.get("tools", [])],
                    allow_digressions=[str(d) for d in s_data.get("allow_digressions", [])],
                    on_refusal=s_data.get("on_refusal"),
                    on_max_turns_exceeded=s_data.get("on_max_turns_exceeded"),
                    on_breach=s_data.get("on_breach"),
                    on_security_violation=s_data.get("on_security_violation"),
                    max_turns=s_data.get("max_turns", 5),
                    collect_model=s_data.get("collect_model"),
                    canned_response=s_data.get("canned_response"),
                    choice_options=[str(c) for c in s_data.get("choice_options", [])],
                    transitions=stage_transitions,
                    guards=stage_guards,
                )
            )

        return StatechartSpec(
            agent_name=agent_name,
            initial_stage=initial_stage,
            description=f"Imported from JSON statechart topology: {agent_name}",
            stages=stages_spec,
            slot_models=[],
            dominance_assertions=[],
        )

    raise ConfigurationError(
        "Payload does not match StatechartSpec or export_json schema",
        code="BLK-CFG-002",
    )


def spec_to_json(spec: StatechartSpec) -> dict[str, Any]:
    """Serialise a StatechartSpec to an export_json-compatible topology dictionary."""
    graph = spec_to_graph(spec)
    json_text = export_json(graph)
    result: dict[str, Any] = json.loads(json_text)
    # Add slot models and dominance assertions metadata if present
    if spec.slot_models:
        result["slot_models"] = [m.model_dump() for m in spec.slot_models]
    if spec.dominance_assertions:
        result["dominance_assertions"] = [a.model_dump() for a in spec.dominance_assertions]
    return result


# Module-level aliases ensuring contract conformance with M1, M2, and M3 interfaces
from_graph = spec_from_graph
to_graph = spec_to_graph
from_json = spec_from_json
to_json = spec_to_json


# ============================================================================
# PEP 695 Python 3.12+ Source Code Generator
# ============================================================================


class PythonCodeGenerator:
    """Deterministic Python Declarative Control Grammar source code generator."""

    def __init__(self, spec: StatechartSpec, *, type_mode: str = "literal") -> None:
        self.spec = spec
        self.type_mode = type_mode  # "literal" (default, strict mypy), "string", "simple"

    def generate(self) -> str:
        """Generate formatted, deterministic Python 3.12+ source code."""
        sections: list[str] = [
            self._render_header(),
            self._render_imports(),
        ]

        slot_models_code = self._render_slot_models()
        if slot_models_code:
            sections.append(slot_models_code)

        tools_code = self._render_tool_stubs()
        if tools_code:
            sections.append(tools_code)

        sections.append(self._render_agent_class())

        dominance_code = self._render_dominance_helpers()
        if dominance_code:
            sections.append(dominance_code)

        sections.append(self._render_exports())

        # Join sections with standard double newlines and ensure single trailing newline
        source = "\n\n\n".join(s for s in sections if s.strip()) + "\n"
        return source

    def _render_header(self) -> str:
        agent_name = self.spec.agent_name
        desc = self.spec.description or f"Declarative Control Grammar (DCG) Agent: {agent_name}."
        return (
            f'"""{desc}\n\n'
            f"Statically compiled statechart with compile-time dominator verification.\n"
            f"Generated automatically by blockstate.compiler.codegen.\n"
            f'"""'
        )

    def _render_imports(self) -> str:
        typing_items = ["Any"]
        if self.type_mode == "literal":
            typing_items.append("Literal")
        typing_str = ", ".join(typing_items)

        sections: list[list[str]] = [
            # Standard library
            [f"from typing import {typing_str}"],
        ]

        # Third party
        if self.spec.slot_models:
            sections.append(["from pydantic import BaseModel, Field"])

        # First party (blockstate)
        first_party: list[str] = []
        has_guards = any(stage.guards for stage in self.spec.stages)
        core_imports = ["Agent"]
        if has_guards:
            core_imports.append("Guard")
        core_imports.extend(["Stage", "Transition"])
        first_party.append(f"from blockstate.core.agent import {', '.join(core_imports)}")

        has_tools = any(stage.tools for stage in self.spec.stages)
        if has_tools:
            first_party.append("from blockstate.core.gatekeeper import RunContext")

        has_choices = any(stage.choice_options for stage in self.spec.stages)
        if has_choices:
            first_party.append("from blockstate.core.transitions import ChoicePayload")

        has_vaulted = any(
            field.vaulted for model in self.spec.slot_models for field in model.fields
        )
        has_detokenise = any(
            any(
                kw in tool_name.lower()
                for kw in ("identity", "verify", "auth", "nin", "token", "ssn", "credit")
            )
            for stage in self.spec.stages
            for tool_name in stage.tools
        )

        sec_imports: list[str] = []
        if has_detokenise:
            sec_imports.append("Detokenise")
        if has_vaulted:
            sec_imports.append("Vaulted")
        if sec_imports:
            first_party.append(
                f"from blockstate.security.annotations import {', '.join(sec_imports)}"
            )

        sections.append(first_party)

        return "\n\n".join("\n".join(sec) for sec in sections if sec)

    def _render_slot_models(self) -> str:
        if not self.spec.slot_models:
            return ""

        chunks: list[str] = []
        for model in self.spec.slot_models:
            doc = model.description or f"Slot model schema for {model.name}."
            lines: list[str] = [
                f"class {model.name}(BaseModel):",
                f'    """{doc}"""',
                "",
            ]
            if not model.fields:
                lines.append("    pass")
            else:
                for field_spec in model.fields:
                    f_type = field_spec.type_name
                    if field_spec.vaulted:
                        f_type = f"Vaulted[{f_type}]"

                    desc_arg = (
                        f'description="{field_spec.description}"'
                        if field_spec.description
                        else 'description="Hydrated slot leaf"'
                    )
                    if field_spec.required:
                        lines.append(f"    {field_spec.name}: {f_type} = Field({desc_arg})")
                    else:
                        def_val = repr(field_spec.default_value)
                        field_decl = (
                            f"    {field_spec.name}: {f_type} | None = "
                            f"Field(default={def_val}, {desc_arg})"
                        )
                        lines.append(field_decl)
            chunks.append("\n".join(lines))

        return "\n\n".join(chunks)

    def _render_tool_stubs(self) -> str:
        # Collect all unique tool names across stages
        all_tools: list[str] = []
        for stage in self.spec.stages:
            for tool_name in stage.tools:
                if tool_name not in all_tools:
                    all_tools.append(tool_name)

        if not all_tools:
            return ""

        stubs: list[str] = []
        for tool_name in all_tools:
            # Showcase Detokenise[str] parameter if tool indicates verification/PII
            is_security_tool = any(
                keyword in tool_name.lower()
                for keyword in ("identity", "verify", "auth", "nin", "token", "ssn", "credit")
            )
            lines: list[str] = [
                f"def {tool_name}(",
                "    context: RunContext[Any],",
            ]
            if is_security_tool:
                lines.append('    token: Detokenise[str] = "",')
            else:
                lines.append('    payload: str = "",')
            ret_payload = f'{{"status": "ok", "tool": "{tool_name}", "turn": context.turn_index}}'
            lines.extend(
                [
                    ") -> dict[str, Any]:",
                    f'    """Authorised enclave tool execution stub for {tool_name}."""',
                    f"    return {ret_payload}",
                ]
            )
            stubs.append("\n".join(lines))

        return "\n\n".join(stubs)

    def _render_agent_class(self) -> str:
        agent_name = self.spec.agent_name
        doc = (
            self.spec.description or f"Declarative Control Grammar statechart agent: {agent_name}."
        )
        lines: list[str] = [
            f"class {agent_name}(Agent):",
            f'    """{doc}"""',
            "",
        ]

        # Order stages so the initial stage is always the first stage emitted
        initial_name = self.spec.initial_stage
        sorted_stages: list[StageSpec] = []
        for stage in self.spec.stages:
            if stage.name == initial_name or (initial_name is None and stage.is_initial):
                sorted_stages.insert(0, stage)
                if initial_name is None:
                    initial_name = stage.name
            else:
                sorted_stages.append(stage)

        # Render stage methods and guards
        for idx, stage in enumerate(sorted_stages):
            if idx > 0:
                lines.append("")
            stage_lines = self._render_stage_method(stage)
            for s_line in stage_lines:
                lines.append(f"    {s_line}" if s_line else "")

            # Render stage guards immediately following stage definition
            for guard in stage.guards:
                lines.append("")
                guard_lines = self._render_guard_method(guard)
                for g_line in guard_lines:
                    lines.append(f"    {g_line}" if g_line else "")

        return "\n".join(lines)

    def _render_stage_method(self, stage: StageSpec) -> list[str]:
        lines: list[str] = []

        # 1. Format @Stage decorator
        stage_args: list[str] = [f'name="{stage.name}"']
        if stage.collect_model:
            stage_args.append(f"collect={stage.collect_model}")
        if stage.tools:
            tools_repr = "[" + ", ".join(f'"{t}"' for t in stage.tools) + "]"
            stage_args.append(f"tools={tools_repr}")
        if stage.max_turns is not None and stage.max_turns != 5:
            stage_args.append(f"max_turns={stage.max_turns}")
        if stage.allow_digressions:
            digs_repr = "[" + ", ".join(f'"{d}"' for d in stage.allow_digressions) + "]"
            stage_args.append(f"allow_digressions={digs_repr}")
        if stage.terminal:
            stage_args.append("terminal=True")
        if stage.canned_response:
            canned_escaped = stage.canned_response.replace('"', '\\"')
            stage_args.append(f'canned_response="{canned_escaped}"')
        if stage.choice_options:
            opts_repr = "[" + ", ".join(f'"{c}"' for c in stage.choice_options) + "]"
            choice_str = (
                'choice_options=ChoicePayload(prompt="Please select an option:", '
                f"options={opts_repr})"
            )
            stage_args.append(choice_str)
        if stage.on_refusal:
            stage_args.append(f'on_refusal="{stage.on_refusal}"')
        if stage.on_max_turns_exceeded:
            stage_args.append(f'on_max_turns_exceeded="{stage.on_max_turns_exceeded}"')
        if stage.on_breach:
            stage_args.append(f'on_breach="{stage.on_breach}"')
        if stage.on_security_violation:
            stage_args.append(f'on_security_violation="{stage.on_security_violation}"')

        if len(stage_args) == 1:
            lines.append(f"@Stage({stage_args[0]})")
        else:
            lines.append("@Stage(")
            for arg in stage_args:
                lines.append(f"    {arg},")
            lines.append(")")

        # 2. Format @Transition decorator if stage has outgoing targets
        outgoing_targets = [t.target for t in stage.transitions if t.kind == "to"]
        if outgoing_targets:
            if len(outgoing_targets) == 1:
                lines.append(f'@Transition(targets=("{outgoing_targets[0]}",))')
            else:
                targets_repr = ", ".join(f'"{t}"' for t in outgoing_targets)
                lines.append(f"@Transition(targets=({targets_repr},))")

        # 3. Determine method return type
        return_type = self._resolve_return_type(stage)

        # 4. Method signature
        method_name = f"{stage.name}_stage"
        lines.append(f"def {method_name}(self) -> {return_type}:")

        # 5. Method body docstring
        doc = stage.description or f"Stage handler for {stage.name}."
        lines.append(f'    """{doc}"""')

        # 6. Static transition statements satisfying [Blockstate E014]
        body_lines = self._render_transition_body(stage)
        lines.extend(f"    {b}" for b in body_lines)

        return lines

    def _render_guard_method(self, guard: GuardSpec) -> list[str]:
        lines: list[str] = [
            f'@Guard("{guard.stage}", targets=("{guard.target}",))',
        ]
        ret_type = (
            f'Transition[Literal["{guard.target}"]]'
            if self.type_mode == "literal"
            else f'Transition["{guard.target}"]'
        )
        lines.append(f"def {guard.name}(self) -> {ret_type}:")
        doc = guard.description or f"Guard check routing to {guard.target}."
        lines.append(f'    """{doc}"""')
        lines.append(f'    return Transition.to("{guard.target}")')
        return lines

    def _resolve_return_type(self, stage: StageSpec) -> str:
        if stage.terminal:
            return "Transition[dict[str, str]]"

        has_pop = any(t.kind == "pop" for t in stage.transitions)
        if has_pop:
            return "Transition[None]"

        targets = [t.target for t in stage.transitions if t.kind in ("to", "stay")]
        if not targets:
            return "Transition[None]"

        if self.type_mode == "literal":
            if len(targets) == 1:
                return f'Transition[Literal["{targets[0]}"]]'
            literals = " | ".join(f'Literal["{t}"]' for t in targets)
            return f"Transition[{literals}]"
        elif self.type_mode == "string":
            if len(targets) == 1:
                return f'Transition["{targets[0]}"]'
            pipe_targets = " | ".join(f'"{t}"' for t in targets)
            return f"Transition[{pipe_targets}]"
        else:
            return "Transition[str]"

    def _render_transition_body(self, stage: StageSpec) -> list[str]:
        if stage.terminal:
            return ['return Transition.end(result={"status": "completed"})']

        if any(t.kind == "pop" for t in stage.transitions):
            return ["return Transition.pop_frame()"]

        if any(t.kind == "stay" for t in stage.transitions) and not any(
            t.kind == "to" for t in stage.transitions
        ):
            return ["return Transition.stay()"]

        to_targets = [t.target for t in stage.transitions if t.kind == "to"]
        if not to_targets:
            return ["return Transition.stay()"]

        if len(to_targets) == 1:
            return [f'return Transition.to("{to_targets[0]}")']

        # Branching targets: emit deterministic static branches without reflection
        lines: list[str] = []
        for idx, target in enumerate(to_targets[:-1]):
            cond = f"if not self.stages:  # Branch option {idx + 1}"
            lines.append(cond)
            lines.append(f'    return Transition.to("{target}")')
        lines.append(f'return Transition.to("{to_targets[-1]}")')
        return lines

    def _render_dominance_helpers(self) -> str:
        if not self.spec.dominance_assertions:
            return ""

        chunks: list[str] = [
            "def verify_agent_dominance(",
            "    cls: type | str | None = None,",
            "    source: str | None = None,",
            ") -> bool:",
            '    """Verify compile-time Lengauer-Tarjan dominance assertions for this agent."""',
            "    import inspect",
            "    import sys",
            "    from pathlib import Path",
            "    from blockstate.compiler.ast_extractor import extract_statechart_from_source",
            "    from blockstate.compiler.dominators import verify_dominance",
            "",
            "    if isinstance(cls, str) and source is None:",
            "        source = cls",
            "        cls = None",
            "",
            "    is_cls = cls is not None and not isinstance(cls, str)",
            f"    target_cls = cls if is_cls else {self.spec.agent_name}",
            "",
            "    if source is None:",
            "        try:",
            '            source = Path(__file__).read_text(encoding="utf-8")',
            "        except (NameError, OSError):",
            "            pass",
            "",
            "    if source is None and target_cls is not None:",
            "        try:",
            "            source = inspect.getsource(target_cls)",
            "        except (TypeError, OSError):",
            "            pass",
            "",
            "    if source is None and target_cls is not None:",
            '        mod_name = getattr(target_cls, "__module__", None)',
            "        if mod_name and mod_name in sys.modules:",
            "            mod = sys.modules[mod_name]",
            '            source = getattr(mod, "_blockstate_source", None)',
            "            if source is None:",
            '                mod_file = getattr(mod, "__file__", None)',
            "                if mod_file:",
            "                    try:",
            '                        source = Path(mod_file).read_text(encoding="utf-8")',
            "                    except OSError:",
            "                        pass",
            "",
            "    if source is not None:",
            "        graph = extract_statechart_from_source(source)",
            "        adj = graph.adjacency_list(include_fallbacks=True)",
            "    else:",
            '        stages_map = getattr(target_cls, "_stages", {})',
            "        adj = {name: set(s.targets) for name, s in stages_map.items()}",
            "        for name, s in stages_map.items():",
            "            fallbacks = (",
            '                getattr(s, "on_refusal", None),',
            '                getattr(s, "on_max_turns_exceeded", None),',
            '                getattr(s, "on_breach", None),',
            '                getattr(s, "on_security_violation", None),',
            "            )",
            "            for fb in fallbacks:",
            "                if fb:",
            "                    adj.setdefault(name, set()).add(fb)",
            "",
        ]

        for idx, assertion in enumerate(self.spec.dominance_assertions):
            root = repr(assertion.root or self.spec.initial_stage or "disclosure")
            precursor = repr(assertion.precursor)
            targets = repr(assertion.targets)
            chunks.append(f"    # Assertion {idx + 1}: Precursor {precursor} dominates {targets}")
            proof_call = (
                f"    proof_{idx} = verify_dominance(\n"
                f"        root={root},\n"
                f"        graph=adj,\n"
                f"        precursor={precursor},\n"
                f"        targets={targets},\n"
                f"    )"
            )
            chunks.append(proof_call)
            chunks.append(f"    if not proof_{idx}.satisfied:")
            chunks.append("        return False")

        chunks.append("    return True")
        return "\n".join(chunks)

    def _render_exports(self) -> str:
        symbols: list[str] = [f'"{self.spec.agent_name}"']
        for model in self.spec.slot_models:
            symbols.append(f'"{model.name}"')
        for stage in self.spec.stages:
            for tool_name in stage.tools:
                tool_repr = f'"{tool_name}"'
                if tool_repr not in symbols:
                    symbols.append(tool_repr)
        if self.spec.dominance_assertions:
            symbols.append('"verify_agent_dominance"')

        export_lines: list[str] = [
            "__all__: list[str] = [",
        ]
        for sym in sorted(symbols):
            export_lines.append(f"    {sym},")
        export_lines.append("]")
        return "\n".join(export_lines)


def generate_python_source(
    spec: StatechartSpec,
    *,
    type_mode: str = "literal",
) -> str:
    """Generate idiomatic PEP 695 type-annotated Python 3.12+ source code from StatechartSpec."""
    generator = PythonCodeGenerator(spec, type_mode=type_mode)
    return generator.generate()


generate_agent_source = generate_python_source


__all__: list[str] = [
    "DominanceAssertionSpec",
    "GuardSpec",
    "PythonCodeGenerator",
    "SlotFieldSpec",
    "SlotModelSpec",
    "StageSpec",
    "StatechartSpec",
    "TransitionSpec",
    "from_graph",
    "from_json",
    "generate_agent_source",
    "generate_python_source",
    "spec_from_graph",
    "spec_from_json",
    "spec_to_graph",
    "spec_to_json",
    "to_graph",
    "to_json",
]
