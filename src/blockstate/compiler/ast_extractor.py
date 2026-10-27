"""Declarative Control Grammar (DCG) static AST graph extractor and validator.

Parses Python source code offline using ast.parse to extract stage definitions,
transitions, guards, and fallback targets without executing user code. Enforces
static transition discipline, terminating compilation with [Blockstate E014] upon
detecting dynamic transition targets, reflection, or transitions within field validators.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blockstate.errors import (
    DynamicTransitionError,
    InvalidStageGraphError,
    UnreachableStageError,
)


@dataclass(frozen=True)
class StageNode:
    """Represents a statically extracted stage in the statechart graph."""

    name: str
    is_initial: bool = False
    terminal: bool = False
    tools: tuple[str, ...] = ()
    allow_digressions: tuple[str, ...] = ()
    on_refusal: str | None = None
    on_max_turns_exceeded: str | None = None
    on_breach: str | None = None
    on_security_violation: str | None = None
    max_turns: int | None = None
    collect_model: str | None = None
    canned_response: str | None = None
    choice_options: tuple[str, ...] = ()
    lineno: int = 0


@dataclass(frozen=True)
class TransitionEdge:
    """Represents a statically verified directed transition edge between stages."""

    source: str
    target: str
    kind: str = "to"  # "to", "end", "stay", "pop", "fallback"
    guard: str | None = None
    lineno: int = 0


@dataclass
class StatechartGraph:
    """Complete statically compiled topology of an agent's Declarative Control Grammar."""

    agent_name: str
    initial_stage: str | None = None
    stages: dict[str, StageNode] = field(default_factory=dict)
    transitions: list[TransitionEdge] = field(default_factory=list)
    guards: dict[str, list[str]] = field(default_factory=dict)  # stage_id -> list of guard names

    def adjacency_list(self, include_fallbacks: bool = True) -> dict[str, set[str]]:
        """Construct an adjacency list mapping each stage to its set of reachable successors."""
        adj: dict[str, set[str]] = {name: set() for name in self.stages}
        for edge in self.transitions:
            if edge.kind in ("stay", "pop"):
                continue
            if not include_fallbacks and edge.kind == "fallback":
                continue
            if edge.source in adj and edge.target in self.stages:
                adj[edge.source].add(edge.target)
        return adj

    def validate_reachability(self) -> None:
        """Verify that all declared non-initial stages are reachable from the initial stage.

        Raises UnreachableStageError (BLK-AST-002) if any dead stages exist.
        """
        if not self.initial_stage:
            return

        adj = self.adjacency_list(include_fallbacks=True)
        visited: set[str] = set()
        queue: list[str] = [self.initial_stage]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            for nxt in adj.get(curr, ()):
                if nxt not in visited:
                    queue.append(nxt)

        # Digression entry stages can be invoked anywhere digressions are allowed
        for stage in self.stages.values():
            for dig in stage.allow_digressions:
                if dig in self.stages and dig not in visited:
                    queue.append(dig)
                    while queue:
                        c = queue.pop(0)
                        if c in visited:
                            continue
                        visited.add(c)
                        for n in adj.get(c, ()):
                            if n not in visited:
                                queue.append(n)

        unreachable = sorted(set(self.stages.keys()) - visited)
        if unreachable:
            raise UnreachableStageError(
                f"Unreachable dead stages detected in agent '{self.agent_name}': "
                f"{', '.join(unreachable)}",
                code="BLK-AST-002",
                unreachable_stages=unreachable,
            )

    def validate_digressions(self) -> None:
        """Verify that digression sub-graphs honour call-return pushdown semantics.

        A digression stage must not transition directly into arbitrary main-flow
        stages without popping (Transition.pop_frame()), terminating, or routing
        to an escalation fallback.
        """
        all_digressions: set[str] = set()
        for s in self.stages.values():
            all_digressions.update(s.allow_digressions)

        for edge in self.transitions:
            if edge.source in all_digressions and edge.kind == "to":
                target_stage = self.stages.get(edge.target)
                is_terminal = target_stage.terminal if target_stage else False
                is_another_digression = edge.target in all_digressions
                if not is_terminal and not is_another_digression:
                    raise InvalidStageGraphError(
                        f"Digression stage '{edge.source}' contains direct transition to main-flow "
                        f"stage '{edge.target}'. Digressions must terminate with "
                        f"Transition.pop_frame(), route to a terminal stage, or invoke an "
                        f"escalation fallback.",
                        code="BLK-AST-001",
                        stage=edge.source,
                        target=edge.target,
                    )


class _DCGASTVisitor(ast.NodeVisitor):
    """Internal AST visitor parsing Declarative Control Grammar declarations."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.agent_name: str = "AnonymousAgent"
        self.initial_stage: str | None = None
        self.stages: dict[str, StageNode] = {}
        self.transitions: list[TransitionEdge] = []
        self.guards: dict[str, list[str]] = {}
        self.current_stage: str | None = None
        self.in_field_validator: bool = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Inspect class definitions extending Agent."""
        is_agent = any(
            (isinstance(base, ast.Name) and base.id == "Agent")
            or (isinstance(base, ast.Attribute) and base.attr == "Agent")
            for base in node.bases
        )

        # Also inspect classes containing @Stage decorators even if base class is indirect
        has_stage_methods = any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(self._is_stage_decorator(dec) for dec in item.decorator_list)
            for item in node.body
        )

        if is_agent or has_stage_methods:
            self.agent_name = node.name

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._inspect_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._inspect_function(node)

    def _inspect_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        is_val = any(self._is_field_validator_decorator(dec) for dec in node.decorator_list)
        prev_in_val = self.in_field_validator
        if is_val:
            self.in_field_validator = True

        stage_dec = next((d for d in node.decorator_list if self._is_stage_decorator(d)), None)
        guard_dec = next((d for d in node.decorator_list if self._is_guard_decorator(d)), None)

        prev_stage = self.current_stage
        if stage_dec is not None:
            stage_node = self._parse_stage_decorator(stage_dec, node.name, node.lineno)
            self.stages[stage_node.name] = stage_node
            if self.initial_stage is None or stage_node.is_initial:
                self.initial_stage = stage_node.name
            self.current_stage = stage_node.name
            self._register_fallback_edges(stage_node)
        elif guard_dec is not None:
            target_stage = self._parse_guard_target(guard_dec, node.lineno)
            self.current_stage = target_stage
            self.guards.setdefault(target_stage, []).append(node.name)

        # Inspect function body for transitions and reflection checks
        self.generic_visit(node)

        self.current_stage = prev_stage
        self.in_field_validator = prev_in_val

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect calls for DynamicTransitionError [Blockstate E014] and valid Transitions."""
        lineno = getattr(node, "lineno", 0)

        # 1. Detect dynamic reflection calls like getattr(self, ...) inside stages/guards
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and self.current_stage is not None
        ):
            raise DynamicTransitionError(
                    f"Dynamic transition destination detected at {self.filename}:{lineno}. "
                    f"Transitions must reference static State definitions to enable "
                    f"Lengauer-Tarjan dominator verification.",
                    code="BLK-AST-014",
                    filename=self.filename,
                    lineno=lineno,
                )

        # 2. Detect Transition calls
        if self._is_transition_call(node):
            if self.in_field_validator:
                raise DynamicTransitionError(
                    f"Dynamic transition destination detected at {self.filename}:{lineno}. "
                    f"Transitions must reference static State definitions to enable "
                    f"Lengauer-Tarjan dominator verification.",
                    code="BLK-AST-014",
                    filename=self.filename,
                    lineno=lineno,
                )

            method_name = self._get_transition_method(node)
            source_stage = self.current_stage or "unknown"

            if method_name == "to":
                if not node.args:
                    raise InvalidStageGraphError(
                        f"Transition.to() missing required target argument at "
                        f"{self.filename}:{lineno}",
                        code="BLK-AST-001",
                        filename=self.filename,
                        lineno=lineno,
                    )
                target_arg = node.args[0]
                if not isinstance(target_arg, ast.Constant) or not isinstance(
                    target_arg.value, str
                ):
                    raise DynamicTransitionError(
                        f"Dynamic transition destination detected at {self.filename}:{lineno}. "
                        f"Transitions must reference static State definitions to enable "
                        f"Lengauer-Tarjan dominator verification.",
                        code="BLK-AST-014",
                        filename=self.filename,
                        lineno=lineno,
                    )
                target_name = target_arg.value
                self.transitions.append(
                    TransitionEdge(
                        source=source_stage,
                        target=target_name,
                        kind="to",
                        lineno=lineno,
                    )
                )
            elif method_name == "end":
                self.transitions.append(
                    TransitionEdge(
                        source=source_stage,
                        target="[END]",
                        kind="end",
                        lineno=lineno,
                    )
                )
            elif method_name == "stay":
                self.transitions.append(
                    TransitionEdge(
                        source=source_stage,
                        target=source_stage,
                        kind="stay",
                        lineno=lineno,
                    )
                )
            elif method_name == "pop_frame":
                self.transitions.append(
                    TransitionEdge(
                        source=source_stage,
                        target="[POP]",
                        kind="pop",
                        lineno=lineno,
                    )
                )

        self.generic_visit(node)

    def _is_stage_decorator(self, dec: ast.expr) -> bool:
        if isinstance(dec, ast.Name):
            return dec.id == "Stage"
        if isinstance(dec, ast.Attribute):
            return dec.attr == "Stage"
        if isinstance(dec, ast.Call):
            return self._is_stage_decorator(dec.func)
        return False

    def _is_guard_decorator(self, dec: ast.expr) -> bool:
        if isinstance(dec, ast.Name):
            return dec.id == "Guard"
        if isinstance(dec, ast.Attribute):
            return dec.attr == "Guard"
        if isinstance(dec, ast.Call):
            return self._is_guard_decorator(dec.func)
        return False

    def _is_field_validator_decorator(self, dec: ast.expr) -> bool:
        if isinstance(dec, ast.Name):
            return dec.id == "field_validator"
        if isinstance(dec, ast.Attribute):
            return dec.attr == "field_validator"
        if isinstance(dec, ast.Call):
            return self._is_field_validator_decorator(dec.func)
        return False

    def _is_transition_call(self, node: ast.Call) -> bool:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "Transition"
        ):
            return node.func.attr in ("to", "end", "stay", "pop_frame")
        return False

    def _get_transition_method(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _parse_guard_target(self, dec: ast.expr, lineno: int) -> str:
        if isinstance(dec, ast.Call):
            if dec.args:
                first_arg = dec.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    return first_arg.value
            for kw in dec.keywords:
                if (
                    kw.arg in ("stage", "target")
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    return kw.value.value
        raise InvalidStageGraphError(
            f"@Guard decorator must specify target stage name as string at "
            f"{self.filename}:{lineno}",
            code="BLK-AST-001",
            lineno=lineno,
        )

    def _parse_stage_decorator(self, dec: ast.expr, fn_name: str, lineno: int) -> StageNode:
        name = fn_name
        is_initial = False
        terminal = False
        tools: list[str] = []
        digressions: list[str] = []
        on_refusal: str | None = None
        on_max_turns_exceeded: str | None = None
        on_breach: str | None = None
        on_security_violation: str | None = None
        max_turns: int | None = 5
        collect_model: str | None = None
        canned_response: str | None = None
        choice_options: list[str] = []

        if isinstance(dec, ast.Call):
            # Positional arguments: @Stage("name")
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(
                dec.args[0].value, str
            ):
                name = dec.args[0].value

            for kw in dec.keywords:
                val = self._extract_constant_value(kw.value)
                if kw.arg == "name" and isinstance(val, str):
                    name = val
                elif kw.arg == "initial" and isinstance(val, bool):
                    is_initial = val
                elif kw.arg == "terminal" and isinstance(val, bool):
                    terminal = val
                elif kw.arg in ("tools", "allowed_tools") and isinstance(val, (list, tuple)):
                    tools = [str(x) for x in val]
                elif kw.arg in ("allow_digressions", "allowed_digressions") and isinstance(
                    val, (list, tuple)
                ):
                    digressions = [str(x) for x in val]
                elif kw.arg == "on_refusal" and isinstance(val, str):
                    on_refusal = val
                elif kw.arg == "on_max_turns_exceeded" and isinstance(val, str):
                    on_max_turns_exceeded = val
                elif kw.arg == "on_breach" and isinstance(val, str):
                    on_breach = val
                elif kw.arg == "on_security_violation" and isinstance(val, str):
                    on_security_violation = val
                elif kw.arg == "max_turns" and (val is None or isinstance(val, int)):
                    max_turns = val
                elif kw.arg in ("collect", "target_model"):
                    collect_model = self._extract_name(kw.value)
                elif kw.arg == "canned_response" and isinstance(val, str):
                    canned_response = val
                elif kw.arg == "choice_options":
                    if isinstance(val, (list, tuple)):
                        choice_options = [str(x) for x in val]
                    elif isinstance(kw.value, ast.Call):
                        # ChoicePayload(prompt=..., options=[...])
                        for opt_kw in kw.value.keywords:
                            if opt_kw.arg == "options":
                                opt_vals = self._extract_constant_value(opt_kw.value)
                                if isinstance(opt_vals, (list, tuple)):
                                    choice_options = [str(x) for x in opt_vals]

        return StageNode(
            name=name,
            is_initial=is_initial,
            terminal=terminal,
            tools=tuple(tools),
            allow_digressions=tuple(digressions),
            on_refusal=on_refusal,
            on_max_turns_exceeded=on_max_turns_exceeded,
            on_breach=on_breach,
            on_security_violation=on_security_violation,
            max_turns=max_turns,
            collect_model=collect_model,
            canned_response=canned_response,
            choice_options=tuple(choice_options),
            lineno=lineno,
        )

    def _register_fallback_edges(self, stage: StageNode) -> None:
        """Register directed edges for fallback targets."""
        for target, _kind in [
            (stage.on_refusal, "fallback_refusal"),
            (stage.on_max_turns_exceeded, "fallback_max_turns"),
            (stage.on_breach, "fallback_breach"),
            (stage.on_security_violation, "fallback_security"),
        ]:
            if target:
                self.transitions.append(
                    TransitionEdge(
                        source=stage.name,
                        target=target,
                        kind="fallback",
                        lineno=stage.lineno,
                    )
                )

    def _extract_constant_value(self, node: ast.expr) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [self._extract_constant_value(elt) for elt in node.elts]
        return None

    def _extract_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


def extract_statechart_from_ast(tree: ast.AST, filename: str = "<string>") -> StatechartGraph:
    """Extract a StatechartGraph from an existing Python AST tree."""
    visitor = _DCGASTVisitor(filename=filename)
    visitor.visit(tree)
    graph = StatechartGraph(
        agent_name=visitor.agent_name,
        initial_stage=visitor.initial_stage,
        stages=visitor.stages,
        transitions=visitor.transitions,
        guards=visitor.guards,
    )
    graph.validate_digressions()
    return graph


def extract_statechart_from_source(
    source: str,
    filename: str = "<string>",
    *,
    validate_reachability: bool = True,
) -> StatechartGraph:
    """Parse Python source code and extract a validated StatechartGraph offline."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as err:
        raise InvalidStageGraphError(
            f"Python syntax error parsing DCG source at {filename}:{err.lineno}: {err.msg}",
            code="BLK-AST-001",
            filename=filename,
            lineno=err.lineno,
        ) from err

    graph = extract_statechart_from_ast(tree, filename=filename)
    if validate_reachability:
        graph.validate_reachability()
    return graph


def extract_statechart_from_file(
    file_path: str | Path,
    *,
    validate_reachability: bool = True,
) -> StatechartGraph:
    """Read a Python source file and extract a validated StatechartGraph offline."""
    path = Path(file_path)
    source = path.read_text(encoding="utf-8")
    return extract_statechart_from_source(
        source,
        filename=str(path),
        validate_reachability=validate_reachability,
    )


class StaticGraphCompiler:
    """Static Declarative Control Grammar AST compiler."""

    @staticmethod
    def compile_source(
        source: str,
        filename: str = "<string>",
        *,
        validate_reachability: bool = True,
    ) -> StatechartGraph:
        """Parse Python source code and extract a validated StatechartGraph offline."""
        return extract_statechart_from_source(
            source,
            filename=filename,
            validate_reachability=validate_reachability,
        )

    @staticmethod
    def compile_file(
        file_path: str | Path,
        *,
        validate_reachability: bool = True,
    ) -> StatechartGraph:
        """Read a Python source file and extract a validated StatechartGraph offline."""
        return extract_statechart_from_file(
            file_path,
            validate_reachability=validate_reachability,
        )


__all__: list[str] = [
    "StageNode",
    "StatechartGraph",
    "StaticGraphCompiler",
    "TransitionEdge",
    "extract_statechart_from_ast",
    "extract_statechart_from_file",
    "extract_statechart_from_source",
]
