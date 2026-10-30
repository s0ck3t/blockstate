"""Comprehensive unit tests for blockstate.compiler AST extractor and exporters."""

import time
from pathlib import Path

import pytest

from blockstate.compiler.ast_extractor import (
    extract_statechart_from_file,
    extract_statechart_from_source,
)
from blockstate.compiler.exporters import export_json, export_mermaid
from blockstate.errors import (
    DynamicTransitionError,
    InvalidStageGraphError,
    UnreachableStageError,
)

VALID_AGENT_SOURCE = """
from blockstate.core.agent import Agent, Stage, Guard, Transition
from blockstate.core.transitions import ChoicePayload
from pydantic import BaseModel

class SampleSlots(BaseModel):
    policy_id: str

class CompliantClaimsAgent(Agent):
    @Stage(
        name="disclosure",
        initial=True,
        tools=["log_audit"],
        canned_response="Standard regulatory disclosure.",
    )
    def disclosure_stage(self) -> Transition[str]:
        return Transition.to("collect_details")

    @Stage(
        name="collect_details",
        collect=SampleSlots,
        tools=["verify_identity"],
        max_turns=3,
        allow_digressions=["faq_help"],
        on_refusal="human_handoff",
        on_max_turns_exceeded="human_handoff",
        on_breach="fraud_alert",
        on_security_violation="fraud_alert",
    )
    def details_stage(self) -> Transition[str]:
        return Transition.to("settlement")

    @Guard("collect_details")
    def guard_check(self) -> Transition[str]:
        return Transition.to("settlement")

    @Stage(
        name="faq_help",
        canned_response="FAQ assistance.",
    )
    def faq_stage(self) -> Transition[None]:
        return Transition.pop_frame()

    @Stage(
        name="settlement",
        choice_options=ChoicePayload(prompt="Select method:", options=["BACS", "Cheque"]),
    )
    def settlement_stage(self) -> Transition[str]:
        return Transition.to("complete")

    @Stage(
        name="complete",
        terminal=True,
        canned_response="Payment disbursed.",
    )
    def complete_stage(self) -> Transition[dict[str, str]]:
        return Transition.end(result={"status": "paid"})

    @Stage(name="human_handoff", terminal=True)
    def handoff_stage(self) -> Transition[dict[str, str]]:
        return Transition.end(result={"status": "escalated"})

    @Stage(name="fraud_alert", terminal=True)
    def fraud_stage(self) -> Transition[dict[str, str]]:
        return Transition.end(result={"status": "locked"})
"""


@pytest.mark.patent_invariant
def test_compiler_extract_valid_statechart() -> None:
    """Verify static extraction of stages, transitions, tools, and digressions."""
    graph = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent.py")

    assert graph.agent_name == "CompliantClaimsAgent"
    assert graph.initial_stage == "disclosure"
    assert "disclosure" in graph.stages
    assert "collect_details" in graph.stages
    assert "settlement" in graph.stages
    assert "complete" in graph.stages
    assert "faq_help" in graph.stages

    # Verify stage metadata
    details_node = graph.stages["collect_details"]
    assert details_node.tools == ("verify_identity",)
    assert details_node.max_turns == 3
    assert details_node.allow_digressions == ("faq_help",)
    assert details_node.on_refusal == "human_handoff"
    assert details_node.on_max_turns_exceeded == "human_handoff"
    assert details_node.on_breach == "fraud_alert"
    assert details_node.on_security_violation == "fraud_alert"

    # Verify transitions
    targets = [e.target for e in graph.transitions if e.source == "disclosure"]
    assert "collect_details" in targets

    # Verify guards
    assert "collect_details" in graph.guards
    assert "guard_check" in graph.guards["collect_details"]


@pytest.mark.patent_invariant
def test_compiler_blockstate_e014_dynamic_transition_target() -> None:
    """Verify dynamic transition destination raises [Blockstate E014] with exact diagnostic."""
    dynamic_source = """
from blockstate.core.agent import Agent, Stage, Transition

class DynamicAgent(Agent):
    @Stage(name="step_a")
    def step_a(self) -> Transition[str]:
        target = "step_b"
        return Transition.to(target)
"""
    with pytest.raises(DynamicTransitionError) as exc_info:
        extract_statechart_from_source(dynamic_source, filename="dynamic.py")

    msg = str(exc_info.value)
    assert "[Blockstate E014]" in msg
    assert "Dynamic transition destination detected at dynamic.py:8." in msg
    assert "Transitions must reference static State definitions" in msg


@pytest.mark.patent_invariant
def test_compiler_blockstate_e014_reflection_getattr() -> None:
    """Verify reflection using getattr() raises [Blockstate E014]."""
    getattr_source = """
from blockstate.core.agent import Agent, Stage, Transition

class ReflectionAgent(Agent):
    @Stage(name="step_a")
    def step_a(self) -> Transition[str]:
        next_step = getattr(self, "step_b")()
        return next_step
"""
    with pytest.raises(DynamicTransitionError) as exc_info:
        extract_statechart_from_source(getattr_source, filename="reflection.py")

    msg = str(exc_info.value)
    assert "[Blockstate E014]" in msg
    assert "Dynamic transition destination detected at reflection.py:7." in msg


@pytest.mark.patent_invariant
def test_compiler_blockstate_e014_field_validator_transition() -> None:
    """Verify Transition inside @field_validator raises [Blockstate E014]."""
    validator_source = """
from pydantic import BaseModel, field_validator
from blockstate.core.agent import Transition

class SlotModel(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if v == "bad":
            Transition.to("error_stage")
        return v
"""
    with pytest.raises(DynamicTransitionError) as exc_info:
        extract_statechart_from_source(validator_source, filename="validator.py")

    msg = str(exc_info.value)
    assert "[Blockstate E014]" in msg
    assert "Dynamic transition destination detected at validator.py:12." in msg


@pytest.mark.patent_invariant
def test_compiler_unreachable_dead_stage() -> None:
    """Verify unreachable stages without incoming transitions raise UnreachableStageError."""
    dead_stage_source = """
from blockstate.core.agent import Agent, Stage, Transition

class DeadStageAgent(Agent):
    @Stage(name="start", initial=True)
    def start(self) -> Transition[str]:
        return Transition.to("active")

    @Stage(name="active")
    def active(self) -> Transition[None]:
        return Transition.stay()

    @Stage(name="orphan_dead_stage")
    def orphan(self) -> Transition[None]:
        return Transition.stay()
"""
    with pytest.raises(UnreachableStageError) as exc_info:
        extract_statechart_from_source(dead_stage_source, filename="dead.py")

    err = exc_info.value
    assert "orphan_dead_stage" in err.message
    assert err.code == "BLK-AST-002"


def test_compiler_invalid_digression_subgraph() -> None:
    """Verify digression jumping directly into main flow raises InvalidStageGraphError."""
    illegal_digress_source = """
from blockstate.core.agent import Agent, Stage, Transition

class BrokenDigressAgent(Agent):
    @Stage(name="main_step", allow_digressions=["side_tangent"])
    def main_step(self) -> Transition[str]:
        return Transition.to("intermediate_step")

    @Stage(name="intermediate_step")
    def inter(self) -> Transition[None]:
        return Transition.stay()

    @Stage(name="side_tangent")
    def side_tangent(self) -> Transition[str]:
        # Illegal: digression transitions to non-terminal intermediate main flow
        return Transition.to("intermediate_step")
"""
    with pytest.raises(InvalidStageGraphError) as exc_info:
        extract_statechart_from_source(illegal_digress_source, filename="broken_digress.py")

    assert "Digression stage 'side_tangent' contains direct transition to main-flow" in str(
        exc_info.value
    )
    assert exc_info.value.code == "BLK-AST-001"


def test_compiler_missing_transition_to_arg() -> None:
    """Verify Transition.to() with missing argument raises InvalidStageGraphError."""
    missing_arg_source = """
from blockstate.core.agent import Agent, Stage, Transition

class BadArgAgent(Agent):
    @Stage(name="step_1")
    def step_1(self) -> Transition[None]:
        return Transition.to()
"""
    with pytest.raises(InvalidStageGraphError) as exc_info:
        extract_statechart_from_source(missing_arg_source, filename="bad_arg.py")

    assert "missing required target argument" in str(exc_info.value)


def test_compiler_syntax_error_handling() -> None:
    """Verify syntax errors in source code raise InvalidStageGraphError."""
    syntax_error_source = "class IncompleteAgent(def broken:"
    with pytest.raises(InvalidStageGraphError) as exc_info:
        extract_statechart_from_source(syntax_error_source, filename="syntax.py")

    assert "Python syntax error" in str(exc_info.value)


@pytest.mark.patent_invariant
def test_compiler_exporters() -> None:
    """Verify Mermaid and JSON exporters produce valid representations."""
    graph = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent.py")

    # 1. Mermaid exporter
    mermaid_def = export_mermaid(graph, markdown_fence=False)
    assert "flowchart TD" in mermaid_def
    assert "disclosure" in mermaid_def
    assert "collect_details" in mermaid_def
    assert "tools: verify_identity" in mermaid_def
    assert "-->" in mermaid_def

    fenced_mermaid = export_mermaid(graph, markdown_fence=True)
    assert fenced_mermaid.startswith("```mermaid\nflowchart TD")
    assert fenced_mermaid.endswith("\n```")

    # 2. JSON exporter
    json_str = export_json(graph)
    assert '"agent_name": "CompliantClaimsAgent"' in json_str
    assert '"disclosure"' in json_str
    assert '"tools": [' in json_str


def test_compiler_500_node_synthetic_benchmark() -> None:
    """Verify static compilation of a 500-node synthetic DCG statechart finishes in < 50ms."""
    lines: list[str] = [
        "from blockstate.core.agent import Agent, Stage, Transition",
        "class HugeAgent(Agent):",
    ]

    # Generate 500 sequential stages
    for i in range(500):
        next_stage = f"stage_{i + 1}" if i < 499 else "stage_final"
        is_initial = 'initial=True, ' if i == 0 else ""
        lines.append(f"    @Stage(name='stage_{i}', {is_initial}tools=['tool_{i}'])")
        lines.append(f"    def handler_{i}(self) -> Transition[str]:")
        lines.append(f"        return Transition.to('{next_stage}')")

    lines.append("    @Stage(name='stage_final', terminal=True)")
    lines.append("    def handler_final(self) -> Transition[dict[str, str]]:")
    lines.append("        return Transition.end(result={'status': 'done'})")

    synthetic_source = "\n".join(lines)

    start_time = time.perf_counter()
    graph = extract_statechart_from_source(
        synthetic_source,
        filename="huge.py",
        validate_reachability=True,
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    assert len(graph.stages) == 501
    assert graph.initial_stage == "stage_0"
    assert elapsed_ms < 50.0, f"Compilation took {elapsed_ms:.2f}ms (budget: 50.0ms)"


def test_compiler_extract_from_file(tmp_path: Path) -> None:
    """Verify extracting StatechartGraph directly from a file path on disk."""
    file_path = tmp_path / "agent.py"
    file_path.write_text(VALID_AGENT_SOURCE, encoding="utf-8")

    graph = extract_statechart_from_file(file_path)
    assert graph.agent_name == "CompliantClaimsAgent"
    assert len(graph.stages) > 0


def test_compiler_additional_coverage_branches() -> None:
    """Verify auxiliary compiler branches, exporter edge cases, and guard errors."""
    from blockstate.compiler.ast_extractor import StatechartGraph, TransitionEdge

    # 1. Empty graph reachability
    empty_graph = StatechartGraph(agent_name="Empty")
    empty_graph.validate_reachability()  # should not raise

    # 2. Adjacency list without fallbacks
    edge1 = TransitionEdge(source="a", target="b", kind="to")
    edge2 = TransitionEdge(source="a", target="c", kind="fallback")
    g = StatechartGraph(
        agent_name="Test",
        initial_stage="a",
        stages={"a": None, "b": None, "c": None},  # type: ignore[dict-item]
        transitions=[edge1, edge2],
    )
    adj_with_fb = g.adjacency_list(include_fallbacks=True)
    adj_no_fb = g.adjacency_list(include_fallbacks=False)
    assert "c" in adj_with_fb["a"]
    assert "c" not in adj_no_fb["a"]

    # 3. Invalid @Guard target
    bad_guard_source = """
from blockstate.core.agent import Agent, Stage, Guard, Transition

class BadGuardAgent(Agent):
    @Stage(name="step_1")
    def step_1(self) -> Transition[None]:
        return Transition.stay()

    @Guard()
    def guard_without_arg(self) -> Transition[None]:
        return Transition.stay()
"""
    with pytest.raises(InvalidStageGraphError) as exc_info:
        extract_statechart_from_source(bad_guard_source, filename="bad_guard.py")
    assert "@Guard decorator must specify target stage name" in str(exc_info.value)

    # 4. Attribute collect model in @Stage(collect=pkg.Model)
    attr_model_source = """
import pkg.models
from blockstate.core.agent import Agent, Stage, Transition

class AttrAgent(Agent):
    @Stage(name="step_1", collect=pkg.models.MyModel)
    def step_1(self) -> Transition[None]:
        return Transition.stay()
"""
    attr_graph = extract_statechart_from_source(
        attr_model_source,
        filename="attr.py",
        validate_reachability=False,
    )
    assert attr_graph.stages["step_1"].collect_model == "MyModel"

