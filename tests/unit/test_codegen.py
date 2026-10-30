"""Unit tests for blockstate.compiler.codegen.

Verifies Pydantic specification models, lossless bidirectional round-trip
conversion between StatechartSpec, StatechartGraph, and export_json(), PEP 695
type-annotated Python source code generation, and UK Patent Claim 1 to 15
invariant preservation.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from blockstate.compiler.ast_extractor import (
    extract_statechart_from_source,
)
from blockstate.compiler.codegen import (
    DominanceAssertionSpec,
    GuardSpec,
    SlotFieldSpec,
    SlotModelSpec,
    StageSpec,
    StatechartSpec,
    TransitionSpec,
    from_graph,
    from_json,
    generate_agent_source,
    generate_python_source,
    spec_from_graph,
    spec_from_json,
    spec_to_json,
    to_graph,
)
from blockstate.compiler.dominators import verify_dominance
from blockstate.compiler.exporters import export_json
from blockstate.errors import ConfigurationError

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


# ============================================================================
# Specification Models & Immutability Tests
# ============================================================================


def test_specification_models_instantiation_and_defaults() -> None:
    """Verify specification model defaults, field types, and frozen immutability."""
    field_spec = SlotFieldSpec(
        name="nin_token",
        vaulted=True,
        description="National Insurance number",
    )
    assert field_spec.name == "nin_token"
    assert field_spec.type_name == "str"
    assert field_spec.vaulted is True
    assert field_spec.required is True

    # Immutability check
    with pytest.raises(ValidationError):
        field_spec.vaulted = False

    model_spec = SlotModelSpec(
        name="CustomerSlots",
        description="Customer KYC data",
        fields=[field_spec],
    )
    assert model_spec.name == "CustomerSlots"
    assert len(model_spec.fields) == 1

    trans_spec = TransitionSpec(target="collect_kyc", kind="to")
    assert trans_spec.target == "collect_kyc"
    assert trans_spec.kind == "to"
    assert trans_spec.guard is None

    guard_spec = GuardSpec(name="check_eligible", stage="collect_kyc", target="approval")
    assert guard_spec.name == "check_eligible"
    assert guard_spec.stage == "collect_kyc"
    assert guard_spec.target == "approval"

    dom_spec = DominanceAssertionSpec(
        precursor="disclosure",
        targets=["settlement", "disbursement"],
        root="disclosure",
    )
    assert dom_spec.precursor == "disclosure"
    assert len(dom_spec.targets) == 2

    stage_spec = StageSpec(
        name="disclosure",
        is_initial=True,
        tools=["log_audit"],
        transitions=[trans_spec],
        guards=[guard_spec],
    )
    assert stage_spec.name == "disclosure"
    assert stage_spec.is_initial is True
    assert stage_spec.terminal is False
    assert stage_spec.tools == ["log_audit"]
    assert stage_spec.max_turns == 5

    spec = StatechartSpec(
        agent_name="KYCAgent",
        initial_stage="disclosure",
        stages=[stage_spec],
        slot_models=[model_spec],
        dominance_assertions=[dom_spec],
    )
    assert spec.agent_name == "KYCAgent"
    assert spec.initial_stage == "disclosure"
    assert len(spec.stages) == 1
    assert len(spec.slot_models) == 1
    assert len(spec.dominance_assertions) == 1


# ============================================================================
# Bidirectional Graph & JSON Lossless Mapping Tests
# ============================================================================


@pytest.mark.patent_invariant
def test_bidirectional_roundtrip_with_statechart_graph() -> None:
    """Verify lossless round-trip conversion between StatechartGraph and StatechartSpec."""
    # 1. Compile base graph from source
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent0.py")

    # 2. Convert graph0 -> spec0
    spec0 = from_graph(graph0)
    assert spec0.agent_name == "CompliantClaimsAgent"
    assert spec0.initial_stage == "disclosure"
    assert len(spec0.stages) == len(graph0.stages)

    # 3. Convert spec0 -> graph1
    graph1 = to_graph(spec0)
    assert graph1.agent_name == graph0.agent_name
    assert graph1.initial_stage == graph0.initial_stage
    assert set(graph1.stages.keys()) == set(graph0.stages.keys())

    # Verify stage attributes match exactly
    for name, s0 in graph0.stages.items():
        s1 = graph1.stages[name]
        assert s0.name == s1.name
        assert s0.terminal == s1.terminal
        assert s0.tools == s1.tools
        assert s0.allow_digressions == s1.allow_digressions
        assert s0.on_refusal == s1.on_refusal
        assert s0.on_max_turns_exceeded == s1.on_max_turns_exceeded
        assert s0.on_breach == s1.on_breach
        assert s0.on_security_violation == s1.on_security_violation
        assert s0.max_turns == s1.max_turns
        assert s0.collect_model == s1.collect_model
        assert s0.choice_options == s1.choice_options

    # Verify adjacency topology matches
    adj0 = graph0.adjacency_list(include_fallbacks=True)
    adj1 = graph1.adjacency_list(include_fallbacks=True)
    assert adj0 == adj1

    # Verify guards match
    assert graph1.guards.get("collect_details") == ["guard_check"]


@pytest.mark.patent_invariant
def test_bidirectional_roundtrip_with_json_schema() -> None:
    """Verify lossless conversion to and from export_json schema dictionaries."""
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent0.py")
    spec0 = spec_from_graph(graph0)

    # 1. Serialise to export_json dictionary via spec_to_json
    json_dict = spec_to_json(spec0)
    assert json_dict["agent_name"] == "CompliantClaimsAgent"
    assert json_dict["initial_stage"] == "disclosure"
    assert "stages" in json_dict
    assert "transitions" in json_dict
    assert isinstance(json_dict["stages"], dict)

    # 2. Deserialise dictionary via spec_from_json
    spec_from_dict = spec_from_json(json_dict)
    assert spec_from_dict.agent_name == spec0.agent_name
    assert spec_from_dict.initial_stage == spec0.initial_stage
    assert len(spec_from_dict.stages) == len(spec0.stages)

    # 3. Deserialise raw export_json string
    raw_json_str = export_json(graph0)
    spec_from_raw_str = from_json(raw_json_str)
    assert spec_from_raw_str.agent_name == "CompliantClaimsAgent"
    assert {s.name for s in spec_from_raw_str.stages} == set(graph0.stages.keys())

    # 4. Deserialise standard model dump JSON string
    model_dump_str = spec0.model_dump_json()
    spec_from_dump = from_json(model_dump_str)
    assert spec_from_dump.agent_name == spec0.agent_name

    # 5. Invalid JSON handling
    with pytest.raises(ConfigurationError):
        from_json("{ invalid json format")

    with pytest.raises(ConfigurationError):
        from_json({"unexpected": "schema"})


# ============================================================================
# PEP 695 Python Source Generation Tests
# ============================================================================


@pytest.mark.patent_invariant
def test_codegen_generates_valid_compilable_python_source() -> None:
    """Verify emitted source code compiles cleanly under extract_statechart_from_source()."""
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent0.py")
    spec0 = from_graph(graph0)

    # Add a dominance assertion to verify helper generation
    spec0 = StatechartSpec(
        agent_name=spec0.agent_name,
        initial_stage=spec0.initial_stage,
        description=spec0.description,
        stages=spec0.stages,
        slot_models=spec0.slot_models,
        dominance_assertions=[
            DominanceAssertionSpec(
                precursor="disclosure",
                targets=["settlement"],
                root="disclosure",
            )
        ],
    )

    # Generate source code in literal typing mode
    source = generate_python_source(spec0, type_mode="literal")
    assert isinstance(source, str)
    assert len(source) > 0

    # 1. Verify standard ast.parse passes
    parsed_ast = ast.parse(source)
    assert parsed_ast is not None

    # 2. Verify offline compilation via extract_statechart_from_source passes
    graph_gen = extract_statechart_from_source(source, filename="generated.py")
    assert graph_gen.agent_name == "CompliantClaimsAgent"
    assert graph_gen.initial_stage == "disclosure"
    assert set(graph_gen.stages.keys()) == set(graph0.stages.keys())

    # Verify reachability passes
    graph_gen.validate_reachability()

    # Verify digressions pass
    graph_gen.validate_digressions()

    # Verify dominance holds on extracted topology
    proof = verify_dominance(
        root="disclosure",
        graph=graph_gen.adjacency_list(include_fallbacks=True),
        precursor="disclosure",
        targets=["settlement"],
    )
    assert proof.satisfied is True


@pytest.mark.patent_invariant
def test_codegen_patent_invariants_ast_compliance() -> None:
    """Verify generated code strictly obeys Independent Claim 1 AST visitor rules."""
    # Build a complex multi-stage spec with branching, pop, stay, choices, and vaulted slots
    slot_model = SlotModelSpec(
        name="KYCSlotData",
        description="Customer KYC slot schema",
        fields=[
            SlotFieldSpec(
                name="nin_token",
                type_name="str",
                vaulted=True,
                description="Vaulted NIN",
            ),
            SlotFieldSpec(
                name="income",
                type_name="float",
                vaulted=False,
                required=False,
                default_value=0.0,
            ),
        ],
    )

    stages = [
        StageSpec(
            name="init_step",
            is_initial=True,
            tools=["log_audit"],
            transitions=[TransitionSpec(target="check_choice", kind="to")],
        ),
        StageSpec(
            name="check_choice",
            choice_options=["branch_a", "branch_b"],
            allow_digressions=["faq_digress"],
            transitions=[
                TransitionSpec(target="branch_a", kind="to"),
                TransitionSpec(target="branch_b", kind="to"),
            ],
            guards=[
                GuardSpec(name="guard_direct", stage="check_choice", target="branch_a"),
            ],
        ),
        StageSpec(
            name="faq_digress",
            canned_response="FAQ response text",
            transitions=[TransitionSpec(target="[POP]", kind="pop")],
        ),
        StageSpec(
            name="branch_a",
            collect_model="KYCSlotData",
            tools=["verify_identity"],
            transitions=[TransitionSpec(target="finish", kind="to")],
        ),
        StageSpec(
            name="branch_b",
            transitions=[TransitionSpec(target="finish", kind="to")],
        ),
        StageSpec(
            name="finish",
            terminal=True,
            canned_response="Process finished",
            transitions=[TransitionSpec(target="[END]", kind="end")],
        ),
    ]

    spec = StatechartSpec(
        agent_name="ComplexEnclaveAgent",
        initial_stage="init_step",
        stages=stages,
        slot_models=[slot_model],
    )

    source = generate_python_source(spec)

    # 1. Claim 1.1: Static Targets: all Transition.to calls must have string literal targets
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "Transition"
                and node.func.attr == "to"
            ):
                assert len(node.args) >= 1
                assert isinstance(node.args[0], ast.Constant)
                assert isinstance(node.args[0].value, str)

            # 2. Claim 1.1: No reflection calls
            if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                pytest.fail("Generated source code contains prohibited getattr() reflection call")

    # 3. Compile through DCGASTVisitor without [Blockstate E014]
    graph = extract_statechart_from_source(source)
    assert graph.agent_name == "ComplexEnclaveAgent"
    assert "KYCSlotData" in source
    assert "Vaulted[str]" in source
    assert "Detokenise[str]" in source
    assert "verify_identity" in source


@pytest.mark.patent_invariant
def test_codegen_source_passes_ruff_and_mypy_strict() -> None:
    """Verify that generated code passes ruff check and mypy --strict without errors."""
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent0.py")
    spec0 = from_graph(graph0)

    # Generate source
    source = generate_python_source(spec0, type_mode="literal")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_file = Path(tmp_dir) / "generated_agent.py"
        tmp_file.write_text(source, encoding="utf-8")

        # 1. Run ruff check on generated file
        ruff_bin = Path(sys.executable).parent / "ruff.exe"
        if ruff_bin.exists():
            res_ruff = subprocess.run(
                [str(ruff_bin), "check", str(tmp_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert (
                res_ruff.returncode == 0
            ), f"Ruff failed on generated code:\n{res_ruff.stdout}\n{res_ruff.stderr}"

        # 2. Run mypy --strict on generated file
        mypy_bin = Path(sys.executable).parent / "mypy.exe"
        if mypy_bin.exists():
            res_mypy = subprocess.run(
                [str(mypy_bin), "--strict", str(tmp_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert (
                res_mypy.returncode == 0
            ), f"Mypy failed on generated code:\n{res_mypy.stdout}\n{res_mypy.stderr}"


def test_codegen_synthetic_50_node_benchmark() -> None:
    """Verify deterministic generation of a 50-node statechart finishes in < 200ms."""
    import time

    stages: list[StageSpec] = []
    for i in range(50):
        next_target = f"stage_{i + 1}" if i < 49 else "finish"
        stages.append(
            StageSpec(
                name=f"stage_{i}",
                is_initial=(i == 0),
                tools=[f"tool_{i % 3}"],
                transitions=[TransitionSpec(target=next_target, kind="to")],
            )
        )
    stages.append(
        StageSpec(
            name="finish",
            terminal=True,
            transitions=[TransitionSpec(target="[END]", kind="end")],
        )
    )

    spec = StatechartSpec(
        agent_name="BenchmarkAgent",
        initial_stage="stage_0",
        stages=stages,
    )

    start = time.perf_counter()
    source = generate_python_source(spec)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert len(source) > 0
    assert elapsed_ms < 200.0, f"Generation took {elapsed_ms:.2f}ms (budget: 200.0ms)"

    # Verify extracted topology
    extracted = extract_statechart_from_source(source)
    assert len(extracted.stages) == 51
    assert extracted.initial_stage == "stage_0"


def test_codegen_statechart_spec_convenience_methods() -> None:
    """Verify StatechartSpec methods: to_graph, to_json, to_json_str, and to_source."""
    stage = StageSpec(
        name="start",
        is_initial=True,
        transitions=[TransitionSpec(target="finish", kind="to")],
    )
    finish = StageSpec(name="finish", terminal=True)
    spec = StatechartSpec(
        agent_name="ConvenienceAgent",
        initial_stage="start",
        stages=[stage, finish],
    )

    # 1. to_graph and from_graph classmethod
    g = spec.to_graph()
    assert g.agent_name == "ConvenienceAgent"
    assert "start" in g.stages
    spec_recovered = StatechartSpec.from_graph(g)
    assert spec_recovered.agent_name == "ConvenienceAgent"

    # 2. to_json and to_json_str
    j_dict = spec.to_json()
    assert isinstance(j_dict, dict)
    assert j_dict["agent_name"] == "ConvenienceAgent"
    j_str = spec.to_json_str(indent=4)
    assert isinstance(j_str, str)
    assert "ConvenienceAgent" in j_str

    # 3. from_json classmethod
    spec_from_str = StatechartSpec.from_json(j_str)
    assert spec_from_str.agent_name == "ConvenienceAgent"

    # 4. to_source method
    py_src = spec.to_source()
    assert "class ConvenienceAgent(Agent):" in py_src


@pytest.mark.patent_invariant
def test_codegen_full_cycle_lossless_roundtrip() -> None:
    """Verify complete lossless cycle: Spec -> Source -> Graph -> Spec -> JSON -> Spec -> Source."""
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="base.py")
    spec0 = spec_from_graph(graph0)

    # Spec -> Source 0
    source0 = generate_python_source(spec0)

    # Source 0 -> Graph 1
    graph1 = extract_statechart_from_source(source0, filename="roundtrip1.py")
    assert graph1.agent_name == graph0.agent_name
    assert graph1.initial_stage == graph0.initial_stage
    assert set(graph1.stages.keys()) == set(graph0.stages.keys())

    # Graph 1 -> Spec 1
    spec1 = spec_from_graph(graph1)

    # Spec 1 -> JSON
    json_payload = spec_to_json(spec1)

    # JSON -> Spec 2
    spec2 = spec_from_json(json_payload)
    assert {s.name for s in spec2.stages} == {s.name for s in spec0.stages}

    # Spec 2 -> Source 1
    source1 = generate_python_source(spec2)

    # Source 1 -> Graph 2
    graph2 = extract_statechart_from_source(source1, filename="roundtrip2.py")
    adj2 = graph2.adjacency_list(include_fallbacks=True)
    adj0 = graph0.adjacency_list(include_fallbacks=True)
    assert adj2 == adj0


def test_codegen_stay_and_pop_transitions() -> None:
    """Verify code generation for stay self-loops and digression pop_frame calls."""
    stages = [
        StageSpec(
            name="step_loop",
            is_initial=True,
            transitions=[TransitionSpec(target="step_loop", kind="stay")],
        ),
        StageSpec(
            name="digress_step",
            transitions=[TransitionSpec(target="[POP]", kind="pop")],
        ),
    ]
    spec = StatechartSpec(
        agent_name="StayPopAgent",
        initial_stage="step_loop",
        stages=stages,
    )

    source = generate_python_source(spec)
    assert "return Transition.stay()" in source
    assert "return Transition.pop_frame()" in source

    # Parse with extract_statechart_from_source
    graph = extract_statechart_from_source(source, validate_reachability=False)
    assert "step_loop" in graph.stages
    assert "digress_step" in graph.stages


def test_codegen_type_modes_and_empty_slot_model() -> None:
    """Verify string and simple typing modes, plus empty SlotModel handling."""
    model_empty = SlotModelSpec(name="EmptySlotModel", fields=[])
    stage = StageSpec(
        name="root",
        is_initial=True,
        collect_model="EmptySlotModel",
        transitions=[
            TransitionSpec(target="next_a", kind="to"),
            TransitionSpec(target="next_b", kind="to"),
        ],
    )
    stage_a = StageSpec(name="next_a", terminal=True)
    stage_b = StageSpec(name="next_b", terminal=True)

    spec = StatechartSpec(
        agent_name="TypeModeAgent",
        initial_stage="root",
        stages=[stage, stage_a, stage_b],
        slot_models=[model_empty],
    )

    # 1. Test "string" type mode
    src_string = generate_agent_source(spec, type_mode="string")
    assert 'Transition["next_a" | "next_b"]' in src_string
    assert "class EmptySlotModel(BaseModel):" in src_string
    assert "pass" in src_string

    # 2. Test "simple" type mode
    src_simple = generate_python_source(spec, type_mode="simple")
    assert "Transition[str]" in src_simple


@pytest.mark.patent_invariant
def test_codegen_dominance_assertion_execution_in_namespace() -> None:
    """Verify that generated verify_agent_dominance() executes and returns True."""
    graph0 = extract_statechart_from_source(VALID_AGENT_SOURCE, filename="agent0.py")
    spec0 = from_graph(graph0)

    spec0 = StatechartSpec(
        agent_name=spec0.agent_name,
        initial_stage=spec0.initial_stage,
        description=spec0.description,
        stages=spec0.stages,
        slot_models=spec0.slot_models,
        dominance_assertions=[
            DominanceAssertionSpec(
                precursor="disclosure",
                targets=["settlement"],
                root="disclosure",
            )
        ],
    )

    source = generate_python_source(spec0)
    assert "def verify_agent_dominance(" in source

    # Execute code in clean namespace
    ns: dict[str, Any] = {}
    exec(source, ns)
    assert "CompliantClaimsAgent" in ns
    assert "verify_agent_dominance" in ns
    verifier = ns["verify_agent_dominance"]
    assert callable(verifier)
    result = verifier()
    assert result is True

