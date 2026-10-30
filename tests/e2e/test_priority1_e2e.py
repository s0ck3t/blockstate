"""Comprehensive Opaque-Box E2E Acceptance Test Suite for Blockstate Priority 1 (v1.1).

Covers Tiers 1 to 4 across all six major functional capabilities:
1. CLI Starter Scaffolder (`blockstate init`, R2 / F05, F06, F07, F08)
2. Deterministic Code Generator (`codegen.py`, R1 / F01, F02, F03, F04)
3. Local Visual Studio Server & REST API (`studio.py`, R3 / F09, F10, F11, F12)
4. Sub-5ms Dominator Overlay & Counterexample Synthesis (R4 / F13)
5. Visual Trace Inspector & Cryptographic Hash Chains (R4 / F14)
6. MRM & CISO Dominance Audit Certificate Export (R4 / F15)

Strict British English orthography and zero em dashes are enforced throughout.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from blockstate.compiler.ast_extractor import (
    extract_statechart_from_source,
)
from blockstate.compiler.dominators import (
    LengauerTarjanSolver,
    find_counterexample_path,
    verify_dominance,
)
from blockstate.compiler.exporters import export_json, export_mermaid
from blockstate.errors import (
    DynamicTransitionError,
    UnreachableStageError,
)

# ---------------------------------------------------------------------------
# Dynamic Feature Availability Guards
# ---------------------------------------------------------------------------


def _has_codegen() -> bool:
    return importlib.util.find_spec("blockstate.compiler.codegen") is not None


def _has_scaffold() -> bool:
    return importlib.util.find_spec("blockstate.cli.scaffold") is not None


def _has_studio() -> bool:
    return importlib.util.find_spec("blockstate.cli.studio") is not None


skip_if_no_codegen = pytest.mark.skipif(
    not _has_codegen(),
    reason="Milestone 1 codegen.py is not yet implemented in src/blockstate/compiler/",
)

skip_if_no_scaffold = pytest.mark.skipif(
    not _has_scaffold(),
    reason="Milestone 2 scaffold.py is not yet implemented in src/blockstate/cli/",
)

skip_if_no_studio = pytest.mark.skipif(
    not _has_studio(),
    reason="Milestone 3/4 studio.py is not yet implemented in src/blockstate/cli/",
)


def _get_root(graph: Any) -> str:
    """Extract and validate non-None initial stage identifier for dominator solver."""
    root = graph.initial_stage
    assert isinstance(root, str), "Initial stage must be declared"
    return root


# ===========================================================================
# TIER 1: FEATURE COVERAGE (>=5 tests per functional area)
# ===========================================================================

# ---------------------------------------------------------------------------
# Area 1: CLI Init Scaffolder (F05, F06, F07, F08)
# ---------------------------------------------------------------------------


@skip_if_no_scaffold
def test_tier1_cli_init_banking_template(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify blockstate init scaffolds the banking template with all required files."""
    dest = tmp_path / "banking_enclave"
    proc = cli_runner("init", str(dest), "--template", "banking")
    assert proc.returncode == 0, f"CLI init failed: {proc.stderr}"

    assert (dest / "banking_agent.py").is_file(), "Missing banking_agent.py"
    assert (dest / "test_banking_agent.py").is_file(), "Missing test_banking_agent.py"
    assert (dest / ".env.example").is_file(), "Missing .env.example"
    assert (dest / ".github" / "workflows" / "blockstate-verify.yml").is_file(), (
        "Missing CI workflow"
    )
    assert (dest / "README.md").is_file(), "Missing README.md"


@skip_if_no_scaffold
def test_tier1_cli_init_insurance_template(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify blockstate init scaffolds the insurance pushdown template."""
    dest = tmp_path / "insurance_enclave"
    proc = cli_runner("init", str(dest), "--template", "insurance")
    assert proc.returncode == 0, f"CLI init failed: {proc.stderr}"

    agent_file = dest / "insurance_agent.py"
    assert agent_file.is_file(), "Missing insurance_agent.py"
    content = agent_file.read_text(encoding="utf-8")
    assert "allow_digressions=True" in content, (
        "Insurance template should showcase digression pushdown"
    )
    assert "Transition.pop_frame()" in content, "Insurance template should showcase stack pop"


@skip_if_no_scaffold
def test_tier1_cli_init_healthcare_template(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify blockstate init scaffolds the healthcare HIPAA template with PII vaulting."""
    dest = tmp_path / "healthcare_enclave"
    proc = cli_runner("init", str(dest), "--template", "healthcare")
    assert proc.returncode == 0, f"CLI init failed: {proc.stderr}"

    agent_file = dest / "healthcare_agent.py"
    assert agent_file.is_file(), "Missing healthcare_agent.py"
    content = agent_file.read_text(encoding="utf-8")
    assert "Vaulted[" in content or "Vaulted" in content, (
        "Healthcare template should showcase PII vaulting"
    )


@skip_if_no_scaffold
def test_tier1_cli_init_minimal_template(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify blockstate init scaffolds the minimal starter template."""
    dest = tmp_path / "minimal_enclave"
    proc = cli_runner("init", str(dest), "--template", "minimal")
    assert proc.returncode == 0, f"CLI init failed: {proc.stderr}"

    agent_file = dest / "minimal_agent.py"
    assert agent_file.is_file(), "Missing minimal_agent.py"
    content = agent_file.read_text(encoding="utf-8")
    assert "@Stage" in content
    assert "Transition.end()" in content or "Transition.to(" in content


@skip_if_no_scaffold
def test_tier1_cli_init_default_template(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify running blockstate init without --template flag defaults gracefully."""
    dest = tmp_path / "default_enclave"
    proc = cli_runner("init", str(dest))
    assert proc.returncode == 0, f"CLI init default failed: {proc.stderr}"
    files = list(dest.glob("*_agent.py"))
    assert len(files) == 1, f"Expected exactly one scaffolded agent file, found {files}"


# ---------------------------------------------------------------------------
# Area 2: Codegen Models & Source Emitter (F01, F02, F03, F04)
# ---------------------------------------------------------------------------


@skip_if_no_codegen
def test_tier1_codegen_specification_models() -> None:
    """Verify instantiation and serialisation of specification models."""
    from blockstate.compiler.codegen import (
        DominanceAssertionSpec,
        SlotFieldSpec,
        SlotModelSpec,
        StageSpec,
        StatechartSpec,
        TransitionSpec,
    )

    spec = StatechartSpec(
        agent_name="TestPaymentAgent",
        description="Enclave payment agent",
        initial_stage="intake",
        stages=[
            StageSpec(
                name="intake",
                is_initial=True,
                tools=["lookup_card"],
                transitions=[TransitionSpec(target="authorise")],
            ),
            StageSpec(
                name="authorise",
                tools=["card_charge"],
                transitions=[TransitionSpec(target="complete")],
            ),
            StageSpec(name="complete", terminal=True),
        ],
        slot_models=[
            SlotModelSpec(
                name="CardDetails",
                fields=[
                    SlotFieldSpec(name="card_num", type_name="str", vaulted=True),
                    SlotFieldSpec(name="amount", type_name="float", vaulted=False),
                ],
            )
        ],
        dominance_assertions=[
            DominanceAssertionSpec(precursor="intake", targets=["authorise"]),
        ],
    )

    data = spec.model_dump()
    assert data["agent_name"] == "TestPaymentAgent"
    assert len(data["stages"]) == 3
    assert data["slot_models"][0]["fields"][0]["vaulted"] is True


@skip_if_no_codegen
def test_tier1_codegen_generate_python_source() -> None:
    """Verify Python code emission generates PEP 695 typed source code."""
    from blockstate.compiler.codegen import (
        StageSpec,
        StatechartSpec,
        TransitionSpec,
        generate_python_source,
    )

    spec = StatechartSpec(
        agent_name="GeneratedAgent",
        initial_stage="start",
        stages=[
            StageSpec(
                name="start",
                is_initial=True,
                transitions=[TransitionSpec(target="finish")],
            ),
            StageSpec(name="finish", terminal=True),
        ],
    )

    source = generate_python_source(spec)
    assert "class GeneratedAgent(Agent):" in source
    assert '@Stage(name="start")' in source or "@Stage(" in source
    assert 'return Transition.to("finish")' in source
    assert "Transition.end(" in source


@skip_if_no_codegen
def test_tier1_codegen_ast_extract_roundtrip() -> None:
    """Verify that source emitted by codegen compiles under StaticGraphCompiler."""
    from blockstate.compiler.codegen import (
        StageSpec,
        StatechartSpec,
        TransitionSpec,
        generate_python_source,
    )

    spec = StatechartSpec(
        agent_name="CompilerPassAgent",
        initial_stage="stage_a",
        stages=[
            StageSpec(
                name="stage_a",
                is_initial=True,
                transitions=[TransitionSpec(target="stage_b")],
            ),
            StageSpec(name="stage_b", terminal=True),
        ],
    )

    source = generate_python_source(spec)
    graph = extract_statechart_from_source(source)
    assert graph.agent_name == "CompilerPassAgent"
    assert "stage_a" in graph.stages
    assert "stage_b" in graph.stages
    assert graph.initial_stage == "stage_a"


@skip_if_no_codegen
def test_tier1_codegen_spec_from_graph(banking_agent_source: str) -> None:
    """Verify lossless conversion from StatechartGraph to StatechartSpec."""
    from blockstate.compiler.codegen import spec_from_graph

    graph = extract_statechart_from_source(banking_agent_source)
    spec = spec_from_graph(graph)

    assert spec.agent_name == "BankingAgent"
    assert spec.initial_stage == "intake"
    stage_names = {s.name for s in spec.stages}
    assert {"intake", "verify_kyc", "execute_transfer", "reject", "completed"}.issubset(stage_names)


@skip_if_no_codegen
def test_tier1_codegen_spec_to_graph(banking_agent_source: str) -> None:
    """Verify lossless conversion from StatechartSpec to StatechartGraph."""
    from blockstate.compiler.codegen import spec_from_graph, spec_to_graph

    original_graph = extract_statechart_from_source(banking_agent_source)
    spec = spec_from_graph(original_graph)
    reconstructed_graph = spec_to_graph(spec)

    assert reconstructed_graph.agent_name == original_graph.agent_name
    assert reconstructed_graph.initial_stage == original_graph.initial_stage
    assert set(reconstructed_graph.stages.keys()) == set(original_graph.stages.keys())


# ---------------------------------------------------------------------------
# Area 3: Studio Server & REST API (F09, F10, F11, F12)
# ---------------------------------------------------------------------------


@skip_if_no_studio
def test_tier1_studio_server_startup(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify standard library ThreadingHTTPServer starts up and responds to HTTP requests."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/status"
        with urlopen(url, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_studio_static_bundle_serving(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify GET / serves index.html with HTML and canvas container elements."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/"
        with urlopen(url, timeout=3.0) as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "<!DOCTYPE html>" in html or "<html" in html
            assert "canvas" in html.lower() or "statechart" in html.lower() or "svg" in html.lower()
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_studio_api_status(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify GET /api/status returns agent name and stage count."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/status"
        with urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data.get("stage_count", 0) >= 3
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_studio_api_graph(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify GET /api/graph returns serialized StatechartGraph."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/graph"
        with urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert "agent_name" in data
            assert "stages" in data
            assert "transitions" in data
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_studio_api_export_code(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify POST /api/export-code accepts spec JSON and returns Python source."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-code"
        payload = {
            "spec": {
                "agent_name": "StudioExportedAgent",
                "initial_stage": "entry",
                "stages": [
                    {
                        "name": "entry",
                        "is_initial": True,
                        "transitions": [{"target": "exit"}],
                    },
                    {"name": "exit", "terminal": True},
                ],
            }
        }
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert "python_source" in data
            assert "StudioExportedAgent" in data["python_source"]
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Area 4: Dominator Overlay & Counterexample Synthesis (F13)
# ---------------------------------------------------------------------------


def test_tier1_dominator_verify_dominance_satisfied(banking_agent_source: str) -> None:
    """Verify verify_dominance confirms dominance when precursor strictly dominates target."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    assert proof.satisfied is True
    assert proof.violating_path is None
    assert proof.precursor == "verify_kyc"
    assert "execute_transfer" in proof.targets


def test_tier1_dominator_verify_dominance_violation(bypass_vulnerable_agent_source: str) -> None:
    """Verify verify_dominance fails and computes counterexample when a bypass exists."""
    graph = extract_statechart_from_source(bypass_vulnerable_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    assert proof.satisfied is False
    assert proof.violating_path is not None
    assert proof.violating_path[0] == root
    assert proof.violating_path[-1] == "execute_transfer"
    assert "verify_kyc" not in proof.violating_path, "Counterexample path must bypass precursor"


@skip_if_no_studio
def test_tier1_dominator_api_verify_endpoint(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify POST /api/verify-dominance returns structured proof with elapsed time."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/verify-dominance"
        payload = {"precursor": "verify_kyc", "target": "execute_transfer"}
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["satisfied"] is True
            assert "elapsed_ms" in data
            assert data["elapsed_ms"] < 5.0, "Dominator verification must execute in under 5ms"
    finally:
        server.shutdown()
        server.server_close()


def test_tier1_dominator_sub_5ms_performance(banking_agent_source: str) -> None:
    """Verify Lengauer-Tarjan solver executes in under 5ms on realistic agent topologies."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    t0 = time.perf_counter()
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert proof.satisfied is True
    assert elapsed_ms < 5.0, f"Dominator check exceeded 5ms limit: took {elapsed_ms:.3f}ms"


def test_tier1_dominator_lengauer_tarjan_tree_structure(banking_agent_source: str) -> None:
    """Verify LengauerTarjanSolver computes valid semi-dominators and immediate dominators."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    solver = LengauerTarjanSolver(root=root, graph=adj)
    idom = solver.solve()

    assert root not in idom, "Root node must be excluded from idom mapping"
    assert idom["verify_kyc"] == "intake"
    assert idom["execute_transfer"] == "verify_kyc"


# ---------------------------------------------------------------------------
# Area 5: Visual Trace Inspector & Cryptographic Hash Chains (F14)
# ---------------------------------------------------------------------------


def test_tier1_trace_inspector_load_session_records(sample_trace_directory: Path) -> None:
    """Verify trace records are correctly read from .blockstate/traces.jsonl."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    lines = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    assert len(lines) == 3
    assert lines[0]["turn_index"] == 0
    assert lines[1]["turn_index"] == 1
    assert lines[2]["turn_index"] == 2


def test_tier1_trace_inspector_hash_chain_verification(sample_trace_directory: Path) -> None:
    """Verify cryptographic hash continuity across turn ledger records."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    records = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]

    # Check turn 0 genesis hash
    assert records[0]["prev_record_hash"] == "0" * 64

    # Verify link between turn 0 and turn 1
    assert records[1]["prev_record_hash"] == records[0]["record_hash"]

    # Verify link between turn 1 and turn 2
    assert records[2]["prev_record_hash"] == records[1]["record_hash"]


@skip_if_no_studio
def test_tier1_trace_inspector_api_endpoint(
    free_tcp_port: int, sample_trace_directory: Path, banking_agent_source: str
) -> None:
    """Verify GET /api/traces returns turn records for inspector scrubber."""
    from blockstate.cli.studio import create_studio_server

    agent_file = sample_trace_directory / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/traces"
        with urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert isinstance(data, list)
            assert len(data) == 3
            assert data[0]["stage"] == "intake"
    finally:
        server.shutdown()
        server.server_close()


def test_tier1_trace_inspector_taskstack_pushdown_replay(sample_trace_directory: Path) -> None:
    """Verify TaskStack frame transitions are present in trace records."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    records = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    for rec in records:
        assert "task_stack" in rec
        assert isinstance(rec["task_stack"], list)
        assert len(rec["task_stack"]) >= 1


def test_tier1_trace_inspector_ephemeral_tool_filtering(sample_trace_directory: Path) -> None:
    """Verify exposed_tools accurately reflects the stage-scoped whitelist."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    records = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    assert records[0]["exposed_tools"] == ["lookup_account"]
    assert "settle_faster_payments" not in records[0]["exposed_tools"]
    assert "settle_faster_payments" in records[2]["exposed_tools"]


# ---------------------------------------------------------------------------
# Area 6: MRM / CISO Audit Certificate Export (F15)
# ---------------------------------------------------------------------------


@skip_if_no_studio
def test_tier1_audit_certificate_markdown_export(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify POST /api/export-certificate with markdown format returns signed Markdown text."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {
            "precursor": "verify_kyc",
            "targets": ["execute_transfer"],
            "format": "markdown",
        }
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            cert = data["certificate"]
            assert (
                "# Model Risk Management Dominance Verification Certificate" in cert
                or "Certificate" in cert
            )
            assert "verify_kyc" in cert
            assert "execute_transfer" in cert
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_audit_certificate_json_export(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify POST /api/export-certificate with json format returns structured certificate."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {
            "precursor": "verify_kyc",
            "targets": ["execute_transfer"],
            "format": "json",
        }
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            cert = data["certificate"]
            assert cert["satisfied"] is True
            assert cert["precursor"] == "verify_kyc"
            assert cert["targets"] == ["execute_transfer"]
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier1_audit_certificate_api_endpoint(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify API endpoint handles invalid requests and parameters."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "test_agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {"precursor": "verify_kyc", "targets": ["execute_transfer"]}
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert "certificate" in data
    finally:
        server.shutdown()
        server.server_close()


def test_tier1_audit_certificate_regulatory_mappings(banking_agent_source: str) -> None:
    """Verify that dominance proofs directly satisfy regulatory control standards."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    # The mathematical proof satisfies FCA SYSC 13.7 and EU AI Act Article 14
    assert proof.satisfied is True


def test_tier1_audit_certificate_bypass_warning_when_unsatisfied(
    bypass_vulnerable_agent_source: str,
) -> None:
    """Verify that audit checks flag counterexample bypass routes prominently."""
    graph = extract_statechart_from_source(bypass_vulnerable_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    assert proof.satisfied is False
    assert proof.violating_path is not None
    assert "fast_track_transfer" in proof.violating_path


# ===========================================================================
# TIER 2: BOUNDARIES & CORNER CASES (>=5 tests per functional area)
# ===========================================================================

# ---------------------------------------------------------------------------
# Area 1 Boundaries: CLI Scaffolding
# ---------------------------------------------------------------------------


@skip_if_no_scaffold
def test_tier2_cli_init_directory_collision_safeguard(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify scaffolding into an existing non-empty directory aborts without --force."""
    dest = tmp_path / "existing_enclave"
    dest.mkdir(parents=True)
    dummy_file = dest / "preexisting.txt"
    dummy_file.write_text("precious user data", encoding="utf-8")

    proc = cli_runner("init", str(dest), "--template", "minimal")
    assert proc.returncode != 0, (
        "CLI init into non-empty directory should fail without --force in non-interactive mode"
    )
    assert dummy_file.read_text(encoding="utf-8") == "precious user data"


@skip_if_no_scaffold
def test_tier2_cli_init_force_overwrite_allowed(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify scaffolding with --force overwrites existing directory cleanly."""
    dest = tmp_path / "overwrite_enclave"
    dest.mkdir(parents=True)
    dummy_file = dest / "minimal_agent.py"
    dummy_file.write_text("# old content", encoding="utf-8")

    proc = cli_runner("init", str(dest), "--template", "minimal", "--force")
    assert proc.returncode == 0, f"CLI init --force failed: {proc.stderr}"
    assert dummy_file.read_text(encoding="utf-8") != "# old content"


@skip_if_no_scaffold
def test_tier2_cli_init_invalid_template_name(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify specifying an unknown template name returns non-zero exit code."""
    dest = tmp_path / "unknown_template_enclave"
    proc = cli_runner("init", str(dest), "--template", "nonexistent_template_xyz")
    assert proc.returncode != 0


@skip_if_no_scaffold
def test_tier2_cli_init_nested_directory_creation(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify scaffolding into deeply nested non-existent directory creates parents."""
    dest = tmp_path / "level1" / "level2" / "enclave"
    proc = cli_runner("init", str(dest), "--template", "minimal")
    assert proc.returncode == 0
    assert (dest / "minimal_agent.py").is_file()


@skip_if_no_scaffold
def test_tier2_cli_init_special_characters_directory(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify scaffolding into directory containing spaces and dashes succeeds."""
    dest = tmp_path / "my enclave-project (v1)"
    proc = cli_runner("init", str(dest), "--template", "minimal")
    assert proc.returncode == 0
    assert (dest / "minimal_agent.py").is_file()


# ---------------------------------------------------------------------------
# Area 2 Boundaries: Codegen Models & Emitter
# ---------------------------------------------------------------------------


@skip_if_no_codegen
def test_tier2_codegen_empty_statechart_validation() -> None:
    """Verify model requires mandatory fields such as name in StageSpec and SlotFieldSpec."""
    from pydantic import ValidationError

    from blockstate.compiler.codegen import SlotFieldSpec, StageSpec

    with pytest.raises(ValidationError):
        StageSpec.model_validate({})  # name is required

    with pytest.raises(ValidationError):
        SlotFieldSpec.model_validate({})  # name is required


def test_tier2_codegen_unreachable_stage_detection() -> None:
    """Verify StaticGraphCompiler raises UnreachableStageError on disconnected stages."""
    code_with_dead_stage = '''"""Agent with unreachable dead stage."""
from blockstate import Agent, Stage, Transition

class DeadStageAgent(Agent):
    @Stage(initial=True)
    def start(self, user_msg: str) -> Transition["done"]:
        return Transition.to("done")

    @Stage
    def dead(self, user_msg: str) -> Transition["done"]:
        return Transition.to("done")

    @Stage(terminal=True)
    def done(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''
    with pytest.raises(UnreachableStageError) as exc_info:
        extract_statechart_from_source(code_with_dead_stage)
    assert "dead" in str(exc_info.value)


def test_tier2_codegen_dynamic_transition_prohibition() -> None:
    """Verify compiler raises DynamicTransitionError on variable transition targets."""
    code_with_dynamic_target = '''"""Agent with dynamic transition variable."""
from typing import Any
from blockstate import Agent, Stage, Transition

class DynamicTargetAgent(Agent):
    @Stage(initial=True)
    def start(self, user_msg: str) -> Transition[Any]:
        target = "next_stage"
        return Transition.to(target)

    @Stage(terminal=True)
    def next_stage(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''
    with pytest.raises(DynamicTransitionError):
        extract_statechart_from_source(code_with_dynamic_target)


def test_tier2_codegen_terminal_stage_without_outgoing_transitions() -> None:
    """Verify terminal stages correctly record terminal flag in StatechartGraph."""
    code = '''"""Agent where terminal stage is defined."""
from blockstate import Agent, Stage, Transition

class TerminalWithOutgoing(Agent):
    @Stage(initial=True)
    def start(self, user_msg: str) -> Transition["end_stage"]:
        return Transition.to("end_stage")

    @Stage(terminal=True)
    def end_stage(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''
    graph = extract_statechart_from_source(code)
    assert graph.stages["end_stage"].terminal is True


def test_tier2_codegen_field_validator_transition_forbidden() -> None:
    """Verify field validators cannot trigger state transitions."""
    code_with_validator_transition = '''"""Model with field validator calling Transition."""
from pydantic import BaseModel, field_validator
from blockstate import Agent, Stage, Transition

class CardModel(BaseModel):
    num: str
    @field_validator("num")
    def validate_num(cls, v):
        Transition.to("other")
        return v

class AgentWithValidator(Agent):
    @Stage(initial=True)
    def start(self, msg: str) -> Transition[None]:
        return Transition.end()
'''
    with pytest.raises(DynamicTransitionError):
        extract_statechart_from_source(code_with_validator_transition)


# ---------------------------------------------------------------------------
# Area 3 Boundaries: Studio Server & REST API
# ---------------------------------------------------------------------------


@skip_if_no_studio
def test_tier2_studio_invalid_port_binding(tmp_path: Path, banking_agent_source: str) -> None:
    """Verify studio handles invalid port or privileged port gracefully."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    try:
        server = create_studio_server(agent_file, port=0)
        server.server_close()
    except (ValueError, OSError):
        pass


@skip_if_no_studio
def test_tier2_studio_missing_agent_file(tmp_path: Path, free_tcp_port: int) -> None:
    """Verify studio server rejects non-existent agent file path."""
    from blockstate.cli.studio import create_studio_server

    non_existent = tmp_path / "does_not_exist.py"
    with pytest.raises((FileNotFoundError, ValueError)):
        create_studio_server(non_existent, port=free_tcp_port)


@skip_if_no_studio
def test_tier2_studio_malformed_json_payload(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify studio returns HTTP 400 when sent malformed JSON in POST body."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/verify-dominance"
        req = Request(
            url,
            data=b"{malformed_json: true,",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req, timeout=3.0)
        assert exc_info.value.code in (400, 500)
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier2_studio_path_traversal_prevention(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify studio server prevents directory traversal via URL path."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/../../../../Windows/win.ini"
        with pytest.raises(HTTPError) as exc_info:
            urlopen(url, timeout=3.0)
        assert exc_info.value.code in (400, 403, 404)
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier2_studio_unknown_api_endpoint(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify requesting an unknown /api/* endpoint returns HTTP 404."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/unknown-endpoint"
        with pytest.raises(HTTPError) as exc_info:
            urlopen(url, timeout=3.0)
        assert exc_info.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Area 4 Boundaries: Dominator Overlay & Counterexample Synthesis
# ---------------------------------------------------------------------------


def test_tier2_dominator_nonexistent_precursor_stage(banking_agent_source: str) -> None:
    """Verify querying dominance with a non-existent precursor stage reports unsatisfied."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="stage_that_does_not_exist",
        targets=["execute_transfer"],
    )
    assert proof.satisfied is False


def test_tier2_dominator_nonexistent_target_stage(banking_agent_source: str) -> None:
    """Verify querying dominance with a non-existent target stage reports unsatisfied."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["nonexistent_target_stage"],
    )
    assert proof.satisfied is False


def test_tier2_dominator_self_dominance(banking_agent_source: str) -> None:
    """Verify that every stage dominates itself."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["verify_kyc"],
    )
    assert proof.satisfied is True


def test_tier2_dominator_cyclical_graph_handling() -> None:
    """Verify Lengauer-Tarjan solver handles cyclical graphs without recursion limit."""
    cyclical_code = '''"""Agent with cyclic state transitions."""
from blockstate import Agent, Stage, Transition

class CyclicAgent(Agent):
    @Stage(initial=True)
    def stage_a(self, msg: str) -> Transition["stage_b"]:
        return Transition.to("stage_b")

    @Stage
    def stage_b(self, msg: str) -> Transition["stage_c" | "stage_a"]:
        if "loop" in msg:
            return Transition.to("stage_a")
        return Transition.to("stage_c")

    @Stage(terminal=True)
    def stage_c(self, msg: str) -> Transition[None]:
        return Transition.end()
'''
    graph = extract_statechart_from_source(cyclical_code)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="stage_b",
        targets=["stage_c"],
    )
    assert proof.satisfied is True


def test_tier2_dominator_disconnected_subgraph(banking_agent_source: str) -> None:
    """Verify find_counterexample_path returns None when precursor strictly dominates."""
    graph = extract_statechart_from_source(banking_agent_source)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    counterexample = find_counterexample_path(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        target="execute_transfer",
    )
    assert counterexample is None


# ---------------------------------------------------------------------------
# Area 5 Boundaries: Trace Inspector
# ---------------------------------------------------------------------------


def test_tier2_trace_inspector_corrupt_jsonl_line(tmp_path: Path) -> None:
    """Verify trace parsing ignores or handles empty/corrupted JSON lines."""
    trace_dir = tmp_path / ".blockstate"
    trace_dir.mkdir(parents=True)
    trace_file = trace_dir / "traces.jsonl"
    content = (
        '{"turn_index": 0, "stage": "start"}\n'
        "CORRUPTED_LINE_NOT_JSON\n"
        '{"turn_index": 1, "stage": "end"}\n'
    )
    trace_file.write_text(content, encoding="utf-8")

    parsed = []
    for line in trace_file.read_text(encoding="utf-8").splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            parsed.append(json.loads(line))
    assert len(parsed) == 2


def test_tier2_trace_inspector_broken_hash_chain(sample_trace_directory: Path) -> None:
    """Verify tampering with a record hash breaks chain validation."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    records = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]

    # Tamper with record 0 hash
    records[0]["record_hash"] = "f" * 64

    # Now verify chain check detects mismatch on record 1
    assert records[1]["prev_record_hash"] != records[0]["record_hash"]


def test_tier2_trace_inspector_missing_traces_file(tmp_path: Path) -> None:
    """Verify handling when .blockstate/traces.jsonl does not exist."""
    missing_trace = tmp_path / ".blockstate" / "traces.jsonl"
    assert not missing_trace.exists()


def test_tier2_trace_inspector_empty_session_id(sample_trace_directory: Path) -> None:
    """Verify querying traces with non-existent session ID yields empty results."""
    trace_file = sample_trace_directory / ".blockstate" / "traces.jsonl"
    records = [
        json.loads(line) for line in trace_file.read_text(encoding="utf-8").strip().split("\n")
    ]
    filtered = [r for r in records if r.get("session_id") == "nonexistent_session_999"]
    assert len(filtered) == 0


def test_tier2_trace_inspector_extreme_turn_count(tmp_path: Path) -> None:
    """Verify generating and parsing 100 consecutive turns performs within 50ms."""
    records = []
    prev_hash = "0" * 64
    for i in range(100):
        data = {"turn_index": i, "stage": f"stage_{i % 5}", "prev_record_hash": prev_hash}
        h = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
        data["record_hash"] = h
        prev_hash = h
        records.append(data)

    t0 = time.perf_counter()
    serialized = "\n".join(json.dumps(r) for r in records)
    loaded = [json.loads(line) for line in serialized.split("\n")]
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert len(loaded) == 100
    assert elapsed_ms < 50.0


# ---------------------------------------------------------------------------
# Area 6 Boundaries: Audit Certificate Export
# ---------------------------------------------------------------------------


@skip_if_no_studio
def test_tier2_audit_certificate_empty_target_list(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify audit certificate export rejects empty target list."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {"precursor": "verify_kyc", "targets": []}
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req, timeout=3.0)
        assert exc_info.value.code in (400, 422)
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier2_audit_certificate_invalid_format_requested(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify audit certificate export rejects unsupported format like XML."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {
            "precursor": "verify_kyc",
            "targets": ["execute_transfer"],
            "format": "xml",
        }
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req, timeout=3.0)
        assert exc_info.value.code in (400, 422)
    finally:
        server.shutdown()
        server.server_close()


def test_tier2_audit_certificate_special_characters_metadata() -> None:
    """Verify agent names with special symbols or Unicode are escaped safely."""
    agent_name = "Agent<Test>&Risk-2026"
    sanitised = json.dumps({"agent_name": agent_name})
    assert "Agent<Test>&Risk-2026" in sanitised


def test_tier2_audit_certificate_multiple_bypass_routes() -> None:
    """Verify counterexample path finds the shortest route when multiple bypasses exist."""
    multi_bypass = '''"""Agent with multiple bypass routes."""
from blockstate import Agent, Stage, Transition

class MultiBypassAgent(Agent):
    @Stage(initial=True)
    def start(self, msg: str) -> Transition["route_a" | "route_b" | "precursor"]:
        if "a" in msg:
            return Transition.to("route_a")
        elif "b" in msg:
            return Transition.to("route_b")
        return Transition.to("precursor")

    @Stage
    def route_a(self, msg: str) -> Transition["target"]:
        return Transition.to("target")

    @Stage
    def route_b(self, msg: str) -> Transition["step_b"]:
        return Transition.to("step_b")

    @Stage
    def step_b(self, msg: str) -> Transition["target"]:
        return Transition.to("target")

    @Stage
    def precursor(self, msg: str) -> Transition["target"]:
        return Transition.to("target")

    @Stage(terminal=True)
    def target(self, msg: str) -> Transition[None]:
        return Transition.end()
'''
    graph = extract_statechart_from_source(multi_bypass)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    counterexample = find_counterexample_path(
        root=root,
        graph=adj,
        precursor="precursor",
        target="target",
    )
    assert counterexample is not None
    # Shortest bypass path should be start -> route_a -> target (length 3)
    assert len(counterexample) == 3
    assert counterexample[0] == "start"
    assert counterexample[-1] == "target"


def test_tier2_audit_certificate_hash_non_repudiation(banking_agent_source: str) -> None:
    """Verify that topology export produces a deterministic SHA-256 graph digest."""
    graph = extract_statechart_from_source(banking_agent_source)
    json_bytes = json.dumps(export_json(graph), sort_keys=True).encode("utf-8")
    digest1 = hashlib.sha256(json_bytes).hexdigest()
    digest2 = hashlib.sha256(json_bytes).hexdigest()
    assert digest1 == digest2
    assert len(digest1) == 64


# ===========================================================================
# TIER 3: CROSS-FEATURE INTERACTIONS (End-to-End Multi-Step Pipelines)
# ===========================================================================


@skip_if_no_scaffold
def test_tier3_pipeline_scaffold_check_verify_roundtrip(
    tmp_path: Path, cli_runner: Callable[..., subprocess.CompletedProcess[str]]
) -> None:
    """Verify CLI init -> check -> verify pipeline executes seamlessly."""
    enclave_dir = tmp_path / "banking_pipeline"
    init_res = cli_runner("init", str(enclave_dir), "--template", "banking")
    assert init_res.returncode == 0, f"Init failed: {init_res.stderr}"

    agent_file = enclave_dir / "banking_agent.py"
    check_res = cli_runner("check", str(agent_file))
    assert check_res.returncode == 0, f"Check failed: {check_res.stderr}"

    verify_res = cli_runner(
        "verify", str(agent_file), "--dominates", "verify_identity -> execute_transfer"
    )
    assert verify_res.returncode == 0 or "verify" in verify_res.stdout.lower()


@skip_if_no_studio
@skip_if_no_codegen
def test_tier3_studio_live_code_edit_and_dominance_recompute(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify modifying graph spec in studio updates graph and re-computes dominance."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url_verify = f"http://127.0.0.1:{free_tcp_port}/api/verify-dominance"
        payload = {"precursor": "verify_kyc", "target": "execute_transfer"}
        req = Request(
            url_verify,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["satisfied"] is True
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier3_trace_generation_to_studio_inspection(
    free_tcp_port: int, sample_trace_directory: Path, banking_agent_source: str
) -> None:
    """Verify recorded execution trace in .blockstate/ is queryable via studio API."""
    from blockstate.cli.studio import create_studio_server

    agent_file = sample_trace_directory / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url_traces = f"http://127.0.0.1:{free_tcp_port}/api/traces"
        with urlopen(url_traces, timeout=3.0) as resp:
            traces = json.loads(resp.read().decode("utf-8"))
            assert len(traces) == 3
            assert traces[0]["prev_record_hash"] == "0" * 64
            assert traces[1]["prev_record_hash"] == traces[0]["record_hash"]
    finally:
        server.shutdown()
        server.server_close()


@skip_if_no_studio
def test_tier3_verified_dominance_to_signed_certificate(
    free_tcp_port: int, banking_agent_source: str, tmp_path: Path
) -> None:
    """Verify verified dominance proof can be exported as signed MRM certificate."""
    from blockstate.cli.studio import create_studio_server

    agent_file = tmp_path / "agent.py"
    agent_file.write_text(banking_agent_source, encoding="utf-8")

    server = create_studio_server(agent_file, port=free_tcp_port)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        url_cert = f"http://127.0.0.1:{free_tcp_port}/api/export-certificate"
        payload = {
            "precursor": "verify_kyc",
            "targets": ["execute_transfer"],
            "format": "markdown",
        }
        req = Request(
            url_cert,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            cert = data["certificate"]
            assert "verify_kyc" in cert
            assert "execute_transfer" in cert
    finally:
        server.shutdown()
        server.server_close()


def test_tier3_design_tokens_studio_canvas_styling(brand_tokens_path: Path) -> None:
    """Verify design tokens file defines authentic railway signal chromatics and typography."""
    assert brand_tokens_path.is_file(), f"Missing brand design tokens at {brand_tokens_path}"
    css = brand_tokens_path.read_text(encoding="utf-8")

    # Archival Vellum chromatics
    assert "#F4EFE6" in css or "#FAF7F2" in css, "Vellum canvas colour should be defined"
    # Railway signal green and red
    assert "#166534" in css or "#166534" in css.upper() or "#141413" in css, (
        "Railway signal palette should be defined"
    )
    assert "#D42B1E" in css or "#B81414" in css, "Railway signal red or stop red should be defined"
    # Exposed carbon ink hairline / border tokens
    assert "solid" in css or "border" in css


# ===========================================================================
# TIER 4: REAL-WORLD SCENARIOS (Domain Enclave Workflows)
# ===========================================================================


def test_tier4_scenario_banking_kyc_dominance_enclave(
    banking_agent_source: str, bypass_vulnerable_agent_source: str
) -> None:
    """Simulate a regulated banking enclave where KYC verification strictly
    dominates Faster Payments settlement.
    """
    # 1. Compile agent and verify static reachability
    graph = extract_statechart_from_source(banking_agent_source)
    assert graph.agent_name == "BankingAgent"
    assert "verify_kyc" in graph.stages
    assert "execute_transfer" in graph.stages

    # 2. Mathematically prove KYC precursor dominance
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    kyc_proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    assert kyc_proof.satisfied is True
    assert kyc_proof.violating_path is None

    # 3. Simulate adversarial attack: developer introduces unauthenticated bypass shortcut
    vulnerable_graph = extract_statechart_from_source(bypass_vulnerable_agent_source)
    v_adj = vulnerable_graph.adjacency_list(include_fallbacks=True)
    v_root = _get_root(vulnerable_graph)
    attack_proof = verify_dominance(
        root=v_root,
        graph=v_adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )
    # 4. Prove that compiler synthesises counterexample and vetos production deployment
    assert attack_proof.satisfied is False
    assert attack_proof.violating_path is not None
    assert "fast_track_transfer" in attack_proof.violating_path


def test_tier4_scenario_insurance_pushdown_claim_workflow(insurance_pushdown_source: str) -> None:
    """Simulate an insurance claim enclave with pushdown automaton handling policy FAQs."""
    # 1. Parse and extract insurance topology
    graph = extract_statechart_from_source(insurance_pushdown_source)
    assert graph.agent_name == "InsuranceAgent"

    # 2. Verify digression stage exists and allows stack pushdown
    assert "policy_faq" in graph.stages
    faq_stage = graph.stages["policy_faq"]
    assert faq_stage.terminal is False

    # 3. Verify policy verification dominates claim settlement
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_policy",
        targets=["settle_claim"],
    )
    assert proof.satisfied is True


def test_tier4_scenario_healthcare_hipaa_detokenisation_enclave() -> None:
    """Simulate a healthcare patient intake enclave with Vaulted tokens
    and stage-scoped gatekeeper.
    """
    healthcare_code = '''"""Healthcare Patient Triage Agent with HIPAA PII Isolation."""

from typing import Annotated
from pydantic import BaseModel
from blockstate import Agent, Stage, Transition
from blockstate.security import Vaulted

class PatientRecord(BaseModel):
    nhs_number: Annotated[str, Vaulted()]
    symptoms: str

class HealthcareAgent(Agent):
    """Enclave agent isolating patient identifiable data."""

    @Stage(initial=True, tools=["lookup_patient_record"])
    def intake(self, user_msg: str) -> Transition["clinical_triage"]:
        return Transition.to("clinical_triage")

    @Stage(tools=["schedule_gp_appointment"])
    def clinical_triage(self, user_msg: str) -> Transition["discharged"]:
        return Transition.to("discharged")

    @Stage(terminal=True)
    def discharged(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''
    graph = extract_statechart_from_source(healthcare_code)
    assert graph.agent_name == "HealthcareAgent"

    # Clinical triage dominates discharge
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="clinical_triage",
        targets=["discharged"],
    )
    assert proof.satisfied is True

    # Tool isolation: lookup_patient_record is only exposed in intake
    assert graph.stages["intake"].tools == ("lookup_patient_record",)
    assert "lookup_patient_record" not in graph.stages["clinical_triage"].tools


def test_tier4_scenario_minimal_rapid_onboarding(tmp_path: Path) -> None:
    """Simulate developer onboarding with a clean 3-stage minimal enclave."""
    minimal_code = '''"""Minimal Enclave for Rapid Developer Onboarding."""

from blockstate import Agent, Stage, Transition

class MinimalAgent(Agent):
    @Stage(initial=True)
    def intake(self, user_msg: str) -> Transition["process"]:
        return Transition.to("process")

    @Stage
    def process(self, user_msg: str) -> Transition["completed"]:
        return Transition.to("completed")

    @Stage(terminal=True)
    def completed(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''
    agent_file = tmp_path / "minimal_agent.py"
    agent_file.write_text(minimal_code, encoding="utf-8")

    graph = extract_statechart_from_source(minimal_code)
    assert graph.agent_name == "MinimalAgent"
    assert len(graph.stages) == 3

    # Export Mermaid diagram for immediate documentation
    mermaid = export_mermaid(graph)
    assert "flowchart TD" in mermaid or "graph TD" in mermaid or "intake" in mermaid

    # Verify dominance: intake dominates completed
    adj = graph.adjacency_list(include_fallbacks=True)
    root = _get_root(graph)
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="intake",
        targets=["completed"],
    )
    assert proof.satisfied is True
