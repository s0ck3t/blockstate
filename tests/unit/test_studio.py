"""Unit test suite for Blockstate Studio local server and REST API endpoints.

Tests server lifecycle, static asset delivery, security controls, dominance proof
generation, trace replayer loading, and MRM audit certificate export.
Strict British English orthography and zero em dashes are enforced throughout.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from blockstate import __version__
from blockstate.cli.studio import (
    StudioServer,
    create_studio_server,
    generate_audit_certificate_json,
    generate_audit_certificate_markdown,
)
from blockstate.compiler.ast_extractor import extract_statechart_from_source
from blockstate.compiler.dominators import verify_dominance

SAMPLE_BANKING_SOURCE = '''"""Banking Agent for Studio Unit Testing."""

from typing import Annotated
from pydantic import BaseModel
from blockstate import Agent, Stage, Transition
from blockstate.security import Vaulted

class PaymentDetails(BaseModel):
    recipient_iban: Annotated[str, Vaulted()]
    amount: float

class BankingTransferAgent(Agent):
    @Stage(initial=True, allow_digressions=["help_faq"])
    def intake(self, user_msg: str) -> Transition["verify_kyc"]:
        return Transition.to("verify_kyc")

    @Stage(tools=["verify_identity_document", "lookup_aml_records"])
    def verify_kyc(self, user_msg: str) -> Transition["execute_transfer" | "rejected"]:
        if "fail" in user_msg:
            return Transition.to("rejected")
        return Transition.to("execute_transfer")

    @Stage(tools=["settle_faster_payments"])
    def execute_transfer(self, user_msg: str) -> Transition["completed"]:
        return Transition.to("completed")

    @Stage(terminal=True)
    def completed(self, user_msg: str) -> Transition[None]:
        return Transition.end()

    @Stage(terminal=True)
    def rejected(self, user_msg: str) -> Transition[None]:
        return Transition.end()

    @Stage
    def help_faq(self, user_msg: str) -> Transition[None]:
        return Transition.pop_frame()
'''

SAMPLE_BYPASS_SOURCE = '''"""Bypass Vulnerable Agent for Studio Unit Testing."""

from blockstate import Agent, Stage, Transition

class BypassAgent(Agent):
    @Stage(initial=True)
    def start(self, user_msg: str) -> Transition["verify_kyc" | "fast_track"]:
        if "skip" in user_msg:
            return Transition.to("fast_track")
        return Transition.to("verify_kyc")

    @Stage
    def verify_kyc(self, user_msg: str) -> Transition["payout"]:
        return Transition.to("payout")

    @Stage
    def fast_track(self, user_msg: str) -> Transition["payout"]:
        return Transition.to("payout")

    @Stage(terminal=True)
    def payout(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''


@pytest.fixture
def banking_agent_file(tmp_path: Path) -> Path:
    """Write sample banking agent source file and return its path."""
    agent_file = tmp_path / "banking_agent.py"
    agent_file.write_text(SAMPLE_BANKING_SOURCE, encoding="utf-8")
    return agent_file


@pytest.fixture
def running_studio_server(
    banking_agent_file: Path,
) -> tuple[StudioServer, int, str]:
    """Launch studio server on an ephemeral port in a daemon thread."""
    server = create_studio_server(banking_agent_file, port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{port}"
    return server, port, base_url


# ============================================================================
# 1. Server Lifecycle & Factory Tests
# ============================================================================


def test_studio_server_creation_and_shutdown(banking_agent_file: Path) -> None:
    """Verify studio server instantiates and terminates cleanly."""
    server = create_studio_server(banking_agent_file, port=0)
    actual_port = server.server_address[1]
    assert actual_port > 0
    assert server.agent_path == banking_agent_file
    assert server.graph is not None
    assert server.graph.agent_name == "BankingTransferAgent"

    server.server_close()


def test_studio_server_missing_agent_file_raises_error(tmp_path: Path) -> None:
    """Verify non-existent agent file raises FileNotFoundError."""
    non_existent = tmp_path / "missing.py"
    with pytest.raises(FileNotFoundError):
        create_studio_server(non_existent, port=0)


def test_studio_server_invalid_port_raises_error(banking_agent_file: Path) -> None:
    """Verify negative port or port > 65535 raises ValueError."""
    with pytest.raises(ValueError):
        create_studio_server(banking_agent_file, port=-1)
    with pytest.raises(ValueError):
        create_studio_server(banking_agent_file, port=999999)


# ============================================================================
# 2. Static Asset Delivery & Security Controls
# ============================================================================


def test_get_root_serves_html(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify GET / delivers index.html with HTML structure and canvas element."""
    server, _, base_url = running_studio_server
    try:
        with urlopen(f"{base_url}/", timeout=3.0) as resp:
            assert resp.status == 200
            content_type = resp.headers.get("Content-Type", "")
            assert "text/html" in content_type
            body = resp.read().decode("utf-8")
            assert "<!DOCTYPE html>" in body
            assert "statechart-canvas" in body
            assert "DRAWING NO." in body
    finally:
        server.shutdown()
        server.server_close()


def test_get_styles_css(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify GET /styles.css delivers brand tokens stylesheet."""
    server, _, base_url = running_studio_server
    try:
        with urlopen(f"{base_url}/styles.css", timeout=3.0) as resp:
            assert resp.status == 200
            content_type = resp.headers.get("Content-Type", "")
            assert "text/css" in content_type
            css = resp.read().decode("utf-8")
            assert "--bg-canvas" in css
            assert "#166534" in css  # Signal green
            assert "#D42B1E" in css  # Signal vermilion
    finally:
        server.shutdown()
        server.server_close()


def test_get_studio_js(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify GET /studio.js delivers visual canvas client controller."""
    server, _, base_url = running_studio_server
    try:
        with urlopen(f"{base_url}/studio.js", timeout=3.0) as resp:
            assert resp.status == 200
            content_type = resp.headers.get("Content-Type", "")
            assert "javascript" in content_type
            js = resp.read().decode("utf-8")
            assert "Blockstate Studio" in js
            assert "calculateDagLayout" in js
    finally:
        server.shutdown()
        server.server_close()


def test_static_path_traversal_forbidden(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify path traversal outside static directory returns HTTP error."""
    server, _, base_url = running_studio_server
    try:
        traversal_url = f"{base_url}/../../../../Windows/win.ini"
        with pytest.raises(HTTPError) as exc_info:
            urlopen(traversal_url, timeout=3.0)
        assert exc_info.value.code in (400, 403, 404)
    finally:
        server.shutdown()
        server.server_close()


def test_nonexistent_static_file_returns_404(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify requesting a missing static file returns HTTP 404."""
    server, _, base_url = running_studio_server
    try:
        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{base_url}/nonexistent_asset.png", timeout=3.0)
        assert exc_info.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


# ============================================================================
# 3. REST API Endpoint Tests
# ============================================================================


def test_api_status_endpoint(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify GET /api/status returns operational status and version metadata."""
    server, _, base_url = running_studio_server
    try:
        with urlopen(f"{base_url}/api/status", timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["version"] == __version__
            assert data["agent_name"] == "BankingTransferAgent"
            assert data["stage_count"] >= 5
    finally:
        server.shutdown()
        server.server_close()


def test_api_graph_endpoint(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify GET /api/graph returns compiled statechart topology."""
    server, _, base_url = running_studio_server
    try:
        with urlopen(f"{base_url}/api/graph", timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["agent_name"] == "BankingTransferAgent"
            assert data["initial_stage"] == "intake"
            assert "stages" in data
            assert "transitions" in data
            assert "verify_kyc" in data["stages"]
            assert "execute_transfer" in data["stages"]
            # Verify tools list
            assert "verify_identity_document" in data["stages"]["verify_kyc"]["tools"]
    finally:
        server.shutdown()
        server.server_close()


def test_api_verify_dominance_satisfied(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify POST /api/verify-dominance returns certified proof in under 5ms."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/verify-dominance",
            data=json.dumps({"precursor": "verify_kyc", "target": "execute_transfer"}).encode(
                "utf-8"
            ),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["satisfied"] is True
            assert data["precursor"] == "verify_kyc"
            assert data["targets"] == ["execute_transfer"]
            assert data["violating_path"] is None
            assert data["elapsed_ms"] < 5.0
            assert "Dominance Verified" in data["summary"]
    finally:
        server.shutdown()
        server.server_close()


def test_api_verify_dominance_bypass_violation(tmp_path: Path) -> None:
    """Verify POST /api/verify-dominance synthesises bypass route on violation."""
    agent_file = tmp_path / "bypass_agent.py"
    agent_file.write_text(SAMPLE_BYPASS_SOURCE, encoding="utf-8")

    server = create_studio_server(agent_file, port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{port}"

    try:
        req = Request(
            f"{base_url}/api/verify-dominance",
            data=json.dumps({"precursor": "verify_kyc", "target": "payout"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["satisfied"] is False
            assert data["violating_target"] == "payout"
            assert data["violating_path"] == ["start", "fast_track", "payout"]
            assert data["elapsed_ms"] < 5.0
    finally:
        server.shutdown()
        server.server_close()


def test_api_verify_dominance_performance_benchmark(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify dominance calculation executes reliably under 5ms across multiple runs."""
    server, _, base_url = running_studio_server
    try:
        payload = json.dumps({"precursor": "verify_kyc", "target": "execute_transfer"}).encode(
            "utf-8"
        )
        latencies: list[float] = []

        for _ in range(5):
            req = Request(
                f"{base_url}/api/verify-dominance",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                latencies.append(data["elapsed_ms"])

        avg_latency = sum(latencies) / len(latencies)
        assert avg_latency < 5.0, f"Average latency exceeded 5ms: {avg_latency:.3f}ms"
    finally:
        server.shutdown()
        server.server_close()


def test_api_verify_dominance_missing_parameters_returns_400(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify endpoint rejects requests with missing precursor or targets."""
    server, _, base_url = running_studio_server
    try:
        # Missing targets
        req1 = Request(
            f"{base_url}/api/verify-dominance",
            data=json.dumps({"precursor": "verify_kyc"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc1:
            urlopen(req1, timeout=3.0)
        assert exc1.value.code == 400

        # Missing precursor
        req2 = Request(
            f"{base_url}/api/verify-dominance",
            data=json.dumps({"target": "execute_transfer"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc2:
            urlopen(req2, timeout=3.0)
        assert exc2.value.code == 400
    finally:
        server.shutdown()
        server.server_close()


def test_api_post_non_dictionary_json_returns_400(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify endpoint rejects non-dictionary JSON payloads with HTTP 400 and BLK-REQ-400."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/verify-dominance",
            data=b"[1, 2, 3]",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(req, timeout=3.0)
        assert exc.value.code == 400
        error_payload = json.loads(exc.value.read().decode("utf-8"))
        assert error_payload["code"] == "BLK-REQ-400"
        assert "Request body must be a JSON object dictionary" in error_payload["error"]
    finally:
        server.shutdown()
        server.server_close()


# ============================================================================
# 4. Trace Replayer Endpoint Tests
# ============================================================================


def test_api_traces_parsing_and_session_filtering(tmp_path: Path) -> None:
    """Verify GET /api/traces parses JSONL records and handles session queries."""
    agent_file = tmp_path / "agent.py"
    agent_file.write_text(SAMPLE_BANKING_SOURCE, encoding="utf-8")

    trace_dir = tmp_path / ".blockstate"
    trace_dir.mkdir(parents=True)
    trace_file = trace_dir / "traces.jsonl"

    records = [
        {
            "session_id": "sess_001",
            "turn_index": 0,
            "stage": "intake",
            "task_stack": ["Mainline"],
            "exposed_tools": [],
            "prev_record_hash": "0" * 64,
            "record_hash": "1" * 64,
        },
        {
            "session_id": "sess_001",
            "turn_index": 1,
            "stage": "verify_kyc",
            "task_stack": ["Mainline"],
            "exposed_tools": ["verify_identity_document"],
            "prev_record_hash": "1" * 64,
            "record_hash": "2" * 64,
        },
        {
            "session_id": "sess_002",
            "turn_index": 0,
            "stage": "intake",
            "task_stack": ["Mainline"],
            "exposed_tools": [],
            "prev_record_hash": "0" * 64,
            "record_hash": "3" * 64,
        },
    ]
    trace_file.write_text(
        "\n".join(json.dumps(r) for r in records) + "\nCORRUPTED_LINE_NOT_JSON\n",
        encoding="utf-8",
    )

    server = create_studio_server(agent_file, port=0, traces_path=trace_file)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Query all traces
        with urlopen(f"{base_url}/api/traces", timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 3

        # Query filtered session
        with urlopen(f"{base_url}/api/traces?session=sess_001", timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert len(data) == 2
            assert data[0]["session_id"] == "sess_001"
            assert data[1]["session_id"] == "sess_001"
    finally:
        server.shutdown()
        server.server_close()


# ============================================================================
# 5. Code & Certificate Export Tests
# ============================================================================


def test_api_export_code(running_studio_server: tuple[StudioServer, int, str]) -> None:
    """Verify POST /api/export-code synthesises compilable Python source."""
    server, _, base_url = running_studio_server
    try:
        spec = {
            "agent_name": "ExportedAgent",
            "initial_stage": "start",
            "stages": [
                {
                    "name": "start",
                    "is_initial": True,
                    "transitions": [{"target": "finish"}],
                },
                {"name": "finish", "terminal": True},
            ],
        }
        req = Request(
            f"{base_url}/api/export-code",
            data=json.dumps({"spec": spec}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            source = data["python_source"]
            assert "class ExportedAgent(Agent):" in source

            # Verify exported code passes compiler
            graph = extract_statechart_from_source(source)
            assert graph.agent_name == "ExportedAgent"
            assert "start" in graph.stages
            assert "finish" in graph.stages
    finally:
        server.shutdown()
        server.server_close()


def test_api_export_certificate_markdown(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify POST /api/export-certificate in Markdown format returns signed audit document."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/export-certificate",
            data=json.dumps(
                {
                    "precursor": "verify_kyc",
                    "targets": ["execute_transfer"],
                    "format": "markdown",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            cert = data["certificate"]
            assert "# Model Risk Management Dominance Verification Certificate" in cert
            assert "verify_kyc" in cert
            assert "execute_transfer" in cert
            assert "UK FCA SYSC 13.7" in cert
            assert "BLOCKSTATE VERIFICATION SEAL" in cert
    finally:
        server.shutdown()
        server.server_close()


def test_api_export_certificate_json(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify POST /api/export-certificate in JSON format returns structured certificate."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/export-certificate",
            data=json.dumps(
                {
                    "precursor": "verify_kyc",
                    "targets": ["execute_transfer"],
                    "format": "json",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            cert = data["certificate"]
            assert cert["satisfied"] is True
            assert cert["precursor"] == "verify_kyc"
            assert cert["targets"] == ["execute_transfer"]
            assert "certificate_sha256" in cert
            assert cert["regulatory_mappings"]["uk_fca_sysc_13_7"] == "COMPLIANT"
    finally:
        server.shutdown()
        server.server_close()


def test_api_export_certificate_empty_targets_rejected(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify export certificate rejects empty targets list with 400."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/export-certificate",
            data=json.dumps({"precursor": "verify_kyc", "targets": []}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req, timeout=3.0)
        assert exc_info.value.code in (400, 422)
    finally:
        server.shutdown()
        server.server_close()


def test_api_export_certificate_invalid_format_rejected(
    running_studio_server: tuple[StudioServer, int, str],
) -> None:
    """Verify export certificate rejects unknown formats like XML with 422."""
    server, _, base_url = running_studio_server
    try:
        req = Request(
            f"{base_url}/api/export-certificate",
            data=json.dumps(
                {
                    "precursor": "verify_kyc",
                    "targets": ["execute_transfer"],
                    "format": "xml",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req, timeout=3.0)
        assert exc_info.value.code in (400, 422)
    finally:
        server.shutdown()
        server.server_close()


def test_direct_certificate_generators_match_contracts() -> None:
    """Verify direct calls to certificate generator functions."""
    graph = extract_statechart_from_source(SAMPLE_BANKING_SOURCE)
    adj = graph.adjacency_list(include_fallbacks=True)
    root = graph.initial_stage or "intake"
    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="verify_kyc",
        targets=["execute_transfer"],
    )

    md = generate_audit_certificate_markdown(graph, proof)
    assert "# Model Risk Management Dominance Verification Certificate" in md
    assert "100% OF PATHS DOMINATED" in md

    js = generate_audit_certificate_json(graph, proof)
    assert js["satisfied"] is True
    assert js["precursor"] == "verify_kyc"
    assert js["certificate_sha256"]
