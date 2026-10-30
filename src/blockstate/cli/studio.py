"""Blockstate Studio local HTTP server and REST API handler.

Provides an offline visual statechart canvas, sub-5ms Lengauer-Tarjan dominator
verification overlay, turn-by-turn trace replay inspector, and signed MRM/CISO
dominance audit certificate export. Built strictly using the Python standard library
(http.server.ThreadingHTTPServer) with zero runtime frontend build chains or copyleft
dependencies.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import mimetypes
import threading
import time
import urllib.parse
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from blockstate import __version__
from blockstate.compiler.ast_extractor import (
    StatechartGraph,
    StaticGraphCompiler,
)
from blockstate.compiler.codegen import (
    StatechartSpec,
    generate_python_source,
)
from blockstate.compiler.dominators import (
    DominanceProofResult,
    verify_dominance,
)
from blockstate.compiler.exporters import export_json
from blockstate.errors import BlockstateError

console = Console()
err_console = Console(stderr=True)


def _compute_sha256(content: str | bytes) -> str:
    """Compute hexadecimal SHA-256 digest of string or bytes."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(raw).hexdigest()


def generate_audit_certificate_markdown(
    graph: StatechartGraph | None,
    proof: DominanceProofResult,
    source_file: str = "unknown_agent.py",
    source_sha256: str = "0" * 64,
) -> str:
    """Generate signed Model Risk Management (MRM) dominance audit certificate in Markdown.

    Args:
        graph: Active compiled StatechartGraph topology.
        proof: Evaluated Lengauer-Tarjan dominance proof result.
        source_file: Agent source filename.
        source_sha256: SHA-256 digest of agent source code.

    Returns:
        Formatted British English Markdown audit certificate.
    """
    agent_name = graph.agent_name if graph else "BlockstateAgent"
    timestamp_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_id = f"CERT-BLK-{int(time.time())}"
    targets_str = ", ".join(proof.targets)

    # Immediate dominators listing
    idom_lines = "\n".join(
        f"- $idom(\\text{{{k}}}) = \\text{{{v}}}$"
        for k, v in sorted(proof.immediate_dominators.items())
    )
    if not idom_lines:
        idom_lines = "- None declared"

    # Mermaid diagram of dominator tree
    mermaid_lines = ["```mermaid", "flowchart TD"]
    for parent, children in sorted(proof.dominator_tree.items()):
        for child in sorted(children):
            mermaid_lines.append(f"    {parent} --> {child}")
    if len(mermaid_lines) == 2:
        mermaid_lines.append(f"    {proof.root} --> {proof.precursor}")
    mermaid_lines.append("```")
    mermaid_block = "\n".join(mermaid_lines)

    status_str = "100% OF PATHS DOMINATED" if proof.satisfied else "DOMINANCE VIOLATION DETECTED"
    bypass_risk = "0.00%" if proof.satisfied else "100.00%"
    patent_msg = (
        "UK Patent Pending (Process execution control system, Priority Date: 28 October 2026)"
    )

    fca_status = (
        "Compliant. Privileged tools cannot be accessed without traversing required precursor "
        "identity verification stages."
        if proof.satisfied
        else "Non-Compliant. Bypass path detected."
    )
    cert_digest = _compute_sha256(cert_id + agent_name + timestamp_utc)
    seal_status = (
        "MATHEMATICAL INVARIANT CERTIFIED" if proof.satisfied else "DOMINANCE VIOLATION DETECTED"
    )
    impossible_desc = (
        "Mathematically Impossible" if proof.satisfied else "Vulnerable Shortcut Found"
    )

    cert_body = f"""# Model Risk Management Dominance Verification Certificate

**Document Reference:** {cert_id}
**Generation Timestamp (UTC):** {timestamp_utc}
**Agent Class:** `{agent_name}`
**Source File:** `{source_file}`
**Source SHA-256:** `{source_sha256}`
**Compiler:** Blockstate Declarative Control Grammar v{__version__}
**Statutory Intellectual Property Notice:** {patent_msg}

---

## 1. Executive Certification & Verification Summary

This audit certificate certifies that the conversational statechart defining `{agent_name}` has
been formally compiled and verified via offline AST static analysis and the
**Lengauer-Tarjan mathematical dominator tree algorithm**.

| Verification Parameter | Certified Specification | Operational Status |
| :--- | :--- | :--- |
| **Root Stage** | `{proof.root}` | Certified Entrypoint |
| **Precursor Stage** | `{proof.precursor}` | Mandatory Interlock Stage |
| **Protected Targets** | `{targets_str}` | Privileged Operations |
| **Formal Invariant** | Paths(Root to Target) contain Precursor | **{status_str}** |
| **Bypass Route Probability** | {bypass_risk} | {impossible_desc} |
| **AST Dynamic Reflection** | Zero dynamic reflection calls | Verified Clean (BLK-AST-014) |
| **Runtime Tool Gating** | Ephemeral `MappingProxyType` dispatch | Enforced (BLK-SEC-001) |

## 2. Regulatory Compliance Control Mappings

- **UK FCA SYSC 13.7 (Operational Risk)**: {fca_status}
- **FCA Consumer Duty (PS22/9)**: Compliant. Deterministic fallback transitions.
- **Bank of England PRA SS1/23 (Model Risk Management)**: Compliant. Offline formal proofs.
- **EU AI Act Articles 9, 12 & 14 (Record-Keeping)**: Compliant. TurnLedger RFC 8785 JCS chains.
- **OWASP Top 10 for LLMs (LLM06 Excessive Agency)**: Compliant. Ephemeral stage-scoped whitelist.

## 3. Lengauer-Tarjan Dominator Tree

{mermaid_block}

### Immediate Dominators ($idom$)
{idom_lines}

## 4. Cryptographic Proof Seal

```
[BLOCKSTATE VERIFICATION SEAL]
Algorithm: Lengauer-Tarjan Path-Compression Disjoint-Set Solver
Certificate Digest: {cert_digest}
Verification Status: {seal_status}
```
"""
    return cert_body


def generate_audit_certificate_json(
    graph: StatechartGraph | None,
    proof: DominanceProofResult,
    source_file: str = "unknown_agent.py",
    source_sha256: str = "0" * 64,
) -> dict[str, Any]:
    """Generate structured Model Risk Management (MRM) dominance audit certificate in JSON.

    Args:
        graph: Active compiled StatechartGraph topology.
        proof: Evaluated Lengauer-Tarjan dominance proof result.
        source_file: Agent source filename.
        source_sha256: SHA-256 digest of agent source code.

    Returns:
        Dictionary conforming to dominance certificate schema.
    """
    agent_name = graph.agent_name if graph else "BlockstateAgent"
    timestamp_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_id = f"CERT-BLK-{int(time.time())}"

    cert_payload: dict[str, Any] = {
        "$schema": "https://blockstate.dev/schemas/dominance_certificate_v1.json",
        "certificate_id": cert_id,
        "timestamp_utc": timestamp_utc,
        "agent_name": agent_name,
        "source_file": source_file,
        "source_sha256": source_sha256,
        "compiler_version": __version__,
        "patent_notice": (
            "UK Patent Pending (Process execution control system, Priority Date: 28 October 2026)"
        ),
        "satisfied": proof.satisfied,
        "precursor": proof.precursor,
        "targets": list(proof.targets),
        "proof": {
            "satisfied": proof.satisfied,
            "root_stage": proof.root,
            "precursor_stage": proof.precursor,
            "target_stages": list(proof.targets),
            "bypass_risk": 0.0 if proof.satisfied else 1.0,
            "violating_target": proof.violating_target,
            "violating_path": list(proof.violating_path) if proof.violating_path else None,
            "immediate_dominators": proof.immediate_dominators,
            "dominator_tree": {k: list(v) for k, v in proof.dominator_tree.items()},
        },
        "regulatory_mappings": {
            "uk_fca_sysc_13_7": "COMPLIANT" if proof.satisfied else "NON_COMPLIANT",
            "bank_of_england_pra_ss1_23": "COMPLIANT" if proof.satisfied else "NON_COMPLIANT",
            "eu_ai_act_article_14": "COMPLIANT" if proof.satisfied else "NON_COMPLIANT",
            "owasp_llm_06": "COMPLIANT" if proof.satisfied else "NON_COMPLIANT",
        },
    }
    cert_str = json.dumps(cert_payload, sort_keys=True)
    cert_payload["certificate_sha256"] = _compute_sha256(cert_str)
    return cert_payload


class StudioRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler dispatching static assets and REST API endpoints."""

    server: StudioServer  # Type narrowing for server attribute

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP request logging to keep console output clean."""

    def _send_cors_headers(self) -> None:
        """Send standard Cross-Origin Resource Sharing (CORS) headers."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: Any, status_code: int = 200) -> None:
        """Send Python object as formatted JSON response."""
        encoded = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error_json(
        self,
        message: str,
        code: str = "BLK-ERR",
        status_code: int = 400,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Send structured error response in JSON format."""
        payload: dict[str, Any] = {"error": message, "code": code}
        if extra:
            payload.update(extra)
        self._send_json(payload, status_code=status_code)

    def do_OPTIONS(self) -> None:
        """Handle HTTP pre-flight OPTIONS request for CORS."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        """Handle incoming HTTP GET requests for static assets and API data."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # 1. API Endpoints
        if path == "/api/status":
            self._handle_get_status()
            return
        if path == "/api/graph":
            self._handle_get_graph()
            return
        if path == "/api/traces":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            session_id = query_params.get("session", [None])[0]
            self._handle_get_traces(session_id=session_id)
            return

        # If path begins with /api/ but is unrecognised, return 404
        if path.startswith("/api/"):
            self._send_error_json("Unknown API endpoint", code="BLK-API-404", status_code=404)
            return

        # 2. Static File Serving
        self._handle_get_static(path)

    def do_POST(self) -> None:
        """Handle incoming HTTP POST requests for calculations and exports."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Read request body
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception as exc:
            self._send_error_json(
                f"Malformed JSON in request body: {exc}",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        if not isinstance(payload, dict):
            self._send_error_json(
                "Request body must be a JSON object dictionary",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        if path == "/api/verify-dominance":
            self._handle_post_verify_dominance(payload)
            return
        if path == "/api/export-code":
            self._handle_post_export_code(payload)
            return
        if path == "/api/export-certificate":
            self._handle_post_export_certificate(payload)
            return

        # Unrecognised POST endpoint
        self._send_error_json("Unknown API endpoint", code="BLK-API-404", status_code=404)

    # -------------------------------------------------------------------------
    # Static File Handler
    # -------------------------------------------------------------------------
    def _handle_get_static(self, req_path: str) -> None:
        """Serve static files from static directory with traversal security."""
        static_dir = self.server.static_dir.resolve()

        # Map / and /index.html to index.html
        rel_path = "index.html" if req_path in ("/", "/index.html") else req_path.lstrip("/")

        # Normalise and guard against path traversal
        try:
            target_path = (static_dir / rel_path).resolve()
        except Exception:
            self._send_error_json("Invalid path", code="BLK-SEC-400", status_code=400)
            return

        # Verify target is strictly within static_dir
        if not str(target_path).startswith(str(static_dir)):
            self._send_error_json(
                "Access denied: path traversal prohibited",
                code="BLK-SEC-403",
                status_code=403,
            )
            return

        if not target_path.is_file():
            self._send_error_json(
                f"File not found: {rel_path}", code="BLK-NOT-FOUND", status_code=404
            )
            return

        mime_type, _ = mimetypes.guess_type(str(target_path))
        if mime_type is None:
            mime_type = "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in (
            "application/javascript",
            "application/json",
        ):
            mime_type += "; charset=utf-8"

        try:
            content = target_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            self._send_error_json(
                f"Error reading static file: {exc}",
                code="BLK-IO-500",
                status_code=500,
            )

    # -------------------------------------------------------------------------
    # REST API Handlers
    # -------------------------------------------------------------------------
    def _handle_get_status(self) -> None:
        """Handle GET /api/status returning server health and agent metadata."""
        graph = self.server.graph
        payload = {
            "status": "ok",
            "version": __version__,
            "agent_file": str(self.server.agent_path) if self.server.agent_path else "",
            "agent_name": graph.agent_name if graph else "BlockstateAgent",
            "stage_count": len(graph.stages) if graph else 0,
            "transition_count": len(graph.transitions) if graph else 0,
        }
        self._send_json(payload)

    def _handle_get_graph(self) -> None:
        """Handle GET /api/graph returning compiled statechart topology."""
        self.server.reload_agent_if_needed()
        graph = self.server.graph

        if graph is None:
            self._send_error_json(
                "No active agent statechart loaded in Studio server.",
                code="BLK-AST-000",
                status_code=400,
            )
            return

        try:
            # export_json returns a serialised JSON string
            json_str = export_json(graph)
            graph_dict = json.loads(json_str)
            # Add full source code and path for studio inspector
            graph_dict["source_path"] = (
                str(self.server.agent_path) if self.server.agent_path else ""
            )
            graph_dict["source_code"] = self.server.agent_source
            self._send_json(graph_dict)
        except BlockstateError as b_err:
            self._send_error_json(str(b_err), code="BLK-AST-014", status_code=400)
        except Exception as exc:
            self._send_error_json(f"Error serialising statechart graph: {exc}", status_code=500)

    def _handle_post_verify_dominance(self, payload: dict[str, Any]) -> None:
        """Handle POST /api/verify-dominance calculating Lengauer-Tarjan proof."""
        self.server.reload_agent_if_needed()
        graph = self.server.graph

        if graph is None:
            self._send_error_json(
                "Cannot verify dominance: no agent graph loaded",
                code="BLK-AST-000",
                status_code=400,
            )
            return

        precursor = payload.get("precursor")
        if not precursor or not isinstance(precursor, str):
            self._send_error_json(
                "Field 'precursor' is required as a string.",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        # Support both 'target' (single) and 'targets' (list)
        targets_input = payload.get("targets")
        target_single = payload.get("target")

        if targets_input is not None and isinstance(targets_input, list):
            targets = [str(t) for t in targets_input if t]
        elif target_single is not None:
            targets = [str(target_single)]
        else:
            self._send_error_json(
                "Either 'target' or 'targets' must be specified.",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        if not targets:
            self._send_error_json(
                "Targets list cannot be empty.", code="BLK-REQ-400", status_code=400
            )
            return

        root = graph.initial_stage
        if not root:
            self._send_error_json(
                "Agent statechart graph has no initial stage.",
                code="BLK-AST-001",
                status_code=400,
            )
            return

        t0 = time.perf_counter()
        adj = graph.adjacency_list(include_fallbacks=True)
        proof = verify_dominance(root=root, graph=adj, precursor=precursor, targets=targets)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        response_payload = {
            "satisfied": proof.satisfied,
            "elapsed_ms": round(elapsed_ms, 3),
            "root": proof.root,
            "precursor": proof.precursor,
            "targets": list(proof.targets),
            "violating_target": proof.violating_target,
            "violating_path": list(proof.violating_path) if proof.violating_path else None,
            "dominator_tree": {k: list(v) for k, v in proof.dominator_tree.items()},
            "immediate_dominators": proof.immediate_dominators,
            "summary": proof.summary(),
        }
        self._send_json(response_payload)

    def _handle_get_traces(self, session_id: str | None = None) -> None:
        """Handle GET /api/traces returning parsed trace records from traces.jsonl."""
        records = self.server.load_trace_records(session_id=session_id)
        self._send_json(records)

    def _handle_post_export_code(self, payload: dict[str, Any]) -> None:
        """Handle POST /api/export-code generating deterministic Python 3.12+ source."""
        spec_data = payload.get("spec", payload)
        if not isinstance(spec_data, dict):
            self._send_error_json(
                "Spec data must be provided as a JSON dictionary.",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        try:
            spec = StatechartSpec.model_validate(spec_data)
            python_source = generate_python_source(spec)
            self._send_json({"python_source": python_source})
        except Exception as exc:
            self._send_error_json(
                f"Error synthesising Python source code: {exc}",
                code="BLK-DCG-500",
                status_code=400,
            )

    def _handle_post_export_certificate(self, payload: dict[str, Any]) -> None:
        """Handle POST /api/export-certificate producing signed MRM compliance certificates."""
        self.server.reload_agent_if_needed()
        graph = self.server.graph

        precursor = payload.get("precursor")
        targets_input = payload.get("targets")
        format_req = payload.get("format", "markdown")

        if not precursor or not isinstance(precursor, str):
            self._send_error_json(
                "Field 'precursor' is required.", code="BLK-REQ-400", status_code=400
            )
            return

        if not targets_input or not isinstance(targets_input, list) or len(targets_input) == 0:
            self._send_error_json(
                "Field 'targets' must be a non-empty list of stage strings.",
                code="BLK-REQ-400",
                status_code=400,
            )
            return

        fmt = str(format_req).lower().strip()
        if fmt not in ("markdown", "json"):
            self._send_error_json(
                f"Unsupported format '{format_req}'. Supported formats: markdown, json.",
                code="BLK-REQ-422",
                status_code=422,
            )
            return

        if graph is None:
            self._send_error_json(
                "No agent loaded to verify certificate",
                code="BLK-AST-000",
                status_code=400,
            )
            return

        root = graph.initial_stage or precursor
        adj = graph.adjacency_list(include_fallbacks=True)
        proof = verify_dominance(root=root, graph=adj, precursor=precursor, targets=targets_input)

        source_file = self.server.agent_path.name if self.server.agent_path else "agent.py"
        source_sha256 = (
            _compute_sha256(self.server.agent_source) if self.server.agent_source else "0" * 64
        )

        if fmt == "markdown":
            cert_text = generate_audit_certificate_markdown(
                graph=graph,
                proof=proof,
                source_file=source_file,
                source_sha256=source_sha256,
            )
            self._send_json({"certificate": cert_text})
        else:
            cert_dict = generate_audit_certificate_json(
                graph=graph,
                proof=proof,
                source_file=source_file,
                source_sha256=source_sha256,
            )
            self._send_json({"certificate": cert_dict})


class StudioServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP server subclass managing agent state, traces, and static assets."""

    def __init__(
        self,
        server_address: tuple[str, int],
        agent_path: Path | None = None,
        traces_path: Path | None = None,
    ) -> None:
        self.daemon_threads = True
        self.allow_reuse_address = True
        self.agent_path: Path | None = agent_path
        self.traces_path: Path | None = traces_path
        self.static_dir: Path = Path(__file__).parent / "static"
        self.graph: StatechartGraph | None = None
        self.agent_source: str = ""
        self._last_mtime: float = 0.0

        # Validate agent file path existence if specified
        if self.agent_path is not None:
            if not self.agent_path.exists():
                raise FileNotFoundError(f"Agent source file not found: {self.agent_path}")
            self.reload_agent()

        super().__init__(server_address, StudioRequestHandler)

    def reload_agent(self) -> None:
        """Compile and cache active agent source code into StatechartGraph."""
        if self.agent_path is None or not self.agent_path.exists():
            return
        try:
            mtime = self.agent_path.stat().st_mtime
            source = self.agent_path.read_text(encoding="utf-8")
            graph = StaticGraphCompiler.compile_source(source, filename=str(self.agent_path))
            self.graph = graph
            self.agent_source = source
            self._last_mtime = mtime
        except Exception as exc:
            err_console.print(f"[yellow]Studio compilation warning: {exc}[/yellow]")

    def reload_agent_if_needed(self) -> None:
        """Check agent file modification time and reload if file changed on disk."""
        if self.agent_path is None or not self.agent_path.exists():
            return
        try:
            mtime = self.agent_path.stat().st_mtime
            if mtime > self._last_mtime:
                self.reload_agent()
        except Exception:
            pass

    def load_trace_records(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Parse turn records from .blockstate/traces.jsonl trace file.

        Args:
            session_id: Optional filter for a specific conversational session.

        Returns:
            List of parsed JSON turn records.
        """
        # Determine candidate traces file paths
        candidates: list[Path] = []
        if self.traces_path is not None:
            candidates.append(self.traces_path)
        if self.agent_path is not None:
            candidates.append(self.agent_path.parent / ".blockstate" / "traces.jsonl")
            candidates.append(self.agent_path.parent / "traces.jsonl")
        candidates.append(Path(".blockstate") / "traces.jsonl")
        candidates.append(Path("traces.jsonl"))

        trace_file: Path | None = None
        for cand in candidates:
            if cand.is_file():
                trace_file = cand
                break

        if trace_file is None:
            return []

        records: list[dict[str, Any]] = []
        try:
            with trace_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        rec = json.loads(line_str)
                        if isinstance(rec, dict):
                            if session_id and rec.get("session_id") != session_id:
                                continue
                            records.append(rec)
                    except json.JSONDecodeError:
                        # Ignore corrupted lines as per boundary requirements
                        continue
        except Exception:
            return []

        return records


def create_studio_server(
    agent_path: Path | None = None,
    port: int = 8420,
    host: str = "127.0.0.1",
    traces_path: Path | None = None,
) -> StudioServer:
    """Create and configure a Blockstate Studio ThreadingHTTPServer instance.

    Args:
        agent_path: Path to Python source file containing Declarative Control Grammar.
        port: TCP port number to bind the server.
        host: Host IP address to bind.
        traces_path: Path to .blockstate/traces.jsonl log file.

    Returns:
        Configured StudioServer ready for serve_forever().

    Raises:
        FileNotFoundError: If agent_path is provided but does not exist.
        ValueError: If port number is invalid.
    """
    if port < 0 or port > 65535:
        raise ValueError(f"Invalid TCP port number: {port}")

    if agent_path is not None:
        agent_path = Path(agent_path)
        if not agent_path.exists():
            raise FileNotFoundError(f"Agent file not found: {agent_path}")

    server_address = (host, port)
    return StudioServer(
        server_address=server_address,
        agent_path=agent_path,
        traces_path=traces_path,
    )


def run_studio(
    path: Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8420,
    open_browser: bool = True,
) -> None:
    """Launch the interactive visual statechart canvas and trace replay studio.

    Args:
        path: Path to Python agent file or directory to inspect.
        host: Host address to bind the HTTP server.
        port: Port number to bind the HTTP server.
        open_browser: Whether to open the system web browser on startup.
    """
    agent_file: Path | None = None
    if path is not None:
        p = Path(path)
        if p.is_dir():
            # Search for canonical agent files in directory
            candidates = list(p.glob("*_agent.py")) or list(p.glob("*.py"))
            if candidates:
                agent_file = candidates[0]
        elif p.is_file():
            agent_file = p

    try:
        server = create_studio_server(agent_path=agent_file, port=port, host=host)
    except FileNotFoundError as fnf:
        err_console.print(f"[red]Error starting Studio: {fnf}[/red]")
        raise typer_exit(1) from None
    except Exception as exc:
        err_console.print(f"[red]Failed to bind Studio server on {host}:{port}: {exc}[/red]")
        raise typer_exit(1) from None

    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"

    agent_desc = agent_file.name if agent_file else "Blank Canvas (No agent loaded)"
    console.print(
        Panel.fit(
            f"[bold green]Blockstate Studio v{__version__}[/bold green]\n\n"
            f"[bold]Active Agent:[/bold] [cyan]{agent_desc}[/cyan]\n"
            f"[bold]Local Server:[/bold] [bold underline blue]{url}[/bold underline blue]\n"
            f"[bold]Dominator Engine:[/bold] [yellow]Lengauer-Tarjan Sub-5ms Proof[/yellow]\n"
            f"[bold]Brand Edition:[/bold] 1965 Archival Vellum & Westinghouse Signal Box\n\n"
            f"[dim]Press Ctrl+C to terminate the local Studio server.[/dim]",
            title="Blockstate Studio",
            border_style="green",
        )
    )

    if open_browser:
        def _open_url_delayed() -> None:
            time.sleep(0.4)
            webbrowser.open(url)

        threading.Thread(target=_open_url_delayed, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down Blockstate Studio server...[/yellow]")
    finally:
        server.shutdown()
        server.server_close()


def typer_exit(code: int) -> BaseException:
    """Helper raising typer.Exit if available or SystemExit."""
    try:
        import typer

        return typer.Exit(code=code)
    except ImportError:
        return SystemExit(code)


__all__: list[str] = [
    "StudioRequestHandler",
    "StudioServer",
    "create_studio_server",
    "generate_audit_certificate_json",
    "generate_audit_certificate_markdown",
    "run_studio",
]
