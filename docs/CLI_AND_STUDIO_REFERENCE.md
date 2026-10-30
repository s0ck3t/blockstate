# Blockstate CLI & Visual Studio Reference

The `blockstate` command-line toolkit and local visual inspector provide offline static AST compilation, Lengauer-Tarjan dominator tree verification, topological diagram export, cryptographic trace replay, project scaffolding, and Model Risk Management (MRM) audit certificate generation.

All CLI commands execute deterministically without invoking external language models or executing untrusted agent bytecode during compilation passes.

---

## 1. CLI Command Summary

| Command | Primary Function | Default Exit Codes | Typical Execution Window |
| :--- | :--- | :--- | :--- |
| `blockstate init [DIR]` | Scaffold a ready-to-verify compliance enclave project (`banking`, `insurance`, `healthcare`, `minimal`) with tests and CI workflow. | `0` (Success / Cancelled)<br/>`1` (Non-empty dir without `--force`, or I/O error) | Local project setup (`< 50ms`) |
| `blockstate check <PATH>` | Parse Python source via `ast.parse` without executing bytecode. Verify DCG syntax, static transitions (`BLK-AST-014`), and BFS reachability (`BLK-AST-002`). | `0` (Valid AST & CFG)<br/>`1` (AST violation, unreachable stage, or missing file) | Pre-commit hook & PR lint stage (`< 25ms`) |
| `blockstate verify <PATH> --dominates "<U> -> <V>"` | Construct the full Control Flow Graph (including fallback edges) and prove mathematical precursor dominance via `LengauerTarjanSolver`. | `0` (Dominance proven)<br/>`1` (Dominance violation with BFS bypass path, or AST error) | CI/CD compliance gate (`< 50ms`) |
| `blockstate export <PATH>` | Export verified statechart topology, tool whitelists, and guard annotations as Mermaid (`stateDiagram-v2`) or JSON Schema. | `0` (Export succeeded)<br/>`1` (Unsupported format or AST error) | PR architecture preview & documentation |
| `blockstate trace --session <ID>` | Replay a multi-turn session from `.blockstate/traces.jsonl`, verifying `RFC 8785 JCS` `SHA-256` hash continuity and slot deltas. | `0` (Trace replayed)<br/>`1` (Session not found in trace log) | Local debugging & SRE incident response |
| `blockstate studio [PATH]` | Launch the local HTTP visual statechart canvas, sub-5ms dominator overlay, codegen workbench, and MRM certificate exporter. | `0` (Clean shutdown)<br/>`1` (Port bind error or missing file) | Interactive architecture design & MRM audit |

---

## 2. Detailed Command Reference

### 2.1 `blockstate init`

Scaffolds a self-contained Blockstate compliance enclave directory containing the agent source file, an automated `pytest` suite (`test_<name>_agent.py` or `test_<name>.py`), `.env.example`, `.github/workflows/blockstate-verify.yml`, and `README.md`.

#### Usage

```bash
blockstate init [DIRECTORY] [OPTIONS]
```

#### Arguments & Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `DIRECTORY` | `Path` | `.` | Target directory in which to generate the enclave files. |
| `--template`, `-t` | `banking \| insurance \| healthcare \| minimal` | `minimal` | Starter domain enclave template (case-insensitive). |
| `--name`, `-n` | `str \| None` | Template name | Custom identifier prefix for generated agent and test filenames. |
| `--force`, `-f` | `bool` | `False` | Overwrite existing files if the target directory is not empty. |

#### Examples

```bash
# Scaffold a retail banking KYC enclave into ./banking_enclave
blockstate init ./banking_enclave --template banking

# Scaffold a healthcare PHI vault enclave with a custom module prefix
blockstate init ./nhs_triage --template healthcare --name nhs_clinical --force
```

---

### 2.2 `blockstate check`

Performs zero-execution static analysis on a Python source file containing a Declarative Control Grammar (`@Stage`, `@Transition`, `@Guard`) agent class via `StaticGraphCompiler.compile_source()`.

#### Usage

```bash
blockstate check <PATH>
```

#### Compile-Time Invariants Enforced

1. **Zero Dynamic Reflection (`BLK-AST-014` / `[Blockstate E014]`)**: Rejects any call to `getattr(...)` inside a `@Stage` method, any `Transition.to(...)` call whose target argument is not a compile-time non-empty string literal constant, and any `Transition.*` call inside a Pydantic `@field_validator` method.
2. **Directed CFG Construction & Reachability (`BLK-AST-002`)**: Builds the stage and transition graph (including `on_refusal`, `on_max_turns_exceeded`, `on_breach`, and `on_security_violation` fallback edges) and verifies via breadth-first search (BFS) from `initial_stage` that every declared stage is reachable.
3. **Graph Integrity (`BLK-AST-001`, `BLK-CFG-001`)**: Ensures transitions reference declared stages, verifies an initial stage exists, and prevents duplicate stage identifiers.

#### Example

```bash
blockstate check examples/02_banking_kyc_dominator.py
```

---

### 2.3 `blockstate verify`

Executes the **Lengauer-Tarjan dominator tree algorithm** (`LengauerTarjanSolver`) over the compiled Control Flow Graph to prove that a designated precursor stage $u$ strictly dominates every target stage $v \in T$ across all execution paths originating at the root stage $r$.

Mathematically, stage $u$ dominates stage $v$ ($u \text{ dom } v$) if and only if every directed walk from the initial stage $r$ to $v$ contains $u$.

#### Usage

```bash
blockstate verify [PATH] --dominates "<PRECURSOR> -> <TARGET_1>, <TARGET_2>, ..."
```

#### Arguments & Options

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `PATH` | `Path` | Yes (or via `--file`) | Positional path to the Python source file containing the agent class. |
| `--file`, `-f` | `Path` | No | Alternative flag to specify the Python source file path. |
| `--dominates`, `-d` | `str` | Yes | Precursor dominance assertion in the format `"PrecursorStage -> TargetA, TargetB"`. |

#### Examples

**Passing Verification (Exit Code `0`):**

```bash
blockstate verify examples/02_banking_kyc_dominator.py --dominates "VerifyKYC -> TransferFunds"
```

**Failing Verification on a Bypass Bug (Exit Code `1`):**

When a target stage can be reached from `initial_stage` without traversing the precursor stage, `find_counterexample_path()` runs a breadth-first search in the residual graph $G \setminus \{u\}$ and outputs the shortest violating bypass route:

```text
Dominance Proof Failure
Dominance Violation: Precursor 'VerifyKYC' does not dominate target 'TransferFunds'. Violating bypass path: VipFastTrack -> TransferFunds
Violating bypass route: VipFastTrack -> TransferFunds
```

---

### 2.4 `blockstate export`

Exports the compiled statechart topology of an agent into a Mermaid state diagram (`stateDiagram-v2`) or a structured JSON topology schema.

#### Usage

```bash
blockstate export <PATH> [--format mermaid|json] [--markdown-fence]
```

#### Arguments & Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PATH` | `Path` | Required | Path to the Python source file containing the DCG agent. |
| `--format`, `-f` | `mermaid \| json` | `mermaid` | Output serialisation format. |
| `--markdown-fence` | `bool` | `False` | Wrap Mermaid output in a ```` ```mermaid ```` fenced code block. |

#### Examples

```bash
# Export Mermaid statechart diagram wrapped in a markdown fence for PR descriptions
blockstate export examples/01_motor_insurance_claim.py --format mermaid --markdown-fence

# Export canonical JSON topology schema
blockstate export examples/02_banking_kyc_dominator.py --format json
```

---

### 2.5 `blockstate trace`

Replays the chronological turn timeline for a specific `session_id` from a local JSONL trace log (`.blockstate/traces.jsonl`), verifying `TurnLedger` cryptographic hash-chain continuity across turns.

#### Usage

```bash
blockstate trace --session <SESSION_ID> [--file <TRACE_PATH>] [--format table|json]
```

#### Arguments & Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--session`, `-s` | `str` | Required | Unique session identifier to filter and replay. |
| `--file`, `-f` | `Path` | `.blockstate/traces.jsonl` | Path to the JSON Lines trace file. |
| `--format` | `table \| json` | `table` | Render a formatted Rich terminal table or raw JSON array. |

#### Example

```bash
blockstate trace --session hipaa_session_9901 --file .blockstate/traces.jsonl --format table
```

---

### 2.6 `blockstate studio`

Launches the local **Blockstate Studio** web server (`StudioServer`), providing an interactive visual statechart canvas, sub-5ms Lengauer-Tarjan dominator tree overlay, trace replay timeline, bidirectional PEP 695 Python code generator, and signed MRM Dominance Audit Certificate exporter.

Built exclusively on Python's standard library (`http.server.ThreadingHTTPServer`) with zero runtime Node.js or external frontend dependencies.

#### Usage

```bash
blockstate studio [PATH] [--port 8420] [--host 127.0.0.1] [--no-browser]
```

#### Arguments & Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PATH` | `Path \| None` | `None` | Optional path to a Python agent file or directory. Automatically hot-reloads when the file's `mtime` changes on disk. |
| `--port`, `-p` | `int` | `8420` | TCP port number to bind the local HTTP server (`0..65535`). |
| `--host`, `-h` | `str` | `127.0.0.1` | Host IP address to bind the local HTTP server. |
| `--no-browser` | `bool` | `False` | Suppress automatic launching of the system web browser on startup. |

#### Studio Local REST API Endpoints

External CI scripts and custom developer tools can query the running Studio server directly over HTTP:

| Method & Endpoint | Request Payload | Response Summary |
| :--- | :--- | :--- |
| `GET /api/status` | None | Returns server health, `version`, `agent_file`, `agent_name`, `stage_count`, and `transition_count`. |
| `GET /api/graph` | None | Hot-reloads the agent file if modified on disk and returns the compiled `export_json` topology plus `source_code`. |
| `GET /api/traces?session=<ID>` | Query param `session` (optional) | Returns parsed turn trace records from `.blockstate/traces.jsonl`. |
| `POST /api/verify-dominance` | `{"precursor": "VerifyKYC", "targets": ["TransferFunds"]}` | Executes `verify_dominance` and returns `satisfied`, `elapsed_ms`, `dominator_tree`, `immediate_dominators`, and `violating_path`. |
| `POST /api/export-code` | `{"spec": { ... }}` (`StatechartSpec` payload) | Synthesises deterministic PEP 695 Python 3.12+ source code via `generate_python_source()`. |
| `POST /api/export-certificate` | `{"precursor": "...", "targets": [...], "format": "markdown" \| "json"}` | Generates a signed `SHA-256` MRM/CISO Dominance Audit Certificate. |

---

## 3. Exporting Signed SHA-256 MRM / CISO Dominance Audit Certificates

Regulated financial, insurance, and healthcare institutions require formal artefacts for Model Risk Management (MRM) sign-off under **UK FCA SYSC 13.7**, **Bank of England PRA SS1/23**, **EU AI Act Articles 9, 12 & 14**, and **OWASP LLM06 (Excessive Agency)**.

Blockstate generates cryptographic Dominance Audit Certificates via three methods:

1. **Via the Blockstate Studio UI**: Click **Export MRM Certificate** in the Studio verification panel.
2. **Via the Studio REST API (`POST /api/export-certificate`)**:
   ```bash
   curl -X POST http://127.0.0.1:8420/api/export-certificate \
     -H "Content-Type: application/json" \
     -d '{"precursor": "VerifyKYC", "targets": ["TransferFunds"], "format": "json"}'
   ```
3. **Programmatically in Python CI Pipelines**:
   ```python
   import hashlib
   from pathlib import Path
   from blockstate.cli.studio import (
       generate_audit_certificate_json,
       generate_audit_certificate_markdown,
   )
   from blockstate.compiler.ast_extractor import StaticGraphCompiler
   from blockstate.compiler.dominators import verify_dominance

   source_path = Path("examples/02_banking_kyc_dominator.py")
   source_code = source_path.read_text(encoding="utf-8")
   source_sha256 = hashlib.sha256(source_code.encode("utf-8")).hexdigest()

   graph = StaticGraphCompiler.compile_source(source_code, filename=source_path.name)
   adj = graph.adjacency_list(include_fallbacks=True)
   proof = verify_dominance(
       root=graph.initial_stage or "VerifyKYC",
       graph=adj,
       precursor="VerifyKYC",
       targets=["TransferFunds"],
   )

   # 1. Generate Markdown Certificate for PR / MRM review packs
   md_cert = generate_audit_certificate_markdown(
       graph=graph,
       proof=proof,
       source_file=source_path.name,
       source_sha256=source_sha256,
   )
   Path("mrm_dominance_certificate.md").write_text(md_cert, encoding="utf-8")

   # 2. Generate JSON Certificate with canonical SHA-256 seal
   json_cert = generate_audit_certificate_json(
       graph=graph,
       proof=proof,
       source_file=source_path.name,
       source_sha256=source_sha256,
   )
   assert json_cert["satisfied"] is True
   print(f"Certificate ID: {json_cert['certificate_id']}")
   print(f"Certificate SHA-256: {json_cert['certificate_sha256']}")
   ```

### JSON Audit Certificate Schema (`dominance_certificate_v1.json`)

```json
{
  "$schema": "https://blockstate.dev/schemas/dominance_certificate_v1.json",
  "agent_name": "BankingKYCDominatorAgent",
  "certificate_id": "CERT-BLK-1793388000",
  "certificate_sha256": "a4f9c2810b7d14e620...",
  "compiler_version": "0.1.0",
  "patent_notice": "UK Patent Pending (Process execution control system, Priority Date: 28 October 2026)",
  "precursor": "VerifyKYC",
  "proof": {
    "bypass_risk": 0.0,
    "dominator_tree": {
      "AssessAccountRisk": ["ManualComplianceReview", "TransferFunds"],
      "ManualComplianceReview": ["RejectTransfer"],
      "RejectTransfer": [],
      "TransferFunds": [],
      "VerifyKYC": ["AssessAccountRisk"]
    },
    "immediate_dominators": {
      "AssessAccountRisk": "VerifyKYC",
      "ManualComplianceReview": "AssessAccountRisk",
      "RejectTransfer": "ManualComplianceReview",
      "TransferFunds": "AssessAccountRisk"
    },
    "precursor_stage": "VerifyKYC",
    "root_stage": "VerifyKYC",
    "satisfied": true,
    "target_stages": ["TransferFunds"],
    "violating_path": null,
    "violating_target": null
  },
  "regulatory_mappings": {
    "bank_of_england_pra_ss1_23": "COMPLIANT",
    "eu_ai_act_article_14": "COMPLIANT",
    "owasp_llm_06": "COMPLIANT",
    "uk_fca_sysc_13_7": "COMPLIANT"
  },
  "satisfied": true,
  "source_file": "02_banking_kyc_dominator.py",
  "source_sha256": "8e1092ab...",
  "targets": ["TransferFunds"],
  "timestamp_utc": "2026-10-30T19:30:00Z"
}
```

---

## 4. Complete Error Code Taxonomy (`blockstate.errors`)

All framework exceptions inherit from [`BlockstateError`](../src/blockstate/errors.py) and carry a deterministic error code partitioned by architectural subsystem:

### 4.1 `BLK-AST-*` & `BLK-CFG-*`: Compile-Time AST & Configuration Errors

| Error Code | Exception Class | Trigger Condition | Remediation |
| :--- | :--- | :--- | :--- |
| `BLK-AST-014` (`[Blockstate E014]`) | `DynamicTransitionError` | 1. A `@Stage` method calls `getattr(...)` (dynamic reflection).<br/>2. A `Transition.to(...)` target is a variable, f-string, or empty string rather than a compile-time string literal.<br/>3. A `@field_validator` method contains a `Transition.*` call. | Replace dynamic targets with static string literals in `Transition.to("stage_name")` and move transition branching out of Pydantic validators into `@Stage` or `@Guard` methods. |
| `BLK-AST-002` | `UnreachableStageError` | One or more declared `@Stage` methods cannot be reached via directed edges (including fallback edges) from `initial_stage`. | Add a valid `@Transition` or fallback edge (`on_breach`, `on_refusal`, `on_max_turns_exceeded`) leading to the orphaned stage, or remove the dead stage. |
| `BLK-AST-001` | `InvalidStageGraphError` / `ASTError` | Agent class declares zero `@Stage` methods, omits an initial stage, or declares a transition to an undefined target stage. | Ensure every transition target matches a declared `@Stage(name=...)` identifier. |
| `BLK-CFG-001` | `DuplicateStageError` | Two or more `@Stage` methods in the same agent class declare the same stage name. | Assign a unique `name` to each `@Stage` decorator. |
| `BLK-CFG-002` | `ConfigurationError` | 1. A Pydantic slot schema's nesting depth exceeds `max_nesting_depth=8`.<br/>2. Malformed JSON or invalid `StatechartSpec` payload passed to `codegen`. | Flatten deeply nested Pydantic slot models to `<= 8` levels. |

### 4.2 `BLK-SEC-*`: Runtime Zero-Trust Security & Stack Isolation Errors

| Error Code | Exception Class | Trigger Condition | Remediation |
| :--- | :--- | :--- | :--- |
| `BLK-SEC-001` | `SecurityViolationError` | 1. An unwhitelisted or unregistered tool invocation is attempted outside the active stage's `MappingProxyType` dispatch table.<br/>2. `VaultCipher.decrypt()` detects a truncated ciphertext, `AES-256-GCM` authentication tag mismatch, or altered `session_id:schema_version:revision_id` AAD. | Add the tool explicitly to `@Stage(tools=[...])` if required at that stage, or route the violation via `on_security_violation`. Verify `BLOCKSTATE_VAULT_KEY` and checkpoint AAD integrity. |
| `BLK-SEC-002` | `UnauthorisedMutationError` | A turn or child digression frame attempts to overwrite an already validated and locked leaf slot path (`locked_slots`) when `allow_slot_overrides=False`. | Set `allow_slot_overrides=True` on `@Stage` if user corrections to previously locked fields are permitted in that stage, or pass an explicit `SlotMutation` when popping a frame. |
| `BLK-SEC-003` | `StackOverflowError` | Pushing a new digression `TaskFrame` onto `TaskStack` exceeds the bounded call stack depth (`max_stack_depth`, default `4`). | Ensure digression stages terminate with `Transition.pop_frame()` rather than recursively pushing unbounded nested digressions. |

### 4.3 `BLK-VAL-*`: Progressive $\Delta$-Hydration & Slot Validation Errors

| Error Code | Exception Class | Trigger Condition | Remediation |
| :--- | :--- | :--- | :--- |
| `BLK-VAL-001` | `SlotValidationError` | Base slot extraction or schema validation failure. | Inspect the candidate slot payload extracted by Pass 1. |
| `BLK-VAL-002` | `FieldValidationError` | One or more individual leaf paths failed Pydantic field constraints or `@field_validator` checks during `SlotHydrator.hydrate()`. Valid sibling fields in the same turn are preserved and locked; raw rejected inputs and PII spans are automatically scrubbed (`[REDACTED_PII]`). | Re-prompt the user for the invalid leaf paths reported in `HydrationResult.validation_errors`. |
| `BLK-VAL-003` | `DisqualifyingBreachError` | A `@field_validator` raised `DisqualifyingBreachError` (or `BreachError`) because the candidate value violates a hard business eligibility rule (e.g. commercial haulage on a personal motor policy). | Slot collection halts immediately on the current turn and the engine transitions to the stage declared in `@Stage(on_breach="...")`. |

### 4.4 `BLK-CON-*`, `BLK-STO-*` & `BLK-MOD-*`: Concurrency, Storage & Model Errors

| Error Code | Exception Class | Trigger Condition | Remediation |
| :--- | :--- | :--- | :--- |
| `BLK-CON-409` | `ConcurrentSessionError` | `StorageBackend.acquire_lease()` failed to acquire an exclusive fenced lease (`LeaseHandle`) for `session_id` within the fail-fast contention timeout (`2000ms`). | Return HTTP `409 Conflict` or debounce concurrent user messages for the same `session_id`. |
| `BLK-STO-001` | `StorageError` | Base persistence error in `StorageBackend`. | Verify database connectivity and permissions. |
| `BLK-STO-002` | `OptimisticLockError` | Compare-And-Swap (`revision_id` or `fence_token`) conflict detected during `save_checkpoint()`, indicating another worker modified or stole the session lease. | Abort the stale turn without overwriting the newer checkpoint. |
| `BLK-STO-003` | `LeaseTimeoutError` | The active session lease (`30000ms` TTL) expired before turn completion and `SessionLeaseHeartbeat` (`10000ms` interval) could not renew it. | Ensure custom tools respect async timeouts so turn execution completes while the lease is active. |
| `BLK-STO-004` | `CheckpointNotFoundError` | Requested `session_id` checkpoint does not exist in storage. | Initialise a new session or verify the `session_id`. |
| `BLK-MOD-001` | `ModelError` | Base Pass 1 classifier or Pass 2 response renderer failure. | Check model adapter configuration. |
| `BLK-MOD-002` | `ModelRefusalError` | Upstream model returned an explicit safety or policy refusal (`is_refusal=True`). | Configure `@Stage(on_refusal="...")` to route model refusals deterministically. |
| `BLK-MOD-003` | `Pass1TimeoutError` | Pass 1 `IntentClassifier.extract()` exceeded `timeout_ms` budget. | Use the local ONNX System-1 classifier or increase `timeout_ms`. |
