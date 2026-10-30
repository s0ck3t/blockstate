# Getting Started with Blockstate (60-Second Quickstart)

Blockstate (`blockstate`) is a deterministic statechart runtime, static AST control-flow compiler, and transactional compliance execution enclave for Python 3.12+. It enforces mathematical execution guarantees, stage-scoped tool whitelists, and ingress PII tokenisation for regulated conversational AI workflows.

This guide walks through installing `blockstate`, scaffolding a ready-to-verify compliance enclave with `blockstate init`, running compile-time AST and Lengauer-Tarjan dominator proofs (`blockstate check` and `blockstate verify`), inspecting the statechart in `blockstate studio`, and executing a multi-turn session.

---

## 1. Prerequisites & Installation

Blockstate requires **Python 3.12 or newer** (using PEP 695 generic type parameters). The core package has a memory footprint under 40 MB and ships with `InMemoryStateStore`, the static Declarative Control Grammar (DCG) compiler, the Lengauer-Tarjan dominator solver, `PIIVault`, and the `blockstate` CLI.

### Install Core Package

```bash
# Using pip
pip install blockstate

# Using uv
uv add blockstate
```

### Install Optional Production Extras

Install storage, model, and observability adapters according to your deployment target:

```bash
# Local development & edge deployments (SQLite WAL StorageBackend + local ONNX System-1 classifier)
pip install "blockstate[local]"
# or:
uv add "blockstate[local]"

# Cloud production workloads (PostgreSQL async SQLAlchemy + asyncpg, PydanticAI models & OpenTelemetry)
pip install "blockstate[postgres,models,otel]"
# or:
uv add "blockstate[postgres,models,otel]"

# Full enterprise installation (PostgreSQL, SQLite WAL, S3 WORM Ledger, LiteLLM, ONNX, OpenTelemetry)
pip install "blockstate[all]"
# or:
uv add "blockstate[all]"
```

---

## 2. Scaffold a Compliance Enclave (`blockstate init`)

The quickest way to create a verified statechart project is the `blockstate init` scaffolder. It generates a complete project directory containing a Declarative Control Grammar agent, a full `pytest` verification suite, a `.env.example` configuration file, and a GitHub Actions pull-request verification workflow.

### Available Starter Templates

| Template Flag | Generated Agent Class | Default Precursor Dominance Assertion | Primary Capabilities Demonstrated |
| :--- | :--- | :--- | :--- |
| `--template banking` | `BankingTransferAgent` | `verify_identity -> execute_transfer` | UK Faster Payments settlement, `@Guard` identity interlocks, AML threshold routing |
| `--template insurance` | `InsuranceClaimAgent` | `verify_policy -> fast_track_settlement` | Motor FNOL intake, `TaskStack` pushdown digressions (`allow_digressions=["policy_faq"]`) |
| `--template healthcare` | `HealthcareTriageAgent` | `patient_intake -> emergency_dispatch, schedule_clinic` | HIPAA / NHS Caldicott `Vaulted[str]` slot fields and volatile `Detokenise[str]` tool injection |
| `--template minimal` | `MinimalAgent` | `intake -> complete` | Clean 3-stage prototype (`intake` -> `process_request` -> `complete`) |

### Run the Scaffolder

Scaffold a retail banking compliance enclave into a new directory `./my_banking_enclave`:

```bash
blockstate init ./my_banking_enclave --template banking
```

You can also customise the module and file prefix using `--name` (or `-n`), and overwrite non-empty directories using `--force` (or `-f`):

```bash
blockstate init ./my_enclave --template insurance --name motor_fnol --force
```

### Generated Project Layout

Running `blockstate init ./my_banking_enclave --template banking` creates five files:

```text
my_banking_enclave/
├── banking_agent.py                        # Declarative Control Grammar statechart & simulation runner
├── test_banking_agent.py                   # Automated pytest suite (AST, dominators, turns & BLK-SEC-001)
├── .env.example                            # Runtime configuration & AES-256-GCM vault key template
├── .github/
│   └── workflows/
│       └── blockstate-verify.yml           # CI pipeline running blockstate check, verify & pytest
└── README.md                               # Enclave verification commands & documentation
```

Configure your local environment by copying `.env.example` to `.env` and generating a 32-byte hexadecimal `AES-256-GCM` key for `PIIVault`:

```bash
cd my_banking_enclave
cp .env.example .env
```

---

## 3. Static AST & Dominator Verification (`check` & `verify`)

Before running any conversational turns or connecting an LLM, Blockstate compiles your Python source file using `ast.parse` without executing bytecode.

### Step 3.1: Offline AST & Reachability Check (`blockstate check`)

`blockstate check` validates the Declarative Control Grammar (`@Stage`, `@Transition`, `@Guard`), confirms that every stage is reachable via breadth-first search from `initial_stage` (`BLK-AST-002`), and rejects dynamic reflection (`getattr`), non-literal transition targets, or `Transition` calls inside `@field_validator` methods (`BLK-AST-014` / `[Blockstate E014]`):

```bash
blockstate check banking_agent.py
```

Expected console output:

```text
╭─────────────────────── Blockstate Check ───────────────────────╮
│ Declarative Control Grammar Verified                           │
│ Agent: BankingTransferAgent                                    │
│ Initial Stage: verify_identity                                 │
│ Total Stages: 5 | Total Transitions: 5                         │
╰────────────────────────────────────────────────────────────────╯
                        Declared Stages (BankingTransferAgent)
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Stage Name           ┃ Type     ┃ Max Turns ┃ Allowed Tools              ┃ Permitted Digressions ┃ Target Fallback ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ assess_transfer_risk │ Standard │         5 │ screen_sanctions_and_fraud │ none                  │ none            │
│ compliance_review    │ Standard │         5 │ none                       │ none                  │ none            │
│ execute_transfer     │ Terminal │         5 │ settle_faster_payment      │ none                  │ none            │
│ reject_transfer      │ Terminal │         5 │ none                       │ none                  │ none            │
│ verify_identity      │ Initial  │         5 │ none                       │ none                  │ none            │
└──────────────────────┴──────────┴───────────┴────────────────────────────┴───────────────────────┴─────────────────┘
```

### Step 3.2: Mathematical Precursor Dominance Proof (`blockstate verify`)

`blockstate verify` builds the full directed control-flow graph (including `on_refusal`, `on_max_turns_exceeded`, `on_breach`, and `on_security_violation` fallback edges) and executes the **Lengauer-Tarjan dominator tree solver** (`LengauerTarjanSolver`). It proves in under 50 milliseconds that every possible execution path from the root stage to your privileged target stages must pass through the designated precursor stage:

```bash
blockstate verify banking_agent.py --dominates "verify_identity -> execute_transfer"
```

Expected console output:

```text
╭─────────────── Verification Certificate ────────────────╮
│ Lengauer-Tarjan Dominance Certified                     │
│                                                         │
│ Precursor: verify_identity                              │
│ Protected Targets: execute_transfer                     │
│ Root Stage: verify_identity                             │
│ Proof Status: 100% of paths dominated                   │
│ Bypass Risk: 0.00% (Mathematical Invariant)             │
╰─────────────────────────────────────────────────────────╯
```

If a developer introduces a shortcut edge that bypasses `verify_identity`, `blockstate verify` exits with code `1` and prints the exact breadth-first counterexample bypass path in $G \setminus \{\text{precursor}\}$.

---

## 4. Launch the Local Visual Inspector (`blockstate studio`)

Blockstate includes a zero-dependency local visual statechart canvas and trace inspector built on Python's standard library `ThreadingHTTPServer`.

Launch Studio pointed at your agent file:

```bash
blockstate studio banking_agent.py
```

Options include customising the host, port, or headless browser behaviour:

```bash
blockstate studio banking_agent.py --host 127.0.0.1 --port 8420 --no-browser
```

Inside **Blockstate Studio** (`http://127.0.0.1:8420/`), you can:
1. **Inspect Statechart Topology**: View initial stages, standard stages, terminal stages, stage-scoped tool whitelists, permitted digression frames, and guard edges, with automatic hot-reload whenever `banking_agent.py` is saved on disk.
2. **Run Interactive Lengauer-Tarjan Dominator Proofs**: Select any precursor stage and one or more target stages to highlight the dominator tree in under 5ms or visualise violating bypass paths in red.
3. **Export Signed MRM / CISO Dominance Audit Certificates**: Generate Markdown or JSON compliance certificates bound to the source file's `SHA-256` digest and mapped to **UK FCA SYSC 13.7**, **PRA SS1/23**, **EU AI Act Article 14**, and **OWASP LLM06**.
4. **Generate PEP 695 Python 3.12+ Code**: Round-trip visual `StatechartSpec` definitions directly into static Python source code that passes `blockstate check` and `mypy --strict`.
5. **Replay Turn Traces**: Inspect `.blockstate/traces.jsonl` sessions turn-by-turn, verifying `RFC 8785 JCS` canonical `SHA-256` hash chains and slot delta hydration.

---

## 5. Run a Multi-Turn Statechart Session

Every scaffolded enclave includes a runnable multi-turn simulation and an automated `pytest` suite.

### Run the Multi-Turn Simulation

Execute the scaffolded banking enclave directly:

```bash
python banking_agent.py
```

Output:

```text
=== Blockstate Banking Enclave Simulation ===
Turn 1 State: in_progress (BlockstateTurnYield)
Turn 2 State: completed (BlockstateTurnComplete)
Settlement Result: {'status': 'settled', 'rail': 'FPS'}
```

### How the Multi-Turn Session Works in Code

Here is the core execution loop inside `banking_agent.py`:

```python
import asyncio
from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.engine import StatechartEngine
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield
from banking_agent import BankingTransferAgent, MockBankingClassifier


async def run_session() -> None:
    # 1. Instantiate the verified DCG agent, storage backend, and Pass 1 classifier
    agent = BankingTransferAgent()
    storage = InMemoryStateStore()
    classifier = MockBankingClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "session_quickstart_001"

    # 2. Turn 1: Customer provides KYC credentials (verify_identity -> assess_transfer_risk)
    turn_1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="My customer ID is CUST-001 and sort code 20-00-00.",
        )
    )
    assert isinstance(turn_1, BlockstateTurnYield)
    print(f"Turn 1 [{turn_1.state}]: {turn_1.message}")

    # 3. Turn 2: Customer provides transfer details (assess_transfer_risk -> execute_transfer)
    turn_2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Transfer 250 GBP to account 88776655.",
        )
    )
    assert isinstance(turn_2, BlockstateTurnComplete)
    print(f"Turn 2 [{turn_2.state}]: {turn_2.result}")
    print(f"Tamper-Evident Ledger Head Hash: {turn_2.ledger_head_hash}")


if __name__ == "__main__":
    asyncio.run(run_session())
```

### Run the Scaffolded Test Suite

Verify that your enclave passes all five automated checks (static AST compilation, precursor dominance certification, synthetic bypass counterexample detection, multi-turn runtime execution, and `BLK-SEC-001` stage-scoped tool gatekeeper isolation):

```bash
pytest test_banking_agent.py -v
```

---

## 6. Next Steps

- [**CLI & Studio Reference (`docs/CLI_AND_STUDIO_REFERENCE.md`)**](CLI_AND_STUDIO_REFERENCE.md): Complete command syntax, flags, exit codes, error code catalogue (`BLK-AST-014` to `BLK-STO-004`), and MRM certificate schemas.
- [**Tutorial 1: Enterprise Motor Insurance Claims (`docs/tutorials/motor_insurance_claim_tutorial.md`)**](tutorials/motor_insurance_claim_tutorial.md): Pushdown `TaskStack` digressions, PAS verification, and 6-trial adversarial audit.
- [**Tutorial 2: Retail Banking KYC Dominator Proofs (`docs/tutorials/02_banking_kyc_dominator_tutorial.md`)**](tutorials/02_banking_kyc_dominator_tutorial.md): Multi-rail wire transfers, `LengauerTarjanSolver` internals, and CI bypass detection.
- [**Tutorial 3: Healthcare HIPAA & NHS `PIIVault` (`docs/tutorials/03_healthcare_hipaa_piivault_tutorial.md`)**](tutorials/03_healthcare_hipaa_piivault_tutorial.md): Ingress NHS Modulus-11 and Luhn Mod-10 checksum tokenisation, `AES-256-GCM` AAD binding, and `Detokenise[T]`.
- [**Tutorial 4: LangGraph Enclave Handoff (`docs/tutorials/04_langgraph_enclave_handoff_tutorial.md`)**](tutorials/04_langgraph_enclave_handoff_tutorial.md): Mounting verified Blockstate enclaves inside LangGraph or outer routers via `as_tool()`.
