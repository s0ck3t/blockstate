# Architecture Diagrams — Blockstate (`blockstate`)

Visual topology, sequence, entity-relationship, and CI/CD operational diagrams referenced by `SPEC.md` and `ARCHITECTURE-SPINE.md`.

## 1. Two-Pass Turn Loop & Zero-Trust Execution Boundary

```mermaid
flowchart TD
    subgraph ClientLayer["Client & Outer Orchestrator Boundary"]
        U["User Utterance / Outer Orchestrator (as_tool) + session_id"] --> LEASE["StorageBackend: Acquire 30s Lease (2s Fail-Fast) & Load SessionCheckpoint"]
        LEASE --> PII["PIIVault.sanitise(): HMAC Session Tokenisation (<VAULT:TYPE_NN>)"]
    end

    subgraph TwoPassLoop["Two-Pass Turn Loop"]
        P1["Pass 1: System-1 ONNX (<=50ms p95) / Fast SLM (<100ms)"]
        PII --> P1
        P1 --> TC{"StatechartEngine.step() (<=5ms Core)"}
        TC -->|"Step 2a: Hydrate Delta"| MM["PartialSlotModel Delta-Hydration & TaskStack (Push/Pop)"]
        TC -->|"Step 2b: Delta == Empty"| DT["ToolGatekeeper: Ephemeral MappingProxyType Dispatch Table"]
        TC -->|"Step 2c: Evaluate DCG Guard"| SG["Declarative Control Grammar (@Stage / @Guard / @Transition[TargetStage])"]
        SG --> P2["Pass 2: Template / ChoicePayload (<120ms E2E) / Scoped LLM (<200ms p95)"]
    end

    subgraph ZeroTrustSecurity["Zero-Trust Execution Boundary"]
        DT -.->|"Physical Isolation + Detokenise[T]"| TOOLS["Active Stage Whitelisted Tools ONLY"]
    end

    subgraph PersistenceAudit["Persistence & Governance"]
        P2 --> COMMIT["StatechartEngine.commit_turn(): SHA-256 TurnLedgerRecord & AES-256-GCM AAD vault_map"]
        COMMIT --> SS[("StorageBackend CAS Commit (v1: PostgreSQL async SQLAlchemy / Local SQLite WAL / In-Memory)")]
        COMMIT -.->|"Session-Partitioned Ring Buffer + SIGTERM WAL"| TL["TurnLedger Sink (PostgreSQL / File .blockstate/wal / S3 WORM)"]
    end
```

## 2. Hexagonal Package Architecture (`AD-1`)

```mermaid
flowchart TD
    subgraph OuterAdapters["Infrastructure & UI Ring (blockstate.adapters / blockstate.cli)"]
        CLI["blockstate.cli (check / verify / trace / export)"]
        AD_STORE["adapters.store (v1: In-Memory / Local SQLite WAL / Postgres async SQLAlchemy; v1.2+ SPI: Redis / MSSQL / DynamoDB)"]
        AD_LLM["adapters.models (ONNX System-1 / PydanticAI / LiteLLM)"]
        AD_LEDGER["adapters.ledger (File .blockstate/wal / Postgres / S3 WORM)"]
        AD_OTEL["adapters.telemetry (OpenTelemetry GenAI 1.30 / .blockstate/traces.jsonl)"]
        AD_HANDOFF["adapters.langchain & handoff (as_tool / run_as_subflow Enclave Adapter)"]
    end

    subgraph PortsRing["Protocol Boundary (blockstate.ports)"]
        PORTS["StorageBackend SPI (src/blockstate/ports/storage.py), typing.Protocol Contracts & Canonical Envelopes"]
    end

    subgraph PureKernel["Pure Domain Kernel (Stdlib + Pydantic + Cryptography ONLY)"]
        SEC["blockstate.security (PIIVault & AES-256-GCM AAD Map)"]
        COMP["blockstate.compiler (DCG AST Parser [Blockstate E014] & Lengauer-Tarjan CFG)"]
        CORE["blockstate.core (StatechartEngine, TaskStack, PartialSlotModel, ToolGatekeeper)"]
    end

    CLI --> COMP
    CLI --> CORE
    CLI --> AD_OTEL
    AD_STORE --> PORTS
    AD_LLM --> PORTS
    AD_LEDGER --> PORTS
    AD_OTEL --> PORTS
    AD_HANDOFF --> CORE
    AD_HANDOFF --> PORTS
    PORTS --> CORE
    PORTS --> SEC
    COMP --> CORE
```

## 3. Runtime Execution & Two-Pass Zero-Trust Sequence (`AD-6`, `AD-7`, `AD-8`, `AD-9`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / Outer Orchestrator (as_tool)
    participant Lock as StorageBackend (Lease & Checkpoint)
    participant Vault as PIIVault (Ingress/Egress + AAD)
    participant P1 as Pass 1: IntentClassifier (<100ms)
    participant Engine as StatechartEngine (Core <=5ms)
    participant Gate as ToolGatekeeper (Scoped Dispatch)
    participant P2 as Pass 2: ResponseRenderer
    participant Ledger as TurnLedger (SHA-256 Outbox + WAL)

    User->>Engine: Utterance + session_id
    Engine->>Lock: acquire_lease(session_id, ttl=30s, wait=2s) + Load SessionCheckpoint
    Lock-->>Engine: SessionCheckpoint (schema_version, revision_id, SessionState, TaskStack, vault_map)
    Engine->>Vault: sanitise(Utterance, vault_map) -> VaultedUtterance (<VAULT:TYPE_NN>) + VaultDelta
    Engine->>P1: extract(VaultedUtterance, ActiveStage Delta Schema)
    P1-->>Engine: ExtractionResult(intent, candidate_slots, is_refusal, confidence)
    Engine->>Engine: Step 2a: PartialSlotModel.hydrate() (Vaulted[T] check) & Lock Validated Leaf Paths
    alt Validation Error or Breach
        Engine->>Engine: Route to on_breach or Sanitised FieldValidationError Re-elicitation
    else Digression Classified (len(stack) < max_stack_depth)
        Engine->>Engine: TaskStack.push(ChildTaskFrame, allow_slot_overrides=False)
    else All Delta Slots Hydrated (Delta == Empty)
        Engine->>Gate: Step 2b: build_dispatch_table(ActiveStage.tools)
        opt Stage Invokes Whitelisted Tool
            Engine->>Gate: invoke(tool_name, args, RunContext[Deps])
            Gate->>Vault: detokenise(Detokenise[T] args)
            Gate->>Gate: Execute Isolated Tool Handler
            Gate->>Vault: sanitise(tool_output)
        end
        Engine->>Engine: Step 2c: Evaluate Pure Python DCG Guard (@Guard / @Transition) -> Transition[TargetStage]
    end
    Engine->>P2: render(ActiveStage, ChoicePayload / Template / Scoped LLM)
    P2-->>Engine: VaultedResponse
    Engine->>Engine: Pop Completed Digression Frame (if Transition.pop_frame) & Compute SHA-256 TurnLedgerRecord
    Engine->>Vault: Encrypt vault_map (AES-256-GCM with AAD = session_id:schema_version:revision_id)
    Engine->>Lock: Atomic CAS Commit SessionCheckpoint (incl. pending_ledger_outbox) + Release Lease
    Engine-)Ledger: Async Flush (session_id Partitioned + Clear Outbox + SIGTERM .blockstate/wal Fallback)
    Engine-->>User: VaultedResponse / BlockstateTurnYield / BlockstateTurnComplete
```

## 4. Core Domain Entity Relationships

```mermaid
erDiagram
    AGENT ||--|{ STAGE : "declares (@Stage)"
    STAGE ||--o| PARTIAL_SLOT_MODEL : "collects (BaseModel)"
    STAGE ||--o{ TOOL_DEFINITION : "whitelists (Zero-Trust)"
    STAGE ||--|{ TRANSITION_EDGE : "guards (DCG @Guard / @Transition PEP 695 Union)"
    SESSION_CHECKPOINT ||--|| GLOBAL_SESSION_STATE : "persists"
    SESSION_CHECKPOINT ||--|| TASK_STACK : "manages (LIFO max_depth=6)"
    SESSION_CHECKPOINT ||--|| ENCRYPTED_VAULT_MAP : "binds (AES-256-GCM + AAD)"
    SESSION_CHECKPOINT ||--o{ PENDING_LEDGER_OUTBOX : "buffers (SIGKILL safe)"
    TASK_STACK ||--|{ TASK_FRAME : "contains"
    TASK_FRAME }|--|| STAGE : "binds active"
    SESSION_CHECKPOINT ||--|{ TURN_LEDGER_RECORD : "chains (SHA-256)"
```

## 5. Operational, CI/CD & Deployment Envelope (`AD-11`, `AD-12`, `AD-13`)

```mermaid
flowchart LR
    subgraph DevWorkstation["Developer Workstation & Git Boundary"]
        CODE["Python 3.12+ DCG Enclave Code & .env.example"] --> HOOKS["Pre-Commit Gate: Gitleaks + detect-secrets + blockstate-pii-guard"]
        HOOKS --> CLI_LOCAL["blockstate check & blockstate verify (<50ms DCG AST [Blockstate E014] & Dominator Proof)"]
    end

    subgraph CIPipeline["GitHub Actions / Enterprise CI Gate"]
        CLI_LOCAL --> LINT["Ruff + mypy --strict + pyright + import-linter"]
        LINT --> TEST["Pytest Matrix: Unit (>=95% Core) + Hypothesis + 5 Port Contract Suites"]
        TEST --> LIC["pip-licenses Allowlist Gate + CycloneDX SBOM + pip-audit + Bandit"]
    end

    subgraph ProdRuntime["Production Runtime Environment (Stateless Enclave Workers >=250 TPS)"]
        LIC --> WORKER["Blockstate Enclave Async Worker Pods (<=40MB Core Footprint)"]
        ORCH["Outer Orchestrator (LangGraph / Semantic Kernel / Bedrock) via as_tool()"] <--> WORKER
        WORKER <--> DB[("v1 StorageBackend SPI: PostgreSQL (async SQLAlchemy) / Local SQLite (WAL) / In-Memory")]
        WORKER -.-> SPI_V12[("v1.2+ StorageBackend SPI: Redis / MS SQL Server / AWS DynamoDB")]
        WORKER -.-> LEDGER_SINK[("TurnLedger Sink: Postgres / S3 WORM + Local .blockstate/wal Drain")]
        WORKER -.-> OTEL_COL["OpenTelemetry Collector (GenAI 1.30 Spans)"]
    end
```
