# Compliance, Formalisms & Developer Surface — Blockstate (`blockstate`)

Reference matrices, mathematical invariants, user journeys, and canonical API patterns cited by `SPEC.md`.

## 1. Regulatory & Compliance Alignment

| Regulatory Framework | Article / Standard | Blockstate Mechanism & Guarantee | Bound Capabilities |
| :--- | :--- | :--- | :--- |
| **EU AI Act** | Article 12 (Record-Keeping) | Immutable, SHA-256 hash-chained `TurnLedger` recording prompt hashes, vaulted inputs/outputs, state transitions, and `exposed_tools` per turn, backed by a crash-safe transactional outbox and local `.blockstate/wal` drain. | `CAP-16`, `CAP-17`, `CAP-21` |
| **EU AI Act** | Article 14 (Human Oversight) | Deterministic `max_turns` circuit breakers (`on_max_turns_exceeded`), model refusal short-circuits (`on_refusal`), and explicit human-escalation fallback stages. | `CAP-2`, `CAP-3`, `CAP-7` |
| **UK FCA** | SYSC 13.7 (Operational Risk) | Build-time `blockstate verify --dominates` over the Declarative Control Grammar (`@Stage`, `@Transition`, `@Guard`, rejecting dynamic targets via `[Blockstate E014]`) proving via Lengauer-Tarjan dominator trees that compliance checkpoints (e.g. `verify_identity`) cannot be bypassed across any branch tier. | `CAP-10`, `CAP-11`, `CAP-12` |
| **HIPAA / GDPR** | Safe Harbor / Data Minimisation | Post-lease `PIIVault` HMAC-SHA256 session tokenisation (`<VAULT:TYPE_NN>`) and AES-256-GCM AAD-encrypted `vault_map`, preventing raw PHI/PII from entering LLM prompts, validation errors, telemetry spans, or audit logs. | `CAP-6`, `CAP-15`, `CAP-24` |
| **SOC 2 Type II** | Trust Services Criteria (Security & Audit) | Zero-trust stage-scoped `MappingProxyType` dispatch tables and dynamic schema scoping preventing unauthorised tool execution (`BLK-SEC-001`). | `CAP-4`, `CAP-5`, `CAP-8` |

## 2. Mathematical Formalisms

### 2.1 Lengauer-Tarjan Graph Dominator Verification & Declarative Control Grammar (DCG) (`CAP-10`, `CAP-11`)
In `blockstate.compiler`, the Control Flow Graph (CFG) of `@Stage`, `@Transition`, and `@Guard` definitions in the **Declarative Control Grammar (DCG)** is extracted via `ast.parse` into a directed graph $G = (V, E, r)$ with root entry stage $r$. Because **Rice's Theorem** proves that static reachability over arbitrary Turing-complete Python reflection (such as `getattr(self, dynamic_state)()`) is mathematically undecidable, `blockstate check` and `blockstate verify` reject dynamic transition targets at compile time with explicit diagnostic output:

```text
[Blockstate E014] Dynamic transition destination detected at mortgage_flow.py:42.
Transitions must reference static State definitions to enable Lengauer-Tarjan dominator verification.
```

A precursor stage $d \in V$ dominates a target stage $n \in V$ ($d \text{ dom } n$) if and only if every path from $r$ to $n$ contains $d$. Immediate dominators are computed via Lengauer-Tarjan in $\mathcal{O}(|E| \log |V|)$ / $\mathcal{O}(|E| \alpha(|E|, |V|))$ time (`< 50ms` for up to 500 nodes). For multi-branch assertions (`blockstate verify --dominates "verify_identity -> [claim_under_100, claim_100_to_200, claim_over_200]"`), the compiler verifies $d \text{ dom } t_i$ for every target $t_i$ and guarantees call-return integrity for `allow_digressions` sub-graphs.

### 2.2 Pushdown Automata Digression Complexity (`CAP-8`, `CAP-9`)
Active conversational context is represented as a bounded LIFO stack $S = [T_0, T_1, \dots, T_k]$ ($k < \text{max\_stack\_depth} = 6$), where $T_k$ is the active `TaskFrame`. When a permitted digression is classified, a child frame $T_{k+1}$ is pushed with read-only access to parent slots and scoped to the digression's tool whitelist. Upon `Transition.pop_frame()`, $T_{k+1}$ is popped during `commit_turn()` after Pass 2 renders the digression response, reducing state-graph edge complexity across $N$ primary stages and $M$ digressions from $\mathcal{O}(N \times M)$ to $\mathcal{O}(N + M)$.

### 2.3 Leaf-Path $\Delta$-Hydration (`CAP-6`, `CAP-7`)
For a stage collecting target Pydantic schema $M$ (recursively wrapped up to `max_nesting_depth=8` by `PartialSlotMetaclass` with `UNSET` sentinels), the unhydrated delta at turn $t$ is $\Delta_t = \text{RequiredLeafPaths}(M) \setminus \text{HydratedLeafPaths}(T_k)$. Validated leaf paths are locked in `TaskFrame.locked_slots`; invalid leaf paths emit sanitised `FieldValidationError` records (`include_input=False`, `include_context=False`) that either trigger an immediate `on_breach` transition or short-circuit Pass 2 to re-elicit only the invalid fields. The strict model $M$ is instantiated once and only once when $\Delta_t = \emptyset$.

## 3. Competitive Architecture & Enclave Integration Matrix

Rather than competing as a monolithic general-purpose orchestrator (the "Enterprise Island Trap"), Blockstate mounts inside outer orchestrators (LangGraph, Microsoft Semantic Kernel, AutoGen, AWS Bedrock) as a **transactional compliance execution enclave** via `from blockstate.adapters.langchain import as_tool`.

| Dimension | LangGraph | NeMo Guardrails (Colang 2.0) | LlamaIndex Workflows | Prefect ControlFlow | PydanticAI / `pydantic-graph` | Blockstate (`blockstate`) Enclave |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Transition Determinism** | Probabilistic / manual conditional edges | Probabilistic LLM intent rails | Hybrid code / LLM events | Hybrid tasks / ReAct | Deterministic Python in `run()` | **100% Deterministic (DCG `@Stage`, `@Guard`, `@Transition` & PEP 695 Unions)** |
| **Physical Tool Containment** | No (shared `ToolNode`) | Partial (DSL action rails) | No (imperative filtering) | Partial (task prompt scope) | Partial (`prepare` callback) | **Yes (ephemeral per-stage `MappingProxyType` dispatch table)** |
| **Offline AST Dominator Proofs** | No | Partial (DSL syntax check) | No | No | Partial (`mypy` return types) | **Yes (`ast.parse` DCG + `[Blockstate E014]` + Lengauer-Tarjan `blockstate verify`)** |
| **Digression Call Stack** | Manual subgraphs ($\mathcal{O}(N \times M)$) | Concurrent flows | Manual event routing | Sub-task nesting | Manual branching | **Pushdown `TaskStack` (`TaskFrame` push/pop, $\mathcal{O}(N + M)$)** |
| **Multi-Turn Slot Engine** | Manual prompt state | Dialog rail scripts | Manual state | Task output validation | Single-turn structured output | **Recursive `PartialSlotModel` with $\Delta$-Hydration & `Vaulted[T]`** |
| **Turn Latency Architecture** | Serialised LLM ($1\text{--}3\text{s}$) | Multi-hop LLM ($3\text{--}6\text{s}$) | Single-pass async LLM | ReAct loop | Single-pass async LLM | **Two-Pass (`<=50ms` ONNX / `<100ms` SLM + `<120ms` Template/Choice)** |
| **PII & Audit Provenance** | Checkpoints only | Optional Presidio rails | Telemetry traces | Task records | Message snapshots | **HMAC/AES-GCM `PIIVault` + SHA-256 JCS `TurnLedger` Outbox** |

## 4. Canonical User Journeys & Public API Surface

### 4.1 User Journeys Summary
- **UJ-1 (Motor Insurance Claim with Digressions & Validation Short-Circuit):** Platform engineer defines `@Stage(name="incident_details", collect=IncidentSlots, allow_digressions=[PolicyFaqTool])` and tiered payout stages (`auto_payout` for `<= £100`, `manager_review` for `> £100`). Mid-collection FAQ triggers `TaskStack` push/pop with parent slots intact; future incident date triggers isolated field re-elicitation without losing prior validated slots (`CAP-1`..`CAP-9`, `CAP-13`, `CAP-14`).
- **UJ-2 (CI/CD Multi-Branch Dominator Audit):** MRM officer runs `blockstate verify --dominates "verify_identity -> [claim_under_100, claim_100_to_200, claim_over_200]"` in CI. Valid graphs emit a cryptographic assertion certificate and Mermaid diagram (`exit 0`); any dynamic transition fails with `[Blockstate E014]` and any VIP bypass route fails the build (`exit 1`) with the exact counter-example path `Entry -> CheckVIP -> AutoPayout` (`CAP-10`..`CAP-12`).
- **UJ-3 (Disputed Interaction Forensic Investigation):** SRE runs `blockstate trace --session <session_id>` to inspect the SHA-256 hash-chained `TurnLedger`, proving `exposed_tools` in `@Stage("account_overview")` physically excluded `issue_credit` and all PII remained vaulted (`CAP-4`, `CAP-5`, `CAP-15`..`CAP-17`, `CAP-21`).

### 4.2 Declarative Stage, Branching & Outer Orchestrator Enclave Pattern
```python
from pydantic import BaseModel, Field
from blockstate import Agent, Stage, Transition, Guard, ChoicePayload, Vaulted, Detokenise
from blockstate.adapters.langchain import as_tool

class ClaimSlots(BaseModel):
    policy_id: str = Field(description="Policy identifier e.g. POL-12345")
    postcode: Vaulted[str] = Field(description="Customer UK postcode")
    incident_date: str = Field(description="Date of incident in YYYY-MM-DD")
    damage_amount: float = Field(description="Estimated damage amount in GBP")

class MotorClaimAgent(Agent):
    @Stage(
        name="collect_details",
        collect=ClaimSlots,
        allow_digressions=["policy_faq"],
        allow_slot_overrides=False,
        max_turns=5,
        on_breach="disqualified",
        on_max_turns_exceeded="escalate",
        on_refusal="escalate",
    )
    @Guard
    @Transition(targets=("tier_auto_payout", "tier_manager_review", "escalate"))
    async def collect_details(
        self, slots: ClaimSlots
    ) -> Transition["tier_auto_payout" | "tier_manager_review" | "escalate"]:
        if self.session.is_suspicious:
            return Transition.to("escalate", reason="Flagged account")
        if slots.damage_amount <= 100.0:
            return Transition.to("tier_auto_payout")
        return Transition.to("tier_manager_review")

    @Stage(
        name="tier_auto_payout",
        tools=["disburse_funds_direct"],
        terminal=True,
    )
    async def tier_auto_payout(self) -> Transition[None]:
        await self.tools.disburse_funds_direct(self.session.user_id, self.slots.damage_amount)
        return Transition.end(message="Your claim under £100 has been approved and disbursed.")

# Expose the entire formal statechart as a single validated tool to LangGraph / outer orchestrators:
from my_regulated_workflows import MortgageOriginationEnclave

langgraph_agent.bind_tools([
    as_tool(MortgageOriginationEnclave, name="execute_mortgage_transaction"),
    as_tool(MotorClaimAgent, name="file_motor_claim"),
])
```

### 4.3 CLI Surface (`blockstate.cli.main`)
- `blockstate check [path]`: Statically parse Python ASTs over the Declarative Control Grammar (`@Stage`, `@Transition`, `@Guard`), reject dynamic transition targets (`[Blockstate E014]`), and validate PEP 695 transition unions and digression call-return sub-graphs (`CAP-10`).
- `blockstate verify [path] --dominates "<PrecursorStage> -> <ProtectedStage(s)>"`: Run Lengauer-Tarjan dominator verification across single or bracketed multi-branch targets (`CAP-11`).
- `blockstate trace --session <session_id> [--file <path>] [--format table|json]`: Replay turn-by-turn slot hydration, `exposed_tools`, and SHA-256 hash chains from `.blockstate/traces.jsonl` or configured `StorageBackend`/`TurnLedger` backends (`CAP-21`).
- `blockstate export [path] --format [mermaid|json]`: Export verified statechart topology diagrams and stage tool schemas (`CAP-12`).
