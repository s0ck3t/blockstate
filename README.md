<div align="center">

# 🛤️ Blockstate (`blockstate`)

### **Deterministic Statecharts, Compile-Time Dominator Proofs & Zero-Trust Tool Gating for Enterprise LLMs**

*"FastAPI meets XState for Regulated AI — where the LLM is never the orchestrator."*

[![Python 3.12+](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-2563eb.svg)](https://www.python.org/)
[![Typed: mypy --strict & pyright](https://img.shields.io/badge/typing-PEP%20695%20%7C%20strict-0d9488.svg)](https://peps.python.org/pep-0695/)
[![Coverage: >=95% Core / >=90% Repo](https://img.shields.io/badge/coverage-%E2%89%A595%25%20core%20%7C%20%E2%89%A590%25%20branch-16a34a.svg)](#enterprise-testing-coverage--interface-contracts)
[![Architecture: Hexagonal import-linter](https://img.shields.io/badge/architecture-hexagonal%20ports%20%26%20adapters-7c3aed.svg)](docs/architecture/ARCHITECTURE-SPINE.md)
[![Security: Zero-Trust & Gitleaks](https://img.shields.io/badge/security-zero--trust%20%7C%20PIIVault-dc2626.svg)](SECURITY.md)
[![Licences: 100% Permissive Audited](https://img.shields.io/badge/licences-MIT%20%2F%20Apache--2.0%20verified-0284c7.svg)](THIRD_PARTY_LICENSES.md)

[**Quick Start**](#60-second-quick-start) · [**Why Blockstate?**](#why-blockstate) · [**4 Domain Examples**](#domain-examples-4-complete-walkthroughs) · [**CLI, DCG & Dominator Proofs**](#cli-reference-declarative-control-grammar--compile-time-verification) · [**Testing & Contracts**](#enterprise-testing-coverage--interface-contracts) · [**Subcomponent Licences**](THIRD_PARTY_LICENSES.md)

</div>

---

## ⚡ Why Blockstate?

Derived from **railway absolute block signalling**—where physical track circuits prevent a train from entering an occupied or unverified block section—and **deterministic state machines**, **Blockstate** brings mathematical execution guarantees to conversational AI.

Most agent frameworks (early LangChain, AutoGen, CrewAI) rely on the **ReAct (Reason + Act)** loop: they hand an LLM a global bag of tools and let probabilistic token generation decide which tool to call, when to transition between workflow steps, and how to mutate state.

In **regulated enterprise domains**—retail banking, mortgage origination, insurance claims, healthcare triage, and telecommunications—giving an LLM autonomous control over execution flow and tool invocation is an unacceptable legal and operational liability (under **EU AI Act Articles 12 & 14**, **UK FCA SYSC 13.7**, **HIPAA**, and **SOC 2 Type II**).

At the same time, Blockstate avoids the **"Enterprise Island Trap"**: it is **not** designed to replace high-level enterprise orchestrators (such as LangGraph, Microsoft Semantic Kernel, AutoGen, or AWS Bedrock). Instead, Blockstate operates as a **transactional compliance execution enclave** that outer orchestrators invoke via a first-class `as_tool()` adapter whenever a conversation enters a regulated boundary.

**Blockstate fundamentally inverts the control hierarchy inside regulated workflows:**

1. **100% Deterministic State Transitions via Declarative Control Grammar (DCG):** The pure Python statechart runtime owns every transition and guard condition through the static **Declarative Control Grammar (`@Stage`, `@Transition`, `@Guard`)**. The LLM is demoted to a bounded semantic worker used strictly for structured slot extraction (Pass 1) and natural language rendering (Pass 2).
2. **Zero-Trust Physical Tool Gating:** Unpermitted tools do not exist in the prompt schema or the Python `MappingProxyType` dispatch table for that turn. Prompt injection cannot invoke a tool that is physically absent from the active `@Stage` memory space.
3. **Compile-Time Mathematical Dominator Proofs (`blockstate verify`) & Rice's Theorem Boundaries:** Because unconstrained Python reflection (`getattr(self, dynamic_state)()`) is mathematically undecidable under **Rice's Theorem**, Blockstate enforces static DCG AST rules (`[Blockstate E014]`) and runs the **Lengauer-Tarjan dominator tree algorithm** in `< 50ms` during CI/CD to prove that mandatory compliance checkpoints (e.g. `verify_identity`) strictly dominate protected actions (e.g. `disburse_funds`) across every possible branch before code reaches production.
4. **Pushdown Automata for Conversational Digressions (`TaskStack`):** Users rarely fill out multi-turn forms linearly. When a customer asks *"Will this affect my no-claims bonus?"* halfway through an insurance claim, Blockstate pushes a read-only child `TaskFrame` onto the call stack, answers the FAQ, pops the frame, and resumes slot collection with parent data 100% intact—reducing graph edge complexity from $\mathcal{O}(N \times M)$ to $\mathcal{O}(N + M)$.
5. **Recursive $\Delta$-Hydration (`PartialSlotModel`):** Declare a standard Pydantic v2 model (including deeply nested child models) on `@Stage(collect=ClaimModel)`. Blockstate automatically relaxes missing fields across intermediate turns, validates supplied fields immediately, locks validated fields against accidental overwrite, and short-circuits invalid fields for targeted re-elicitation.
6. **Tokenised `PIIVault` & Hash-Chained `TurnLedger`:** Sensitive PII/PHI is replaced at ingress with HMAC-keyed session tokens (`<VAULT:POSTCODE_01>`) before touching any LLM or telemetry log, while every turn is recorded in a tamper-evident SHA-256 hash chain.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph ClientBoundary["1. Client / Outer Orchestrator & Zero-Trust Ingress Boundary"]
        U["Customer Utterance / as_tool() Enclave Call + session_id"] --> LEASE["StorageBackend.acquire_lease()<br/>Fail-Fast 2s Timeout | 30s TTL | 10s Heartbeat"]
        LEASE --> PII["PIIVault.sanitise()<br/>HMAC Tokenisation (&lt;VAULT:TYPE_NN&gt;)"]
    end

    subgraph TwoPassLoop["2. Two-Pass Deterministic Turn Pipeline (DCG Enclave)"]
        PII --> P1["Pass 1: IntentClassifier (&lt;100ms)<br/>Local ONNX System-1 / ModernBERT / Fast SLM"]
        P1 --> ENGINE{"StatechartEngine (&le;5ms Core)<br/>DCG (@Stage, @Transition, @Guard) &amp; PEP 695"}
        ENGINE -->|"Hydrate &amp; Lock Leaf Paths"| DELTA["PartialSlotModel &Delta;-Hydration<br/>&Delta; = Required \ Hydrated"]
        ENGINE -->|"Off-Topic Allowed Intent"| STACK["TaskStack Pushdown Automata<br/>Push/Pop Isolated TaskFrame"]
        ENGINE -->|"Scope Active Stage Tools"| GATE["ToolGatekeeper<br/>Frozen MappingProxyType Dispatch Table"]
        GATE -.->|"Detokenise[T] Only"| TOOLS["Whitelisted Stage Tools ONLY"]
        ENGINE --> P2["Pass 2: ResponseRenderer<br/>Canned Template / ChoicePayload (&lt;15ms) or Scoped LLM"]
    end

    subgraph GovernanceAudit["3. StorageBackend SPI, Telemetry & Audit Provenance"]
        ENGINE -->|"Atomic CAS Commit (schema_version)"| STORE[("v1 StorageBackend SPI:<br/>In-Memory | SQLite (WAL) | PostgreSQL")]
        ENGINE -.->|"RFC 8785 JCS + SHA-256 Chain"| LEDGER["TurnLedger Ring Buffer<br/>(PostgreSQL / S3 WORM + .blockstate/wal Drain)"]
        ENGINE -.->|"Post-Vault Spans"| OTEL["OpenTelemetry GenAI 1.30 &amp;<br/>.blockstate/traces.jsonl"]
    end
```

### Competitive Capability Matrix

| Capability | LangGraph | NeMo Guardrails (Colang 2.0) | LlamaIndex Workflows | PydanticAI (`pydantic-graph`) | **Blockstate (`blockstate`)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Role** | High-level outer orchestrator | Proprietary Colang `.co` DSL | Event-driven async steps | Typed node return unions | **Transactional Compliance Execution Enclave** |
| **Physical Tool Containment** | ❌ Global `ToolNode` superset | ⚠️ DSL action rail checks | ❌ Imperative event handlers | ⚠️ Dynamic `prepare` callbacks | **✅ Ephemeral per-stage `MappingProxyType`** |
| **Static AST Graph Compiler** | ❌ Runtime graph inspection | ⚠️ Colang syntax check | ❌ Runtime reflection | ⚠️ `mypy` type checking only | **✅ Zero-execution DCG AST CFG compiler (`[Blockstate E014]`)** |
| **Mathematical Dominator Proofs** | ❌ None | ❌ None | ❌ None | ❌ None | **✅ Lengauer-Tarjan (`KYC dom Payout`)** |
| **Multi-Turn Digression Stack** | ❌ Manual subgraphs ($\mathcal{O}(N \times M)$) | ⚠️ Concurrent DSL flows | ❌ Manual event state | ❌ Manual node branching | **✅ LIFO `TaskStack` Pushdown Automata** |
| **Nested Multi-Turn Slot Filling** | ❌ Custom prompt & state boilerplate | ⚠️ Colang dialog scripts | ❌ Manual state dicts | ❌ Single-turn structured output | **✅ Recursive `PartialSlotModel` $\Delta$-Hydration** |
| **Turn Latency Architecture** | $1\text{--}3\text{s}$ serialised LLM calls | $3\text{--}6\text{s}$ multi-hop rails | Single-pass async LLM | Single-pass async LLM | **✅ Two-Pass (`<50ms` ONNX + `<15ms` Template/LLM)** |
| **Ingress PII Tokenisation** | ❌ Manual middleware | ⚠️ Presidio text masking | ❌ Manual hooks | ❌ Manual preprocessing | **✅ Built-in `PIIVault` (`<VAULT:ID>`) + `Detokenise[T]`** |
| **Tamper-Evident Audit Log** | ❌ State checkpoints only | ❌ Unstructured event logs | ❌ Telemetry traces only | ❌ Message history JSON | **✅ SHA-256 Hash-Chained `TurnLedger` + WAL** |

---

## 🚀 60-Second Quick Start

### 1. Installation

Blockstate requires **Python 3.12+** (leveraging PEP 695 type parameters). The core package is ultra-lightweight (`<= 40MB` RAM, zero database or cloud SDK bloat) and includes `InMemoryStorageBackend`. Install optional v1 adapters via PEP 621 extras:

```bash
# Core runtime, DCG AST compiler, CLI & InMemoryStorageBackend
pip install blockstate
# or via uv:
uv add blockstate

# Local development & edge deployments (SQLite WAL StorageBackend + local ONNX System-1 classifier)
pip install "blockstate[local]"
# or:
uv add "blockstate[local]"

# Cloud production workloads (PostgreSQL async SQLAlchemy + asyncpg StorageBackend, PydanticAI models & OTel)
pip install "blockstate[postgres,models,otel]"
# or install all canonical v1 enterprise adapters (PostgreSQL, SQLite WAL, S3, LiteLLM, ONNX, OTel):
uv add "blockstate[all]"
```

> **Version 1 Storage Slicing (`StorageBackend` SPI):** Version 1 ships with three canonical backends implementing `src/blockstate/ports/storage.py` (`StorageBackend`):
> 1. **In-Memory (`InMemoryStorageBackend`):** For hermetic unit testing and CI/CD.
> 2. **Local SQLite with WAL mode (`SQLiteStorageBackend` with `PRAGMA journal_mode=WAL` via `aiosqlite`):** For zero-dependency local development and edge deployments.
> 3. **PostgreSQL via async SQLAlchemy (`PostgresStorageBackend` via `SQLAlchemy[asyncio]` + `asyncpg`):** For cloud production workloads.
>
> *Redis, Microsoft SQL Server, and AWS DynamoDB are formally deferred to **v1.2+** via the pluggable async `StorageBackend` SPI.*

### 2. Configure Your Environment

Copy the provided enterprise `.env.example` template and generate a local vault encryption key:

```bash
cp .env.example .env
```

### 3. Build, Verify & Run Your First Governed Agent

Create `QuickStartAgent` in `agent.py` using the **Declarative Control Grammar (DCG)** (`@Stage`, `@Transition`, `@Guard`, `ChoicePayload`):

```python
import asyncio
from pydantic import BaseModel, Field
from blockstate import Agent, Stage, Transition, Guard, ChoicePayload


class RefundRequest(BaseModel):
    order_id: str = Field(pattern=r"^ORD-\d{5}$", description="Order ID in format ORD-12345")
    reason: str = Field(min_length=5, description="Brief reason for requesting a refund")
    amount_gbp: float = Field(gt=0, le=5000, description="Refund amount in GBP")


class QuickStartRefundAgent(Agent):
    @Stage(name="verify_identity", initial=True, max_turns=3)
    @Guard(requires=("is_authenticated",))
    @Transition(targets=("collect_refund", "security_lockout"))
    async def verify_identity(self) -> Transition["collect_refund" | "security_lockout"]:
        if not self.session.get("is_authenticated", False):
            return Transition.to("security_lockout", reason="Unauthenticated session")
        return Transition.to("collect_refund")

    @Stage(name="collect_refund", collect=RefundRequest, max_turns=5)
    @Transition(targets=("instant_refund", "manual_approval"))
    async def collect_refund(
        self, slots: RefundRequest
    ) -> Transition["instant_refund" | "manual_approval"]:
        if slots.amount_gbp <= 50.0:
            return Transition.to("instant_refund")
        return Transition.to("manual_approval")

    @Stage(name="instant_refund", tools=["issue_stripe_refund"], terminal=True)
    async def instant_refund(self, slots: RefundRequest) -> Transition[None]:
        await self.tools.issue_stripe_refund(order_id=slots.order_id, amount=slots.amount_gbp)
        return Transition.end(canned_response=f"Refund of £{slots.order_id} (£{slots.amount_gbp:.2f}) issued.")

    @Stage(name="manual_approval", terminal=True)
    async def manual_approval(self, slots: RefundRequest) -> Transition[None]:
        return Transition.end(canned_response=f"Order {slots.order_id} (£{slots.amount_gbp:.2f}) routed to a specialist.")

    @Stage(name="security_lockout", terminal=True)
    async def security_lockout(self) -> Transition[None]:
        return Transition.end(canned_response="Session locked: identity verification failed.")
```

Run the **Static DCG Graph Compiler** and prove that `verify_identity` mathematically dominates every refund stage before executing a single turn:

```bash
# 1. Statically validate DCG (@Stage, @Transition, @Guard), PEP 695 transitions, and validator rules
$ blockstate check agent.py
✔ [AST-OK] QuickStartRefundAgent: 5 stages, 5 edges, 0 unreachable nodes (compiled in 11.4ms)

# 2. Prove mathematical dominance across all payout branches via Lengauer-Tarjan
$ blockstate verify agent.py --dominates "verify_identity -> [instant_refund, manual_approval]"
✔ [DOMINANCE PROVEN] 'verify_identity' strictly dominates 'instant_refund' and 'manual_approval' across all execution paths.
```

---

## 📚 Domain Examples (4 Complete Walkthroughs)

To demonstrate how Blockstate adapts across industries and architectural patterns, explore these four complete, production-grade examples:

---

### Example 1: Motor Insurance Claims — Recursive Nested $\Delta$-Hydration, `on_breach` & `TaskStack` Digressions

**Scenario:** An insurance customer files a motor claim requiring nested address details, vehicle registration, and damage estimates. Mid-conversation, the customer goes off-script to ask *"Will claiming for a cracked windscreen affect my no-claims bonus?"*. Furthermore, if the policy covers commercial haulage, the claim must immediately exit early (`on_breach`) before asking remaining questions.

```python
from datetime import date
from pydantic import BaseModel, Field, field_validator
from blockstate import Agent, Stage, Transition, Guard, BreachError


class IncidentLocation(BaseModel):
    street: str = Field(description="Street name where the incident occurred")
    city: str = Field(description="Town or city")
    postcode: str = Field(pattern=r"^[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}$")


class MotorClaimSlots(BaseModel):
    policy_number: str = Field(pattern=r"^POL-\d{6}$")
    vehicle_usage: str = Field(description="personal | commuting | commercial_haulage")
    incident_date: date = Field(description="Date of incident (YYYY-MM-DD)")
    estimated_damage_gbp: float = Field(gt=0)
    location: IncidentLocation  # Nested Pydantic model hydrated progressively!

    @field_validator("incident_date", mode="after")
    @classmethod
    def validate_not_in_future(cls, v: date) -> date:
        if v > date.today():
            raise ValueError("Incident date cannot be in the future.")
        return v

    @field_validator("vehicle_usage", mode="after")
    @classmethod
    def check_commercial_eligibility(cls, v: str) -> str:
        if v.lower() == "commercial_haulage":
            # Triggers immediate stage exit via @Stage(on_breach=...)
            raise BreachError("Commercial haulage policies require the Specialist Fleet Desk.")
        return v


class MotorInsuranceClaimAgent(Agent):
    @Stage(
        name="intake_claim",
        initial=True,
        collect=MotorClaimSlots,
        allow_digressions=["ncd_policy_faq"],
        allow_slot_overrides=False,  # Child FAQ frame cannot overwrite parent claim slots
        on_breach="commercial_fleet_desk",
        on_max_turns_exceeded="human_claims_handler",
        max_turns=6,
    )
    @Transition(targets=("tier_auto_payout", "tier_adjuster_review"))
    async def intake_claim(
        self, slots: MotorClaimSlots
    ) -> Transition["tier_auto_payout" | "tier_adjuster_review"]:
        if slots.estimated_damage_gbp <= 250.0:
            return Transition.to("tier_auto_payout")
        return Transition.to("tier_adjuster_review")

    @Stage(
        name="ncd_policy_faq",
        tools=["query_policy_handbook_rag"],  # Read-only tool isolated to FAQ frame
        max_turns=2,
    )
    async def ncd_policy_faq(self, query: str) -> Transition[None]:
        excerpt = await self.tools.query_policy_handbook_rag(topic=query)
        # Popping a digression frame automatically returns to 'intake_claim'
        # and prompts for the remaining unhydrated leaf paths (Delta)!
        return Transition.pop_frame(message=f"Policy Handbook: {excerpt}")

    @Stage(name="tier_auto_payout", tools=["authorise_bacs_payout"], terminal=True)
    async def tier_auto_payout(self, slots: MotorClaimSlots) -> Transition[None]:
        tx_ref = await self.tools.authorise_bacs_payout(
            policy=slots.policy_number, amount=slots.estimated_damage_gbp
        )
        return Transition.end(
            canned_response=f"Claim approved under £250 fast-track. Reference: {tx_ref}."
        )

    @Stage(name="tier_adjuster_review", tools=["create_adjuster_ticket"], terminal=True)
    async def tier_adjuster_review(self, slots: MotorClaimSlots) -> Transition[None]:
        ticket = await self.tools.create_adjuster_ticket(claim=slots.model_dump())
        return Transition.end(
            canned_response=f"Claim exceeds £250 fast-track limit. Assigned to adjuster ({ticket})."
        )

    @Stage(name="commercial_fleet_desk", terminal=True)
    async def commercial_fleet_desk(self) -> Transition[None]:
        return Transition.end(
            canned_response="Commercial haulage policies are handled by our Specialist Fleet Desk on 0800-000-111."
        )

    @Stage(name="human_claims_handler", terminal=True)
    async def human_claims_handler(self) -> Transition[None]:
        return Transition.end(canned_response="Transferring you to a live claims specialist with your details.")
```

**What happens at runtime across 4 turns:**
1. **Turn 1:** User says *"Hi, my policy is POL-884120, it's for personal use, and someone bumped my bumper in Manchester (`M1 1AG`) yesterday."*
   - `PartialSlotModel` validates and locks `policy_number`, `vehicle_usage`, `incident_date`, `location.city`, and `location.postcode`.
   - $\Delta$-Hydration computes $\Delta = \{\text{`location.street`}, \text{`estimated_damage_gbp`}\}$ and prompts only for those two missing fields.
2. **Turn 2 (Digression):** User asks *"Wait—before I tell you the street and cost, will this hurt my no-claims discount?"*
   - Pass 1 classifies the permitted digression `ncd_policy_faq`.
   - `TaskStack` pushes a child `TaskFrame(stage="ncd_policy_faq")`. Only `query_policy_handbook_rag` is present in the dispatch table (`authorise_bacs_payout` does not exist).
   - The FAQ is answered, `Transition.pop_frame()` pops the child frame, and Blockstate automatically resumes `intake_claim` with the 5 previously collected fields untouched.
3. **Turn 3:** User says *"Got it. It happened on Deansgate and the garage quoted £180."*
   - $\Delta = \emptyset$. The strict `MotorClaimSlots` model materialises, the guard sees `£180 <= £250`, and transitions deterministically to `tier_auto_payout`.

---

### Example 2: Retail Banking Wire Transfer — Multi-Branch KYC Dominator Proofs & Zero-LLM `ChoicePayload`

**Scenario:** A retail bank offers three payment rails (`faster_payments_uk`, `sepa_euro_transfer`, `swift_international`). Under UK FCA SYSC 13.7 operational risk rules, the Model Risk Management (MRM) team requires mathematical proof that **every payment rail** is strictly dominated by `step_up_mfa_kyc`, plus sub-120ms deterministic choice menus (`ChoicePayload`) for regulatory fee disclosures.

```python
from pydantic import BaseModel, Field
from blockstate import Agent, Stage, Transition, Guard, ChoicePayload, ChoiceOption


class TransferDetails(BaseModel):
    rail: str = Field(description="uk_faster | sepa_eur | swift_intl")
    amount_gbp: float = Field(gt=0, le=250_000)
    beneficiary_iban: str = Field(min_length=15, max_length=34)


class RetailWireTransferAgent(Agent):
    @Stage(
        name="select_payment_rail",
        initial=True,
        collect=TransferDetails,
        choice_options=ChoicePayload(
            prompt="Which payment rail would you like to use for your transfer?",
            options=[
                ChoiceOption(id="uk_faster", label="UK Faster Payments (£0 fee, instant)"),
                ChoiceOption(id="sepa_eur", label="SEPA Euro Transfer (£5 fee, 1 business day)"),
                ChoiceOption(id="swift_intl", label="International SWIFT Wire (£25 fee, 1-3 days)"),
            ],
        ),
    )
    @Transition(targets=("step_up_mfa_kyc",))
    async def select_payment_rail(
        self, slots: TransferDetails
    ) -> Transition["step_up_mfa_kyc"]:
        return Transition.to("step_up_mfa_kyc")

    @Stage(name="step_up_mfa_kyc", tools=["verify_fido2_passkey"], max_turns=3, on_max_turns_exceeded="fraud_lock")
    @Guard(requires=("user_id",))
    @Transition(targets=("faster_payments_uk", "sepa_euro_transfer", "swift_international", "fraud_lock"))
    async def step_up_mfa_kyc(
        self, slots: TransferDetails
    ) -> Transition["faster_payments_uk" | "sepa_euro_transfer" | "swift_international" | "fraud_lock"]:
        verified = await self.tools.verify_fido2_passkey(user_id=self.session["user_id"])
        if not verified:
            return Transition.to("fraud_lock")
        match slots.rail:
            case "uk_faster":
                return Transition.to("faster_payments_uk")
            case "sepa_eur":
                return Transition.to("sepa_euro_transfer")
            case _:
                return Transition.to("swift_international")

    @Stage(name="faster_payments_uk", tools=["execute_fps_rail"], terminal=True)
    async def faster_payments_uk(self, slots: TransferDetails) -> Transition[None]:
        await self.tools.execute_fps_rail(iban=slots.beneficiary_iban, amount=slots.amount_gbp)
        return Transition.end(canned_response="UK Faster Payment executed.")

    @Stage(name="sepa_euro_transfer", tools=["execute_sepa_rail"], terminal=True)
    async def sepa_euro_transfer(self, slots: TransferDetails) -> Transition[None]:
        await self.tools.execute_sepa_rail(iban=slots.beneficiary_iban, amount=slots.amount_gbp)
        return Transition.end(canned_response="SEPA Euro Transfer executed.")

    @Stage(name="swift_international", tools=["execute_swift_rail"], terminal=True)
    async def swift_international(self, slots: TransferDetails) -> Transition[None]:
        await self.tools.execute_swift_rail(iban=slots.beneficiary_iban, amount=slots.amount_gbp)
        return Transition.end(canned_response="SWIFT International Wire executed.")

    @Stage(name="fraud_lock", terminal=True)
    async def fraud_lock(self) -> Transition[None]:
        return Transition.end(canned_response="Transfer halted: MFA verification failed.")
```

**What happens if a developer introduces a bypass bug in a Pull Request?**
Suppose a developer modifies `select_payment_rail` to route transfers under `£10` directly to `faster_payments_uk`, bypassing `step_up_mfa_kyc`. In CI, `blockstate verify` immediately blocks the PR:

```bash
$ blockstate verify wire_agent.py \
    --dominates "step_up_mfa_kyc -> [faster_payments_uk, sepa_euro_transfer, swift_international]"

✖ [BLK-AST-002] DOMINATOR VIOLATION DETECTED
  Assertion:  step_up_mfa_kyc dom faster_payments_uk
  Status:     FAILED (Immediate dominator of 'faster_payments_uk' is 'select_payment_rail', not 'step_up_mfa_kyc')
  Counter-Example Bypass Path:
    [0] select_payment_rail (wire_agent.py:24)
    └──► [1] faster_payments_uk (wire_agent.py:49)  <-- BYPASSED 'step_up_mfa_kyc'
  Exit Code:  1
```

---

### Example 3: Healthcare Patient Triage — HIPAA/GDPR `PIIVault`, `Detokenise[T]` & SHA-256 `TurnLedger`

**Scenario:** A patient contacts an NHS/healthcare triage assistant providing their NHS Number, postcode, and symptoms. Under GDPR and HIPAA Safe Harbor rules, raw patient identifiers must **never** be transmitted to external commercial LLM APIs or written to telemetry logs, yet the internal electronic health record (EHR) lookup tool requires the real NHS Number to verify registration.

```python
from pydantic import BaseModel, Field
from blockstate import Agent, Stage, Transition, Detokenise


class PatientIntakeSlots(BaseModel):
    nhs_number: str = Field(description="Tokenised NHS identifier (<VAULT:NHS_NUMBER_NN>)")
    postcode: str = Field(description="Tokenised patient postcode (<VAULT:POSTCODE_NN>)")
    primary_symptom: str = Field(description="Clinical symptom summary")


# Tool handler receives real cleartext ONLY for arguments wrapped in Detokenise[T]
async def lookup_patient_ehr_record(
    nhs_number: Detokenise[str],
    postcode: Detokenise[str],
) -> dict[str, str]:
    # ToolGatekeeper automatically detokenises <VAULT:NHS_NUMBER_01> -> "485 777 3456"
    # strictly inside this isolated function scope, and re-sanitises the return value!
    return {"registration_status": "ACTIVE", "gp_practice_code": "Y00124"}


class ClinicalTriageAgent(Agent):
    @Stage(
        name="collect_patient_identifiers",
        initial=True,
        collect=PatientIntakeSlots,
    )
    @Transition(targets=("verify_ehr_registration",))
    async def collect_patient_identifiers(
        self, slots: PatientIntakeSlots
    ) -> Transition["verify_ehr_registration"]:
        # Notice: inside LLM prompts and slots, slots.nhs_number is literally "<VAULT:NHS_NUMBER_01>"
        return Transition.to("verify_ehr_registration")

    @Stage(
        name="verify_ehr_registration",
        tools=[lookup_patient_ehr_record],
        terminal=True,
    )
    async def verify_ehr_registration(self, slots: PatientIntakeSlots) -> Transition[None]:
        ehr = await self.tools.lookup_patient_ehr_record(
            nhs_number=slots.nhs_number,
            postcode=slots.postcode,
        )
        return Transition.end(
            canned_response=f"Registration verified ({ehr['registration_status']}) at practice {ehr['gp_practice_code']}."
        )
```

**Inspecting the Cryptographic `TurnLedger` & Local Trace (`blockstate trace`):**

```bash
$ blockstate trace --session 0192ce18-7b40-7000-8000-4a91f0012c9a
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Turn ┃ Transition                 ┃ Vaulted Input Tokens       ┃ Exposed Tool Whitelist     ┃ SHA-256 Chain    ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ 1    │ [START] ->                 │ "My NHS number is          │ [] (Zero Tools Exposed)    │ 8f9c2b1a...e401  │
│      │ collect_patient_identifiers│ <VAULT:NHS_NUMBER_01> and  │                            │ (prev: GENESIS)  │
│      │                            │ postcode <VAULT:POST_01>"  │                            │                  │
│ 2    │ collect_patient_identifiers│ "I have had a fever for    │ [lookup_patient_ehr_record]│ 3d41a90c...99b2  │
│      │ -> verify_ehr_registration │ two days"                  │                            │ (prev: 8f9c2b1a) │
└──────┴────────────────────────────┴────────────────────────────┴────────────────────────────┴──────────────────┘
✔ Cryptographic Hash Chain Verified (2/2 records intact, RFC 8785 JCS canonical SHA-256, 0 raw PII tokens leaked)
```

---

### Example 4: Outer Orchestrator Enclave (`as_tool()`) — Embedding Blockstate Inside LangGraph, Semantic Kernel, AutoGen or AWS Bedrock

**Scenario:** Your enterprise already runs a high-level orchestrator (LangGraph, Microsoft Semantic Kernel, AutoGen, or AWS Bedrock) as an open-domain concierge router. Rather than forcing a rip-and-replace (the **"Enterprise Island Trap"**), Blockstate operates as a **transactional compliance execution enclave**: when the user asks to originate a mortgage or file a regulated claim, the outer orchestrator invokes the entire verified Blockstate statechart as a single validated tool via `from blockstate.adapters.langchain import as_tool`.

```python
from blockstate.adapters.langchain import as_tool
from my_regulated_workflows import MortgageOriginationEnclave

# Expose the entire formal statechart as a single validated tool to LangGraph
langgraph_agent.bind_tools([
    as_tool(MortgageOriginationEnclave, name="execute_mortgage_transaction")
])
```

You can also drive multi-turn subflow handoffs directly from custom API gateways using `PostgresStorageBackend` or `SQLiteStorageBackend` and match over the discriminated union (`BlockstateTurnYield | BlockstateTurnComplete | BlockstateTurnAborted`):

```python
from blockstate import BlockstateTurnYield, BlockstateTurnComplete, BlockstateTurnAborted
from examples.motor_insurance import MotorInsuranceClaimAgent
from blockstate.adapters.storage.postgres import PostgresStorageBackend

# 1. Instantiate your governed Blockstate enclave backed by PostgreSQL (or SQLite WAL)
claim_agent = MotorInsuranceClaimAgent(
    storage_backend=PostgresStorageBackend.from_dsn(
        "postgresql+asyncpg://blockstate_user:secret@localhost:5432/blockstate_db"
    )
)

# 2. Drive multi-turn enclave handoffs explicitly in your gateway router
async def handle_customer_turn(session_id: str, user_utterance: str) -> str:
    outcome = await claim_agent.run_as_subflow(
        session_id=session_id,
        user_message=user_utterance,
        initial_context={"is_authenticated": True, "user_id": "USR-99201"},
    )

    match outcome:
        case BlockstateTurnYield(message=prompt_msg, missing_slots=delta):
            # Blockstate is mid-flow collecting slots or answering a TaskStack digression
            return prompt_msg

        case BlockstateTurnComplete(result=validated_claim, ledger_head_hash=audit_hash):
            # Terminal stage reached! Control returns to outer router with a strict Pydantic model
            return f"Workflow complete (Audit Hash: {audit_hash[:12]}): {validated_claim}"

        case BlockstateTurnAborted(error_code=code, reason=reason):
            # SecurityViolationError or max_turns circuit breaker triggered
            return f"[{code}] Escalating to human specialist: {reason}"
```

---

## 🛠️ CLI Reference, Declarative Control Grammar & Compile-Time Verification

### Addressing Rice's Theorem with the Declarative Control Grammar (DCG)

By **Rice's Theorem**, any non-trivial semantic property of an unconstrained, Turing-complete Python program (such as dynamic reflection `getattr(self, dynamic_state)()`, `eval()`, or computed stage targets) is mathematically undecidable by static analysis.

To make Lengauer-Tarjan dominator verification 100% sound and decidable, Blockstate requires all stage topologies to be declared using the **Declarative Control Grammar (DCG)**: `@Stage`, `@Transition`, and `@Guard` combined with static PEP 695 `Transition["target_a" | "target_b"]` annotations. If `blockstate check` or `blockstate verify` encounters dynamic reflection or a non-static transition target in the AST, it immediately terminates the build pass:

```text
[Blockstate E014] Dynamic transition destination detected at mortgage_flow.py:42.
Transitions must reference static State definitions to enable Lengauer-Tarjan dominator verification.
```

### CLI Commands (`blockstate`)

Blockstate ships a rich command-line toolkit (`blockstate`) powered by `Typer` and `Rich`:

| Command | Purpose | CI / Production Usage |
| :--- | :--- | :--- |
| `blockstate check [PATH]` | Parses Python source files via `ast.parse` (zero code execution). Enforces **Declarative Control Grammar (DCG)** (`@Stage`, `@Transition`, `@Guard`), rejects dynamic transition targets with `[Blockstate E014]`, checks unreachable dead stages, and ensures zero `Transition` calls exist inside `@field_validator` methods (`FR-2`, `FR-10`). | Run in pre-commit & PR lint stage (`< 25ms`). |
| `blockstate verify [PATH] --dominates "A -> [B, C]"` | Constructs the complete Control Flow Graph (including `on_breach`, `on_refusal`, and `on_max_turns_exceeded` edges) and executes the **Lengauer-Tarjan dominator tree algorithm** (`FR-11`). Emits a signed JSON/Markdown audit certificate or exits with code `1` and the exact violating counter-example path. | Mandatory MRM / FCA / EU AI Act compliance gate in CI. |
| `blockstate export [PATH] --format [mermaid\|json]` | Exports verified statechart topologies, stage tool whitelists, and guard annotations to Markdown Mermaid diagrams or JSON Schema (`FR-12`). | Auto-generate PR architecture previews & audit docs. |
| `blockstate trace --session <UUID>` | Replays a multi-turn session from `.blockstate/traces.jsonl` or a configured `StorageBackend` (`FR-21`), verifying SHA-256 `TurnLedger` hash continuity and rendering turn-by-turn slot hydration and tool boundaries. | Local developer debugging & SRE incident response (`< 5 min` MTTR). |

---

## 🧪 Enterprise Testing, Coverage & Interface Contracts

Blockstate enforces a **Three-Tier Verification Architecture (`AD-11`)** designed to eliminate both boundary edge-case bugs and subtle integration drift across storage and model adapters:

### 1. Enforced Line & Branch Coverage Gates

Coverage is measured with `pytest-cov` (`--cov-branch`) and strictly enforced in CI:

| Architectural Ring | Packages Covered | Minimum Line Coverage | Minimum Branch Coverage |
| :--- | :--- | :--- | :--- |
| **Tier 1: Pure Kernel & Security** | `blockstate.core`, `blockstate.compiler`, `blockstate.security` | **$\ge 95\%$** | **$\ge 90\%$** |
| **Tier 2: Full Repository** | All packages including `blockstate.adapters.*` & `blockstate.cli` | **$\ge 90\%$** | **$\ge 85\%$** |

### 2. Port Interface Contract Suites (`blockstate.testing.contracts`)

To prevent integration failures where an agent works against `InMemoryStorageBackend` in unit tests but fails under `SQLiteStorageBackend` or `PostgresStorageBackend` in production, every port in `blockstate.ports` defines an abstract **Interface Contract Test Suite**:

- **`StorageBackendContractSuite` (`StateStoreContractSuite`):** Automatically tests all three canonical v1 `StorageBackend` drivers (`InMemoryStorageBackend`, `SQLiteStorageBackend` with `PRAGMA journal_mode=WAL`, and `PostgresStorageBackend` via `SQLAlchemy[asyncio]` + `asyncpg`)—as well as any v1.2+ SPI plugins (Redis, Microsoft SQL Server, AWS DynamoDB)—against identical assertions:
  - Concurrent `acquire_lease` contention (verifying `ConcurrentSessionError` / `BLK-CON-409` after exactly `2000ms`).
  - Stale lease automatic TTL expiry (`30000ms`) and active `10000ms` heartbeat renewal.
  - Optimistic Compare-And-Swap (`revision_id`) conflict detection on simultaneous checkpoint writes.
  - Rolling-deployment `SchemaUpcaster` migration (`schema_version: 1 -> 2`) on historical session payloads.
  - Boundary payloads: empty strings, 64KB slot strings, maximum nesting depth (`depth=8`), Unicode zero-width joiners/RTL overrides, null-byte rejection, and leap-year/UTC midnight timestamps.
- **`PIIStripperContractSuite`:** Verifies deterministic token stability within a session, zero token collision across distinct PII values, resistance to partial-token prompt injection (`<VAULT:...>`), and round-trip `Detokenise[T]` restoration.
- **`LedgerSinkContractSuite`:** Verifies monotonic `turn_index` ordering per `session_id`, RFC 8785 JCS SHA-256 tamper detection (flipping a single bit in turn $k$ invalidates turn $k+1 \dots n$), and `SIGTERM` local `.blockstate/wal/` spill and recovery.

### 3. Property-Based Fuzzing (`Hypothesis`)

In addition to deterministic example tests, CI runs **Hypothesis** property-based test suites (`max_examples=500` per property):
- **Arbitrary Nested Pydantic Schema Fuzzing:** Generates random multi-level `BaseModel` trees and random sequences of partial/invalid turn inputs, proving that $\Delta$-Hydration is monotonic, never mutates locked slots, and instantiates the target model if and only if $\Delta = \emptyset$.
- **Arbitrary Directed Graph Dominator Fuzzing:** Generates random cyclic, acyclic, diamond, and multi-exit graphs ($|V| \le 250$), proving that `blockstate.compiler.dominators` (Lengauer-Tarjan) agrees 100% with brute-force path enumeration.

```bash
# Run the full test suite with branch coverage and architectural import-linter checks
uv run lint-imports
uv run pytest --cov=blockstate --cov-branch --cov-report=term-missing
```

---

## 🔒 Zero-Leakage Security, `.env` Hygiene & Git Hooks

Blockstate enforces a strict **Zero PII & Zero Credential Leakage Policy (`AD-13`)**:

1. **Automated Pre-Commit & Pre-Push Scanning (`.pre-commit-config.yaml`):**
   - **Gitleaks (`v8.30.1`)** and **Yelp `detect-secrets` (`v1.5.0`)** scan every staged diff and commit for API keys, cloud tokens, private keys, and high-entropy connection strings.
   - **`blockstate-pii-guard`** scans staged files for accidental inclusion of UK National Insurance numbers, NHS numbers, US SSNs, Luhn-valid payment card numbers, and Bearer tokens.
   - **Sensitive File Blocker** physically rejects any commit attempting to stage `.env` (other than `.env.example`), `.blockstate/` trace directories, `.wal` files, or `.db`/`.sqlite` files.
2. **Typed `SecretStr` Configuration (`BlockstateSettings`):**
   - All environment variables documented in [`.env.example`](.env.example) (`BLOCKSTATE_` prefix) are loaded via `pydantic-settings` into `pydantic.SecretStr` fields, ensuring credentials are automatically masked as `**********` in logs, stack traces, and local crash dumps.

```bash
# Enable the zero-leakage git hooks immediately after cloning
uv run pre-commit install --hook-type pre-commit --hook-type pre-push
```

See [**SECURITY.md**](SECURITY.md) for the complete zero-trust threat model and vulnerability disclosure policy.

---

## 📜 Subcomponent Licences & Supply-Chain Governance

Every runtime and optional subcomponent of `blockstate` is audited and restricted in CI (`pip-licenses` + CycloneDX SBOM generation) to **permissive enterprise-approved licences (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `PSF-2.0`)** with **zero copyleft (`GPL`/`AGPL`/`LGPL`) dependencies**.

| Component Layer | Packages | SPDX Licences | Copyleft Risk |
| :--- | :--- | :--- | :--- |
| **Core Runtime & InMemory Backend** | `python` (`3.12+`), `pydantic`, `pydantic-settings`, `cryptography`, `typer`, `rich` | `PSF-2.0`, `MIT`, `Apache-2.0 / BSD-3-Clause` | **None (0%)** |
| **Model & Classifier Extras** | `pydantic-ai-slim`, `litellm` (`<1.107.0`), `onnxruntime` | `MIT` | **None (0%)** |
| **v1 StorageBackend & Ledger Extras** | `aiosqlite` (SQLite WAL), `SQLAlchemy` + `asyncpg` (PostgreSQL), `aioboto3` (S3 WORM) | `MIT`, `Apache-2.0` | **None (0%)** |
| **Observability Extra** | `opentelemetry-api`, `opentelemetry-sdk` | `Apache-2.0` | **None (0%)** |

*(Note: Redis, Microsoft SQL Server, and AWS DynamoDB storage adapters are deferred to v1.2+ via the formal `StorageBackend` SPI in `src/blockstate/ports/storage.py`.)*

For the complete package-by-package version, licence, and upstream repository manifest, see [**THIRD_PARTY_LICENSES.md**](THIRD_PARTY_LICENSES.md).

---

## 🗺️ Architectural Documentation & Artifacts

- [**Architecture Spine (`ARCHITECTURE-SPINE.md`)**](docs/architecture/ARCHITECTURE-SPINE.md) — The normative build substrate fixing all 14 Architectural Decisions (`AD-1` to `AD-14`), Hexagonal boundaries, wire protocols, and stack versions.
- [**Interactive Visual Architecture Deck (`architecture-deck.html`)**](docs/architecture/architecture-deck.html) — Self-contained HTML+SVG executive and engineering walkthrough deck.
- [**Product Requirements Document (`prd.md`)**](docs/spec/prd.md) — Functional requirements (`FR-1` to `FR-22`), user journeys (`UJ-1` to `UJ-3`), and regulatory mapping (`EU AI Act`, `UK FCA`, `HIPAA`, `SOC 2`).
- [**Technical Specification (`SPEC.md`)**](docs/spec/SPEC.md) — Execution specification, state transitions, and compliance reference mappings.
- [**Third-Party Licences (`THIRD_PARTY_LICENSES.md`)**](THIRD_PARTY_LICENSES.md) & [**Security Policy (`SECURITY.md`)**](SECURITY.md).
