"""Blockstate CLI project and enclave scaffolding engine.

Generates production-grade, mathematically verifiable compliance enclaves with
deterministic statechart topologies, stage-scoped tool whitelists, and automated
test suites passing offline verification out of the box.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class TemplateType(StrEnum):
    """Supported starter enclave templates."""

    BANKING = "banking"
    INSURANCE = "insurance"
    HEALTHCARE = "healthcare"
    MINIMAL = "minimal"


@dataclass(frozen=True)
class EnclaveTemplate:
    """Specification and file generators for a starter enclave template."""

    name: str
    description: str
    agent_class_name: str
    precursor_stage: str
    target_stages: tuple[str, ...]
    dominance_assertion: str
    turn_1_message: str
    turn_2_message: str
    render_agent_source: Callable[[str, str], str]
    render_test_source: Callable[[str, str, str, tuple[str, ...], str, str], str]


# ---------------------------------------------------------------------------
# Template Source Generators
# ---------------------------------------------------------------------------


def _render_banking_agent(module_name: str, class_name: str) -> str:
    return f'''"""Regulated retail banking funds transfer compliance enclave.

Enforces mandatory customer identity verification before interbank settlement
across Faster Payments rails under FCA SYSC 13.7 and PSR 2017.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class CustomerIdentitySlots(BaseModel):
    """Slot schema for customer identity and sort code verification."""

    customer_id: str = Field(..., description="Unique customer banking identifier")
    sort_code: str = Field(..., description="Six-digit UK clearing sort code")


class TransferDetailsSlots(BaseModel):
    """Slot schema for funds transfer beneficiary and amount."""

    beneficiary_account: str = Field(..., description="Beneficiary eight-digit account number")
    amount_gbp: float = Field(..., description="Transfer amount in GBP")


def screen_sanctions_and_fraud(
    customer_id: str = "CUST-001",
    amount_gbp: float = 250.0,
) -> dict[str, Any]:
    """Screen transfer payload against sanctions lists and AML fraud models."""
    return {{"status": "clear", "flagged": amount_gbp > 10000.0}}


screen_sanctions_and_fraud._blockstate_tool = True


def settle_faster_payment(
    beneficiary_account: str = "88776655",
    amount_gbp: float = 250.0,
) -> dict[str, Any]:
    """Execute settlement across interbank Faster Payments clearing rails."""
    return {{"status": "settled", "rail": "FPS", "payment_reference": "FPS-LON-99218"}}


settle_faster_payment._blockstate_tool = True


class {class_name}(Agent):
    """Regulated retail banking enclave enforcing mandatory KYC before transfer."""

    def __init__(self, tools: Mapping[str, Any] | None = None) -> None:
        default_tools = {{
            "screen_sanctions_and_fraud": screen_sanctions_and_fraud,
            "settle_faster_payment": settle_faster_payment,
        }}
        if tools:
            default_tools.update(tools)
        super().__init__(tools=default_tools)

    @Stage(
        name="verify_identity",
        collect=CustomerIdentitySlots,
        canned_response="Please state your customer ID and sort code for identity verification.",
    )
    @Transition(targets=["assess_transfer_risk"])
    def identity_stage(self, slots: CustomerIdentitySlots) -> Transition[str]:
        return Transition.to("assess_transfer_risk")

    @Guard(stage="verify_identity", targets=["assess_transfer_risk"])
    def guard_identity_verified(
        self, slots: CustomerIdentitySlots | None
    ) -> Transition[str | None]:
        if slots and slots.customer_id and slots.sort_code:
            return Transition.to("assess_transfer_risk")
        return Transition.stay()

    @Stage(
        name="assess_transfer_risk",
        collect=TransferDetailsSlots,
        tools=[screen_sanctions_and_fraud],
        canned_response="Please provide the destination account number and transfer amount in GBP.",
    )
    @Transition(targets=["execute_transfer", "compliance_review"])
    def risk_stage(self, slots: TransferDetailsSlots) -> Transition[str]:
        if slots.amount_gbp > 10000.0:
            return Transition.to("compliance_review")
        return Transition.to("execute_transfer")

    @Stage(
        name="compliance_review",
        canned_response="Transfer flagged for compliance officer investigation.",
    )
    @Transition(targets=["execute_transfer", "reject_transfer"])
    def compliance_stage(self) -> Transition[str]:
        flagged = True
        if flagged:
            return Transition.to("reject_transfer")
        return Transition.to("execute_transfer")

    @Stage(
        name="execute_transfer",
        terminal=True,
        tools=[settle_faster_payment],
        canned_response="Funds successfully transferred via Faster Payments.",
    )
    def transfer_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"status": "settled", "rail": "FPS"}})

    @Stage(
        name="reject_transfer",
        terminal=True,
        canned_response="Transfer declined following compliance review.",
    )
    def reject_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"status": "rejected"}})


class MockBankingClassifier(IntentClassifier):
    """Deterministic offline classifier for simulation and unit testing."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        slots: dict[str, Any] = {{}}
        if "CUST" in utterance or "customer" in utterance.lower():
            slots["customer_id"] = "CUST-001"
            slots["sort_code"] = "20-00-00"
            intent = "verify_identity"
        else:
            slots["beneficiary_account"] = "88776655"
            slots["amount_gbp"] = 250.0
            intent = "assess_transfer_risk"

        return ExtractionResult(
            intent=intent,
            candidate_slots=slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


async def main() -> None:
    """Run local interactive simulation of the banking enclave."""
    agent = {class_name}()
    storage = InMemoryStateStore()
    classifier = MockBankingClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "banking_demo_session"

    print("=== Blockstate Banking Enclave Simulation ===")
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="My customer ID is CUST-001 and sort code 20-00-00.",
        )
    )
    print(f"Turn 1 State: {{t1.state}} ({{type(t1).__name__}})")

    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Transfer 250 GBP to account 88776655.",
        )
    )
    print(f"Turn 2 State: {{t2.state}} ({{type(t2).__name__}})")
    if isinstance(t2, BlockstateTurnComplete):
        print(f"Settlement Result: {{t2.result}}")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _render_insurance_agent(module_name: str, class_name: str) -> str:
    return f'''"""Regulated motor insurance claim First Notice of Loss (FNOL) enclave.

Demonstrates TaskStack pushdown automaton digression handling (allow_digressions=True)
where policy verification strictly dominates repair network settlement.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class PolicySlots(BaseModel):
    """Slot schema for policyholder registration validation."""

    policy_number: str = Field(..., description="Active motor insurance policy number")
    vehicle_reg: str = Field(..., description="Vehicle registration mark")


class IncidentSlots(BaseModel):
    """Slot schema for incident circumstance capture."""

    incident_date: str = Field(..., description="Accident date in YYYY-MM-DD format")
    incident_description: str = Field(..., description="Damage circumstances narrative")


def lookup_policy_status(policy_number: str = "POL-UK-8821") -> dict[str, Any]:
    """Policy administration system verification tool."""
    return {{"status": "active", "policy_number": policy_number, "excess_gbp": 250.0}}


lookup_policy_status._blockstate_tool = True


def authorise_bodyshop_repair(policy_number: str = "POL-UK-8821") -> dict[str, Any]:
    """Authorise approved regional bodyshop repair network."""
    return {{"action": "repair_authorised", "bodyshop": "Approved Central Garage"}}


authorise_bodyshop_repair._blockstate_tool = True


class {class_name}(Agent):
    """Regulated motor insurance claim enclave with digression handling.

    Showcases pushdown automaton digression handling with allow_digressions=True.
    """

    def __init__(self, tools: Mapping[str, Any] | None = None) -> None:
        default_tools = {{
            "lookup_policy_status": lookup_policy_status,
            "authorise_bodyshop_repair": authorise_bodyshop_repair,
        }}
        if tools:
            default_tools.update(tools)
        super().__init__(tools=default_tools)

    @Stage(
        name="verify_policy",
        collect=PolicySlots,
        tools=[lookup_policy_status],
        allow_digressions=["policy_faq"],
        max_turns=5,
        canned_response="Please provide your policy number and vehicle registration.",
    )
    @Transition(targets=["incident_intake"])
    def verify_policy_stage(self, slots: PolicySlots) -> Transition[str]:
        return Transition.to("incident_intake")

    @Stage(
        name="policy_faq",
        canned_response=(
            "Comprehensive coverage includes accidental damage subject to standard excess."
        ),
    )
    def faq_stage(self) -> Transition[None]:
        return Transition.pop_frame()

    @Stage(
        name="incident_intake",
        collect=IncidentSlots,
        allow_digressions=["policy_faq"],
        max_turns=5,
        canned_response="Please state the incident date and description.",
    )
    @Transition(targets=["fast_track_settlement", "adjuster_review"])
    def incident_stage(self, slots: IncidentSlots) -> Transition[str]:
        requires_adjuster = False
        if requires_adjuster:
            return Transition.to("adjuster_review")
        return Transition.to("fast_track_settlement")

    @Stage(
        name="adjuster_review",
        canned_response="Claim referred to senior loss adjuster.",
    )
    @Transition(targets=["fast_track_settlement", "decline_claim"])
    def review_stage(self) -> Transition[str]:
        declined = False
        if declined:
            return Transition.to("decline_claim")
        return Transition.to("fast_track_settlement")

    @Stage(
        name="fast_track_settlement",
        terminal=True,
        tools=[authorise_bodyshop_repair],
        canned_response="Claim approved and scheduled for approved bodyshop repair.",
    )
    def settlement_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"claim_status": "approved", "channel": "bodyshop_network"}})

    @Stage(
        name="decline_claim",
        terminal=True,
        canned_response="Claim declined under policy exclusions.",
    )
    def decline_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"claim_status": "declined"}})


class MockInsuranceClassifier(IntentClassifier):
    """Deterministic offline classifier for simulation and testing."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        slots: dict[str, Any] = {{}}
        if "POL" in utterance or "policy" in utterance.lower():
            slots["policy_number"] = "POL-UK-8821"
            slots["vehicle_reg"] = "AB21 CDE"
            intent = "verify_policy"
        else:
            slots["incident_date"] = "2026-10-15"
            slots["incident_description"] = "Rear bumper impact in car park."
            intent = "incident_intake"

        return ExtractionResult(
            intent=intent,
            candidate_slots=slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


async def main() -> None:
    """Run local interactive simulation of the insurance claim enclave."""
    agent = {class_name}()
    storage = InMemoryStateStore()
    classifier = MockInsuranceClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "insurance_demo_session"

    print("=== Blockstate Insurance FNOL Enclave Simulation ===")
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="Claiming on policy POL-UK-8821 for registration AB21 CDE.",
        )
    )
    print(f"Turn 1 State: {{t1.state}} ({{type(t1).__name__}})")

    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Accident happened on 2026-10-15 with bumper damage.",
        )
    )
    print(f"Turn 2 State: {{t2.state}} ({{type(t2).__name__}})")
    if isinstance(t2, BlockstateTurnComplete):
        print(f"Settlement Result: {{t2.result}}")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _render_healthcare_agent(module_name: str, class_name: str) -> str:
    return f'''"""Regulated healthcare clinical triage and PHI protection enclave.

Enforces cryptographic PII vaulting with Vaulted[T] slot fields and volatile-memory
Detokenise[T] tool parameter injection under HIPAA and NHS Caldicott principles.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield
from blockstate.security.annotations import Detokenise, Vaulted


class PatientIntakeSlots(BaseModel):
    """Patient intake slots with cryptographic PII vaulting tokens."""

    patient_id: Vaulted[str] = Field(..., description="Government health identifier")
    contact_phone: Vaulted[str] = Field(..., description="Patient telephone contact")


class ClinicalAssessmentSlots(BaseModel):
    """Slot schema for triage priority and clinical symptoms."""

    symptoms: str = Field(..., description="Reported clinical symptoms")
    triage_priority: str = Field(default="routine", description="Clinical triage urgency")


def schedule_clinic_consultation(
    patient_id: Detokenise[str] = "943 476 5919",
    triage_priority: str = "routine",
) -> dict[str, str]:
    """Clinical scheduling tool receiving detokenised patient ID in volatile memory."""
    return {{
        "status": "confirmed",
        "priority": triage_priority,
        "appointment_ref": "APT-NHS-9012",
    }}


schedule_clinic_consultation._blockstate_tool = True


class {class_name}(Agent):
    """Regulated healthcare enclave ensuring zero raw PHI leakage into audit logs."""

    def __init__(self, tools: Mapping[str, Any] | None = None) -> None:
        default_tools = {{
            "schedule_clinic_consultation": schedule_clinic_consultation,
        }}
        if tools:
            default_tools.update(tools)
        super().__init__(tools=default_tools)

    @Stage(
        name="patient_intake",
        collect=PatientIntakeSlots,
        canned_response="Please state your patient identifier and telephone contact.",
    )
    @Transition(targets=["clinical_assessment"])
    def intake_stage(self, slots: PatientIntakeSlots) -> Transition[str]:
        return Transition.to("clinical_assessment")

    @Stage(
        name="clinical_assessment",
        collect=ClinicalAssessmentSlots,
        tools=[schedule_clinic_consultation],
        canned_response="Evaluating clinical urgency.",
    )
    @Transition(targets=["emergency_dispatch", "schedule_clinic"])
    def triage_stage(self, slots: ClinicalAssessmentSlots) -> Transition[str]:
        if "emergency" in slots.triage_priority.lower():
            return Transition.to("emergency_dispatch")
        return Transition.to("schedule_clinic")

    @Stage(
        name="emergency_dispatch",
        terminal=True,
        canned_response="Emergency clinical dispatch initiated.",
    )
    def emergency_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"priority": "emergency", "service": "ambulance"}})

    @Stage(
        name="schedule_clinic",
        terminal=True,
        canned_response="Routine consultation scheduled with duty clinician.",
    )
    def routine_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(
            result={{"priority": "routine", "booking_reference": "NHS-CLINIC-7741"}}
        )


class MockHealthcareClassifier(IntentClassifier):
    """Deterministic offline classifier for simulation and testing."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        slots: dict[str, Any] = {{}}
        if "NHS" in utterance or "patient" in utterance.lower():
            slots["patient_id"] = "943 476 5919"
            slots["contact_phone"] = "07700 900123"
            intent = "patient_intake"
        else:
            slots["symptoms"] = "Persistent headache and mild fever"
            slots["triage_priority"] = "routine"
            intent = "clinical_assessment"

        return ExtractionResult(
            intent=intent,
            candidate_slots=slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


async def main() -> None:
    """Run local interactive simulation of the healthcare enclave."""
    agent = {class_name}()
    storage = InMemoryStateStore()
    classifier = MockHealthcareClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "healthcare_demo_session"

    print("=== Blockstate Healthcare Enclave Simulation ===")
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="Patient NHS 943 476 5919 phone 07700 900123.",
        )
    )
    print(f"Turn 1 State: {{t1.state}} ({{type(t1).__name__}})")

    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Reporting fever symptoms with routine priority.",
        )
    )
    print(f"Turn 2 State: {{t2.state}} ({{type(t2).__name__}})")
    if isinstance(t2, BlockstateTurnComplete):
        print(f"Triage Result: {{t2.result}}")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _render_minimal_agent(module_name: str, class_name: str) -> str:
    return f'''"""Minimal 3-stage starter compliance enclave for rapid prototyping.

Provides an intake stage, validation processing stage, and terminal completion stage
with verified Lengauer-Tarjan mathematical dominance.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class RequestSlots(BaseModel):
    """Basic slot model capturing user request parameter."""

    request_id: str = Field(..., description="Unique client request token")


class ProcessingSlots(BaseModel):
    """Slot model for request processing action."""

    action_code: str = Field(..., description="Processing action code")


def validate_request_payload(
    request_id: str = "REQ-1001",
    action_code: str = "ACT-42",
) -> dict[str, Any]:
    """Validate request payload parameters."""
    return {{"valid": True, "request_id": request_id, "action_code": action_code}}


validate_request_payload._blockstate_tool = True


class {class_name}(Agent):
    """Minimal compliance enclave statechart."""

    def __init__(self, tools: Mapping[str, Any] | None = None) -> None:
        default_tools = {{
            "validate_request_payload": validate_request_payload,
        }}
        if tools:
            default_tools.update(tools)
        super().__init__(tools=default_tools)

    @Stage(
        name="intake",
        collect=RequestSlots,
        canned_response="Please provide your request identifier to proceed.",
    )
    @Transition(targets=["process_request"])
    def intake_stage(self, slots: RequestSlots) -> Transition[str]:
        return Transition.to("process_request")

    @Stage(
        name="process_request",
        collect=ProcessingSlots,
        tools=[validate_request_payload],
        canned_response="Processing validated request payload.",
    )
    @Transition(targets=["complete"])
    def process_stage(self, slots: ProcessingSlots) -> Transition[str]:
        return Transition.to("complete")

    @Stage(
        name="complete",
        terminal=True,
        canned_response="Request processed and completed successfully.",
    )
    def complete_stage(self) -> Transition[dict[str, Any]]:
        return Transition.end(result={{"status": "completed"}})


class MockMinimalClassifier(IntentClassifier):
    """Deterministic offline classifier for simulation and testing."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        slots: dict[str, Any] = {{}}
        if "REQ" in utterance or "request" in utterance.lower():
            slots["request_id"] = "REQ-1001"
            intent = "intake"
        else:
            slots["action_code"] = "ACT-42"
            intent = "process_request"

        return ExtractionResult(
            intent=intent,
            candidate_slots=slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


async def main() -> None:
    """Run local interactive simulation of the minimal enclave."""
    agent = {class_name}()
    storage = InMemoryStateStore()
    classifier = MockMinimalClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "minimal_demo_session"

    print("=== Blockstate Minimal Enclave Simulation ===")
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="Initialising request REQ-1001.",
        )
    )
    print(f"Turn 1 State: {{t1.state}} ({{type(t1).__name__}})")

    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Execute processing action ACT-42.",
        )
    )
    print(f"Turn 2 State: {{t2.state}} ({{type(t2).__name__}})")
    if isinstance(t2, BlockstateTurnComplete):
        print(f"Completion Result: {{t2.result}}")


if __name__ == "__main__":
    asyncio.run(main())
'''


def _render_test_source(
    module_name: str,
    class_name: str,
    precursor: str,
    targets: tuple[str, ...],
    turn_1_message: str,
    turn_2_message: str,
) -> str:
    targets_repr = repr(list(targets))
    return f'''"""Comprehensive pytest suite for {class_name}.

Verifies offline AST graph compilation, mathematical Lengauer-Tarjan dominance,
adversarial bypass detection, multi-turn statechart execution, and stage-scoped
tool gatekeeper isolation (BLK-SEC-001).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Ensure local module is resolvable regardless of test runner working directory
_local_dir = Path(__file__).resolve().parent
if str(_local_dir) not in sys.path:
    sys.path.insert(0, str(_local_dir))

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.compiler.ast_extractor import StaticGraphCompiler
from blockstate.compiler.dominators import verify_dominance
from blockstate.core.engine import StatechartEngine
from blockstate.errors import SecurityViolationError
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield

from {module_name} import {class_name}


@pytest.fixture
def agent_source() -> str:
    """Load agent Python source code from adjacent module file."""
    source_file = _local_dir / "{module_name}.py"
    return source_file.read_text(encoding="utf-8")


def test_static_ast_compilation(agent_source: str) -> None:
    """Verify Declarative Control Grammar statically compiles with zero defects."""
    graph = StaticGraphCompiler.compile_source(agent_source, filename="{module_name}.py")
    assert graph.agent_name == "{class_name}"
    assert graph.initial_stage == "{precursor}"
    assert "{precursor}" in graph.stages
    for target in {targets_repr}:
        assert target in graph.stages
        assert graph.stages[target].terminal is True


def test_precursor_dominance_certified(agent_source: str) -> None:
    """Mathematically prove that {precursor} strictly dominates all target stages."""
    graph = StaticGraphCompiler.compile_source(agent_source, filename="{module_name}.py")
    adj = graph.adjacency_list(include_fallbacks=True)
    root = graph.initial_stage
    assert root is not None, "Initial stage must be declared"

    proof = verify_dominance(
        root=root,
        graph=adj,
        precursor="{precursor}",
        targets={targets_repr},
    )
    assert proof.satisfied is True, f"Dominance proof failed: {{proof.summary()}}"
    assert proof.violating_path is None


def test_precursor_dominance_bypass_detection(agent_source: str) -> None:
    """Verify compiler synthesises counterexample path when an illegal bypass edge is introduced."""
    graph = StaticGraphCompiler.compile_source(agent_source, filename="{module_name}.py")
    adj = graph.adjacency_list(include_fallbacks=True)
    root = graph.initial_stage
    assert root is not None

    target = {targets_repr}[0]
    if root == "{precursor}":
        adj["synthetic_bypass_entry"] = {{root, target}}
        proof = verify_dominance(
            root="synthetic_bypass_entry",
            graph=adj,
            precursor="{precursor}",
            targets=[target],
        )
    else:
        adj[root].add(target)
        proof = verify_dominance(
            root=root,
            graph=adj,
            precursor="{precursor}",
            targets=[target],
        )
    assert proof.satisfied is False
    assert proof.violating_path is not None


@pytest.mark.asyncio
async def test_runtime_enclave_turns() -> None:
    """Verify multi-turn statechart execution through StatechartEngine."""
    agent = {class_name}()
    storage = InMemoryStateStore()

    # Discover and instantiate embedded mock classifier
    import {module_name} as agent_mod
    classifier_cls = next(
        getattr(agent_mod, name)
        for name in dir(agent_mod)
        if name.startswith("Mock") and name.endswith("Classifier")
    )
    classifier = classifier_cls()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "test_{module_name}_turn_session"

    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="{turn_1_message}",
        )
    )
    assert isinstance(t1, BlockstateTurnYield)
    assert t1.state == "in_progress"

    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="{turn_2_message}",
        )
    )
    assert isinstance(t2, BlockstateTurnComplete)
    assert t2.state == "completed"


@pytest.mark.asyncio
async def test_stage_scoped_tool_gatekeeper_security() -> None:
    """Verify gatekeeper raises SecurityViolationError (BLK-SEC-001) on unwhitelisted tool calls."""
    agent = {class_name}()
    initial_stage_tools = agent.stages["{precursor}"].tools
    dispatch = agent.gatekeeper.build_dispatch_table(initial_stage_tools)

    unauthorised_tool = "unwhitelisted_administrative_override_tool"
    assert unauthorised_tool not in dispatch

    with pytest.raises(SecurityViolationError) as exc_info:
        await agent.gatekeeper.invoke(
            tool_name=unauthorised_tool,
            allowed_tools=initial_stage_tools,
            arguments={{"param": "test"}},
        )
    assert exc_info.value.code == "BLK-SEC-001"
'''


def _render_env_example() -> str:
    return """# Blockstate Enclave Runtime Configuration
BLOCKSTATE_STORAGE_BACKEND=in_memory
BLOCKSTATE_SQLITE_PATH=.blockstate/enclave.db

# Cryptographic PII Vault Master Key (AES-256-GCM 32-byte hex key)
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
BLOCKSTATE_VAULT_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BLOCKSTATE_VAULT_PEPPER=session_deduplication_pepper_token

# Optional Model Provider API Keys (if integrating external LLM adapters)
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
"""


def _render_workflow(module_name: str, dominance_assertion: str, test_filename: str) -> str:
    return f"""name: Blockstate Enclave Verification

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  verify-enclave:
    name: Verify Enclave AST, Dominators and Tests
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install blockstate pytest pytest-asyncio

      - name: Blockstate Offline AST Check
        run: blockstate check {module_name}.py

      - name: Blockstate Lengauer-Tarjan Dominator Verification
        run: blockstate verify {module_name}.py --dominates "{dominance_assertion}"

      - name: Run Enclave Unit Tests
        run: pytest {test_filename} -v
"""


def _render_readme(
    agent_class: str,
    module_name: str,
    template_name: str,
    dominance_assertion: str,
    test_filename: str,
) -> str:
    return f"""# {agent_class} Compliance Enclave

This repository contains a production-grade Blockstate compliance enclave scaffolded from the
`{template_name}` template. It implements a Declarative Control Grammar statechart with
stage-scoped tool whitelists, slot schemas, and compile-time Lengauer-Tarjan dominance proofs.

## Architectural Guarantees

1. **Deterministic Statechart Topology**: Offline AST compilation via `StaticGraphCompiler`.
2. **Precursor Dominance Invariant**: Certified via `verify_dominance("{dominance_assertion}")`.
3. **Stage-Scoped Tool Gatekeeper**: Tool access is strictly restricted to active stage whitelists.
4. **Cryptographic Turn Ledger**: Chronological execution recorded with SHA-256 hash chains.

## Quickstart Verification

Execute these verification commands directly in your terminal:

```bash
# 1. Statically inspect agent topology and stage declarations offline
blockstate check {module_name}.py

# 2. Mathematically prove precursor dominance
blockstate verify {module_name}.py --dominates "{dominance_assertion}"

# 3. Run the automated pytest test suite
pytest {test_filename} -v

# 4. Run local simulation
python {module_name}.py
```

## Launching Visual Studio

To explore this enclave in the interactive visual topology canvas:

```bash
blockstate studio {module_name}.py
```
"""


# ---------------------------------------------------------------------------
# Template Registry
# ---------------------------------------------------------------------------

TEMPLATES: dict[TemplateType, EnclaveTemplate] = {
    TemplateType.BANKING: EnclaveTemplate(
        name="banking",
        description="Retail banking funds transfer enclave with mandatory KYC dominance.",
        agent_class_name="BankingTransferAgent",
        precursor_stage="verify_identity",
        target_stages=("execute_transfer",),
        dominance_assertion="verify_identity -> execute_transfer",
        turn_1_message="My customer ID is CUST-001 and sort code 20-00-00.",
        turn_2_message="Transfer 250 GBP to account 88776655.",
        render_agent_source=_render_banking_agent,
        render_test_source=_render_test_source,
    ),
    TemplateType.INSURANCE: EnclaveTemplate(
        name="insurance",
        description="Motor insurance FNOL claim enclave with pushdown automaton digressions.",
        agent_class_name="InsuranceClaimAgent",
        precursor_stage="verify_policy",
        target_stages=("fast_track_settlement",),
        dominance_assertion="verify_policy -> fast_track_settlement",
        turn_1_message="Claiming on policy POL-UK-8821 for registration AB21 CDE.",
        turn_2_message="Accident happened on 2026-10-15 with bumper damage.",
        render_agent_source=_render_insurance_agent,
        render_test_source=_render_test_source,
    ),
    TemplateType.HEALTHCARE: EnclaveTemplate(
        name="healthcare",
        description="Healthcare clinical triage enclave with Vaulted PHI data protection.",
        agent_class_name="HealthcareTriageAgent",
        precursor_stage="patient_intake",
        target_stages=("emergency_dispatch", "schedule_clinic"),
        dominance_assertion="patient_intake -> emergency_dispatch, schedule_clinic",
        turn_1_message="Patient NHS 943 476 5919 phone 07700 900123.",
        turn_2_message="Reporting fever symptoms with routine priority.",
        render_agent_source=_render_healthcare_agent,
        render_test_source=_render_test_source,
    ),
    TemplateType.MINIMAL: EnclaveTemplate(
        name="minimal",
        description="Minimal 3-stage starter enclave for rapid developer prototyping.",
        agent_class_name="MinimalAgent",
        precursor_stage="intake",
        target_stages=("complete",),
        dominance_assertion="intake -> complete",
        turn_1_message="Initialising request REQ-1001.",
        turn_2_message="Execute processing action ACT-42.",
        render_agent_source=_render_minimal_agent,
        render_test_source=_render_test_source,
    ),
}


# ---------------------------------------------------------------------------
# Scaffolding Engine
# ---------------------------------------------------------------------------


def scaffold_project(
    target_dir: Path | str,
    template: str | TemplateType = "banking",
    force: bool = False,
    agent_name: str | None = None,
) -> list[Path]:
    """Scaffold a ready-to-verify Blockstate compliance enclave repository.

    Args:
        target_dir: Destination directory path.
        template: Template identifier (banking, insurance, healthcare, minimal).
        force: Overwrite existing files if destination is non-empty.
        agent_name: Optional custom prefix for generated files and class names.

    Returns:
        List of generated file paths.

    Raises:
        FileExistsError: If destination contains files and force is False.
        ValueError: If template identifier is unrecognised.
    """
    dest = Path(target_dir)

    try:
        template_key = (
            template if isinstance(template, TemplateType) else TemplateType(str(template).lower())
        )
    except ValueError:
        supported = ", ".join(t.value for t in TemplateType)
        raise ValueError(
            f"Unknown template '{template}'. Supported templates: {supported}."
        ) from None

    if template_key not in TEMPLATES:
        supported = ", ".join(t.value for t in TemplateType)
        raise ValueError(f"Unknown template '{template}'. Supported templates: {supported}.")

    enclave_template = TEMPLATES[template_key]

    if dest.exists() and any(dest.iterdir()) and not force:
        raise FileExistsError(
            f"Target directory '{dest}' is not empty. Use force=True to overwrite."
        )

    dest.mkdir(parents=True, exist_ok=True)
    workflow_dir = dest / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)

    base_name = agent_name.strip() if agent_name else enclave_template.name
    module_name = f"{base_name}_agent"
    class_name = enclave_template.agent_class_name
    test_filename = (
        f"test_{base_name}.py" if enclave_template.name == "minimal" else f"test_{module_name}.py"
    )

    generated_files: list[Path] = []

    # 1. Agent file
    agent_path = dest / f"{module_name}.py"
    agent_code = enclave_template.render_agent_source(module_name, class_name)
    agent_path.write_text(agent_code, encoding="utf-8")
    generated_files.append(agent_path)

    # 2. Test file
    test_path = dest / test_filename
    test_code = enclave_template.render_test_source(
        module_name,
        class_name,
        enclave_template.precursor_stage,
        enclave_template.target_stages,
        enclave_template.turn_1_message,
        enclave_template.turn_2_message,
    )
    test_path.write_text(test_code, encoding="utf-8")
    generated_files.append(test_path)

    # 3. Environment configuration template
    env_path = dest / ".env.example"
    env_path.write_text(_render_env_example(), encoding="utf-8")
    generated_files.append(env_path)

    # 4. GitHub Actions CI workflow
    workflow_path = workflow_dir / "blockstate-verify.yml"
    workflow_code = _render_workflow(
        module_name,
        enclave_template.dominance_assertion,
        test_filename,
    )
    workflow_path.write_text(workflow_code, encoding="utf-8")
    generated_files.append(workflow_path)

    # 5. README documentation
    readme_path = dest / "README.md"
    readme_code = _render_readme(
        class_name,
        module_name,
        enclave_template.name,
        enclave_template.dominance_assertion,
        test_filename,
    )
    readme_path.write_text(readme_code, encoding="utf-8")
    generated_files.append(readme_path)

    return generated_files


scaffold_enclave = scaffold_project

__all__: list[str] = [
    "TEMPLATES",
    "EnclaveTemplate",
    "TemplateType",
    "scaffold_enclave",
    "scaffold_project",
]
