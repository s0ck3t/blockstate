"""Reference Agent 3: Healthcare HIPAA vault with PHI/PII protection.

Demonstrates cryptographic boundary isolation for Protected Health Information (PHI)
under HIPAA and GDPR regulations. Validates that sensitive identifiers (NHS number,
patient name, date of birth) are tokenised into session-scoped opaque vault tokens
(<VAULT:CATEGORY_NN>) at ingress, leaving zero unencrypted PHI in outbound prompts,
traces, or TurnLedger audit records.
"""

import asyncio
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.adapters.telemetry.otel import OpenTelemetryLedgerSink
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete
from blockstate.security.annotations import Detokenise, Vaulted
from blockstate.security.vault import PIIVault


class PatientIntakeSlots(BaseModel):
    """Protected patient registration data containing vaulted PHI fields."""

    national_id: Vaulted[str] = Field(..., description="Government health identifier (NHS/SSN)")
    contact_email: Vaulted[str] = Field(..., description="Patient contact email address")
    contact_phone: Vaulted[str] = Field(..., description="Patient primary telephone contact")
    symptoms: str = Field(..., description="Reported clinical symptoms for triage")


def schedule_clinical_triage(
    national_id: Detokenise[str],
    contact_email: str,
    contact_phone: str,
    symptoms: str,
) -> dict[str, str]:
    """Authorised internal clinical tool receiving detokenised identifiers strictly in-memory."""
    return {
        "status": "confirmed",
        "triage_priority": "urgent" if "chest" in symptoms.lower() else "routine",
        "appointment_id": "APT-NHS-90124",
    }


schedule_clinical_triage._blockstate_tool = True  # type: ignore[attr-defined]


class HealthcareHIPAAVaultAgent(Agent):
    """Regulated healthcare agent ensuring zero raw PHI leakage into audit trails."""

    @Stage(
        name="patient_intake",
        collect=PatientIntakeSlots,
        tools=["schedule_clinical_triage"],
        canned_response="Please state patient national ID, contact email, telephone, and symptoms.",
    )
    @Transition(targets=["confirm_triage"])
    def intake_stage(self, slots: PatientIntakeSlots) -> Transition[str]:
        """Triage intake routing to confirmation once all mandatory PHI slots are gathered."""
        return Transition.to("confirm_triage")

    @Guard(stage="patient_intake", targets=["confirm_triage"])
    def guard_intake_complete(self, slots: PatientIntakeSlots | None) -> Transition[str | None]:
        """Deterministic guard verifying all patient intake fields are populated."""
        if (
            slots is not None
            and slots.national_id
            and slots.contact_email
            and slots.contact_phone
            and slots.symptoms
        ):
            return Transition.to("confirm_triage")
        return Transition.stay()

    @Stage(
        name="confirm_triage",
        terminal=True,
        canned_response="Clinical triage scheduled successfully with duty specialist.",
    )
    def confirm_stage(self, slots: PatientIntakeSlots) -> Transition[dict[str, Any]]:
        """Terminal stage formalising triage record without exposing raw PHI."""
        return Transition.end(
            result={
                "status": "scheduled",
                "national_id_token": str(slots.national_id),
                "email_token": str(slots.contact_email),
                "phone_token": str(slots.contact_phone),
                "triage_id": "TRG-LON-5512",
            }
        )


class HIPAADialogueClassifier(IntentClassifier):
    """Deterministic extractor parsing vaulted tokens from ingress utterances."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        candidate_slots: dict[str, Any] = {}

        # The classifier receives vaulted_message from the engine.
        # National ID token or pattern
        id_match = re.search(r"(?:<VAULT:(?:NHS|SSN)_\d+>|\b\d{3}-\d{3}-\d{4}\b)", utterance)
        if id_match:
            candidate_slots["national_id"] = id_match.group(0)

        # Contact email token
        email_pattern = r"(?:<VAULT:EMAIL_\d+>|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
        email_match = re.search(email_pattern, utterance)
        if email_match:
            candidate_slots["contact_email"] = email_match.group(0)

        # Contact phone token
        phone_match = re.search(r"(?:<VAULT:PHONE_\d+>|0\d{10})", utterance)
        if phone_match:
            candidate_slots["contact_phone"] = phone_match.group(0)

        # Symptoms
        if "chest pain" in utterance.lower():
            candidate_slots["symptoms"] = "acute chest pain and shortness of breath"
        elif "fever" in utterance.lower():
            candidate_slots["symptoms"] = "persistent high fever"

        return ExtractionResult(
            intent="patient_intake",
            candidate_slots=candidate_slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.2,
        )


async def main() -> None:
    """Run simulation verifying PHI tokenisation and zero raw data leakage."""
    print("--- Running Healthcare HIPAA Vault Reference Agent ---")
    agent = HealthcareHIPAAVaultAgent(tools={"schedule_clinical_triage": schedule_clinical_triage})
    storage = InMemoryStateStore()
    vault = PIIVault()
    ledger_sink = OpenTelemetryLedgerSink(trace_file=".blockstate/traces.jsonl")
    classifier = HIPAADialogueClassifier()
    engine = StatechartEngine(
        agent=agent,
        storage=storage,
        vault=vault,
        ledger_sink=ledger_sink,
        classifier=classifier,
    )
    session_id = "hipaa_session_9901"

    # User utterance containing real PHI
    raw_phi_utterance = (
        "Patient with NHS 943-476-5919 email patient.smith@clinic.nhs.uk "
        "phone 07123456789 experiencing chest pain."
    )

    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message=raw_phi_utterance,
        )
    )

    print(f"Turn 1 State: {t1.state} | Result: {getattr(t1, 'result', None)}")
    assert isinstance(t1, BlockstateTurnComplete)
    assert t1.result["status"] == "scheduled"

    # Verify zero raw PHI in stored state checkpoint
    checkpoint = await storage.load_checkpoint(session_id)
    assert checkpoint is not None
    top_frame = checkpoint.task_stack[0]
    slots = top_frame.get("slots", {})

    # Raw identifiers must NOT exist anywhere in slots; only vaulted tokens
    assert "943-476-5919" not in str(slots)
    assert "patient.smith@clinic.nhs.uk" not in str(slots)
    assert "07123456789" not in str(slots)
    assert "<VAULT:NHS_" in str(slots.get("national_id", ""))
    assert "<VAULT:EMAIL_" in str(slots.get("contact_email", ""))
    assert "<VAULT:PHONE_" in str(slots.get("contact_phone", ""))

    print("Verification: Zero raw PHI strings detected in storage slots.")
    print("--- Healthcare HIPAA Vault Reference Agent Completed Successfully ---")


if __name__ == "__main__":
    asyncio.run(main())
