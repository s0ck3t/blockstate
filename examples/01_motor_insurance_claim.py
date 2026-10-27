"""Reference Agent 1: Regulated motor insurance claim with digression handling.

Demonstrates Declarative Control Grammar (DCG) slot collection across multiple turns,
isolated digression handling with call-return pushdown semantics via TaskStack,
and cryptographic TurnLedger non-repudiation.
"""

import asyncio
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class MotorClaimSlots(BaseModel):
    """Declarative slot schema for motor insurance first notice of loss (FNOL)."""

    policy_number: str = Field(..., description="Active motor insurance policy number")
    incident_date: str = Field(..., description="Date of the incident in YYYY-MM-DD format")
    incident_description: str = Field(..., description="Summary of the incident damage")


class MotorInsuranceClaimAgent(Agent):
    """Regulated conversational statechart for motor vehicle insurance claim intake."""

    @Stage(
        name="intake",
        collect=MotorClaimSlots,
        allow_digressions=["policy_faq"],
        max_turns=5,
        canned_response="Please provide your policy number, incident date, and damage description.",
    )
    @Transition(targets=["settle_claim"])
    def intake_stage(self, slots: MotorClaimSlots) -> Transition[str | None]:
        """Process collected slots and route to claim settlement."""
        if slots.policy_number.startswith("POL-"):
            return Transition.to("settle_claim")
        return Transition.stay()

    @Guard(stage="intake", targets=["settle_claim"])
    def guard_intake_complete(self, slots: MotorClaimSlots | None) -> Transition[str | None]:
        """Deterministic guard verifying all mandatory claim details are supplied."""
        if (
            slots is not None
            and slots.policy_number
            and slots.incident_date
            and slots.incident_description
        ):
            return Transition.to("settle_claim")
        return Transition.stay()

    @Stage(
        name="policy_faq",
        canned_response=(
            "Standard comprehensive coverage includes accidental damage subject to excess."
        ),
    )
    def faq_stage(self) -> Transition[None]:
        """Digression sub-flow answering policy coverage inquiries then returning to parent."""
        return Transition.pop_frame()

    @Stage(
        name="settle_claim",
        terminal=True,
        canned_response="Your claim has been registered and approved for repair assessment.",
    )
    def settlement_stage(self, slots: MotorClaimSlots) -> Transition[dict[str, Any]]:
        """Terminal stage formalising claim settlement."""
        return Transition.end(
            result={
                "status": "approved",
                "policy_number": slots.policy_number,
                "incident_date": slots.incident_date,
                "claim_reference": "CLM-GB-88421",
            }
        )


class MotorClaimClassifier(IntentClassifier):
    """Local deterministic semantic extractor for motor claim dialogue turns."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        candidate_slots: dict[str, Any] = {}

        # Extract policy number pattern (POL-XXXXX) supporting vaulted tokens
        pol_match = re.search(r"POL-(?:[0-9]+|<VAULT:[^>]+>|\w+)", utterance)
        if pol_match:
            candidate_slots["policy_number"] = pol_match.group(0)

        # Extract incident date (YYYY-MM-DD)
        date_match = re.search(r"\d{4}-\d{2}-\d{2}", utterance)
        if date_match:
            candidate_slots["incident_date"] = date_match.group(0)

        # Extract incident description
        is_damage_utterance = "damage" in utterance.lower() or "bumper" in utterance.lower()
        if is_damage_utterance and "does my policy cover" not in utterance.lower():
            candidate_slots["incident_description"] = utterance

        # Check for permitted digression intent
        intent = "intake"
        if "cover" in utterance.lower() or "policy cover" in utterance.lower():
            intent = "policy_faq"

        return ExtractionResult(
            intent=intent,
            candidate_slots=candidate_slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=2.0,
        )


async def main() -> None:
    """Run interactive simulation demonstrating intake, digression, and completion."""
    print("--- Running Motor Insurance Claim Reference Agent ---")
    agent = MotorInsuranceClaimAgent()
    storage = InMemoryStateStore()
    classifier = MotorClaimClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "claim_session_001"

    # Turn 1: Partial intake
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="Hello, my policy number is POL-99234.",
        )
    )
    print(f"Turn 1 State: {t1.state} | Message: {getattr(t1, 'message', '')}")
    assert isinstance(t1, BlockstateTurnYield)

    # Turn 2: Digression tangent
    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Wait, does my policy cover accidental vehicle damage?",
        )
    )
    print(f"Turn 2 State: {t2.state} | Message: {getattr(t2, 'message', '')}")
    assert isinstance(t2, BlockstateTurnYield)

    # Turn 3: Complete remaining slots
    t3 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=3,
            user_message=(
                "Incident date is 2026-10-20. Reversing into a bollard caused rear bumper dent."
            ),
        )
    )
    print(f"Turn 3 State: {t3.state} | Result: {getattr(t3, 'result', None)}")
    assert isinstance(t3, BlockstateTurnComplete)
    assert t3.result["status"] == "approved"
    assert str(t3.result["policy_number"]).startswith("POL-")
    print("--- Motor Insurance Claim Reference Agent Completed Successfully ---")


if __name__ == "__main__":
    asyncio.run(main())
