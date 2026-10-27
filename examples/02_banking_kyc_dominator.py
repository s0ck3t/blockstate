"""Reference Agent 2: Banking KYC with Lengauer-Tarjan dominator verification.

Demonstrates mathematical dominance proofs over high-value financial transactions.
Ensures that regulatory identity verification (VerifyKYC) dominates all execution
routes leading to fund transfers (TransferFunds).
"""

import asyncio
import contextlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.compiler.ast_extractor import StaticGraphCompiler
from blockstate.compiler.dominators import verify_dominance
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class KYCSlots(BaseModel):
    """Customer identity credentials required by banking regulations."""

    customer_id: str = Field(..., description="Unique customer banking identifier")
    passport_number: str = Field(..., description="Government-issued passport number")


class TransferSlots(BaseModel):
    """Financial transfer transaction instructions."""

    beneficiary_iban: str = Field(..., description="Destination beneficiary IBAN")
    amount_gbp: float = Field(..., description="Transfer amount in GBP")


class BankingKYCDominatorAgent(Agent):
    """Regulated banking statechart enforcing mandatory KYC before fund transfer."""

    @Stage(
        name="VerifyKYC",
        collect=KYCSlots,
        canned_response="Please present your customer ID and passport number for KYC verification.",
    )
    @Transition(targets=["AssessAccountRisk"])
    def kyc_stage(self, slots: KYCSlots) -> Transition[str | None]:
        """Perform customer due diligence verification."""
        if slots.customer_id and slots.passport_number:
            return Transition.to("AssessAccountRisk")
        return Transition.stay()

    @Guard(stage="VerifyKYC", targets=["AssessAccountRisk"])
    def guard_kyc_passed(self, slots: KYCSlots | None) -> Transition[str | None]:
        """Deterministic guard verifying KYC credentials have been validated."""
        if slots is not None and slots.customer_id and slots.passport_number:
            return Transition.to("AssessAccountRisk")
        return Transition.stay()

    @Stage(
        name="AssessAccountRisk",
        canned_response="KYC verified. Please specify the beneficiary IBAN and amount to transfer.",
    )
    @Transition(targets=["TransferFunds", "ManualComplianceReview"])
    def risk_assessment_stage(self) -> Transition[str]:
        """Route standard transfers directly or escalate high-risk transactions."""
        # Risk assessment evaluates risk score threshold
        risk_score = 10
        if risk_score > 80:
            return Transition.to("ManualComplianceReview")
        return Transition.to("TransferFunds")

    @Stage(
        name="ManualComplianceReview",
        canned_response="Your transfer has been flagged for enhanced compliance review.",
    )
    @Transition(targets=["TransferFunds", "RejectTransfer"])
    def review_stage(self) -> Transition[str]:
        """Officer review path that can either approve or reject."""
        is_sanctioned = False
        if is_sanctioned:
            return Transition.to("RejectTransfer")
        return Transition.to("TransferFunds")

    @Stage(
        name="TransferFunds",
        terminal=True,
        canned_response="Transfer successfully executed across the interbank clearing rail.",
    )
    def transfer_stage(self) -> Transition[dict[str, Any]]:
        """Terminal execution stage formalising money movement."""
        return Transition.end(
            result={
                "status": "settled",
                "rail": "FPS",
                "reference": "TXN-LON-77192",
            }
        )

    @Stage(
        name="RejectTransfer",
        terminal=True,
        canned_response="Transfer declined following compliance review.",
    )
    def reject_stage(self) -> Transition[dict[str, Any]]:
        """Terminal rejection stage."""
        return Transition.end(result={"status": "rejected"})


class BankingDialogueClassifier(IntentClassifier):
    """Deterministic extractor for KYC verification and transfer details."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        candidate_slots: dict[str, Any] = {}

        # Extract customer ID
        cust_match = re.search(r"CUST-[A-Z0-9]+", utterance)
        if cust_match:
            candidate_slots["customer_id"] = cust_match.group(0)

        # Extract passport number (or vaulted token)
        pass_match = re.search(r"(?:PASS-[A-Z0-9]+|<VAULT:[^>]+>|[A-Z]{2}\d{7})", utterance)
        if pass_match:
            candidate_slots["passport_number"] = pass_match.group(0)

        # Extract IBAN
        iban_match = re.search(r"GB\d{2}[A-Z]{4}\d{14}", utterance)
        if iban_match:
            candidate_slots["beneficiary_iban"] = iban_match.group(0)

        # Extract amount
        amt_match = re.search(r"[£$]?(\d+(?:\.\d{2})?)", utterance)
        if amt_match:
            with contextlib.suppress(ValueError):
                candidate_slots["amount_gbp"] = float(amt_match.group(1))

        return ExtractionResult(
            intent="VerifyKYC",
            candidate_slots=candidate_slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.5,
        )


async def main() -> None:
    """Run interactive simulation and prove mathematical dominance."""
    print("--- Running Banking KYC Dominator Reference Agent ---")

    # 1. Compile graph and mathematically prove dominance offline
    graph = StaticGraphCompiler.compile_source(
        Path(__file__).read_text(encoding="utf-8"),
        filename=__file__,
    )
    adj = graph.adjacency_list(include_fallbacks=True)
    proof = verify_dominance(
        root="VerifyKYC",
        graph=adj,
        precursor="VerifyKYC",
        targets=["TransferFunds"],
    )
    print(f"Dominance Proof: {proof.summary()}")
    assert proof.satisfied is True, "Precursor VerifyKYC must strictly dominate TransferFunds"

    # 2. Execute conversational turns
    agent = BankingKYCDominatorAgent()
    storage = InMemoryStateStore()
    classifier = BankingDialogueClassifier()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)
    session_id = "banking_kyc_001"

    # Turn 1: Provide KYC credentials
    t1 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=1,
            user_message="Hello, my customer ID is CUST-8831 and passport is GB1234567.",
        )
    )
    print(f"Turn 1 State: {t1.state} | Message: {getattr(t1, 'message', '')}")
    assert isinstance(t1, BlockstateTurnYield)

    # Turn 2: Route through risk assessment and execute transfer
    t2 = await engine.step(
        TurnEnvelope(
            session_id=session_id,
            turn_index=2,
            user_message="Please transfer £500 to beneficiary GB29NWBK60161331926819.",
        )
    )
    print(f"Turn 2 State: {t2.state} | Result: {getattr(t2, 'result', None)}")
    assert isinstance(t2, BlockstateTurnComplete)
    assert t2.result["status"] == "settled"
    print("--- Banking KYC Dominator Reference Agent Completed Successfully ---")


if __name__ == "__main__":
    asyncio.run(main())
