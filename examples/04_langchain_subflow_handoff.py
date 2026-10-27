"""Reference Agent 4: LangGraph/LangChain subflow transactional compliance enclave handoff.

Demonstrates mounting a Blockstate Declarative Control Grammar agent as a LangChain-compatible
tool via `as_tool()` and executing multi-turn compliance workflows from outer orchestrators
(such as LangGraph, Semantic Kernel, or AutoGen) with zero internal engine state leakage.
"""

import asyncio
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from blockstate.adapters.langchain import as_tool, run_as_subflow
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.wire import BlockstateTurnComplete, BlockstateTurnYield


class MortgageSlots(BaseModel):
    """Financial parameters required for regulated mortgage affordability origination."""

    property_value: float = Field(..., description="Estimated market valuation of the property")
    loan_amount: float = Field(..., description="Requested borrowing principal amount")
    annual_income: float = Field(..., description="Gross verifiable annual applicant income")


class MortgageOriginationEnclave(Agent):
    """Regulated mortgage lending statechart executed as a compliance enclave."""

    @Stage(
        name="intake_financials",
        collect=MortgageSlots,
        canned_response=(
            "Please state property valuation, requested borrowing amount, and gross annual income."
        ),
    )
    @Transition(targets=["underwrite_offer"])
    def intake_stage(self, slots: MortgageSlots) -> Transition[str]:
        """Collect applicant financial metrics."""
        return Transition.to("underwrite_offer")

    @Guard(stage="intake_financials", targets=["underwrite_offer"])
    def guard_financials_complete(self, slots: MortgageSlots | None) -> Transition[str | None]:
        """Deterministic guard verifying all underwriting inputs are present."""
        if (
            slots is not None
            and slots.property_value > 0
            and slots.loan_amount > 0
            and slots.annual_income > 0
        ):
            return Transition.to("underwrite_offer")
        return Transition.stay()

    @Stage(
        name="underwrite_offer",
        terminal=True,
        canned_response="Mortgage underwriting assessment completed.",
    )
    def underwriting_stage(self, slots: MortgageSlots) -> Transition[dict[str, Any]]:
        """Terminal underwriting stage evaluating loan-to-value (LTV) and debt-to-income."""
        ltv = slots.loan_amount / slots.property_value
        dti = slots.loan_amount / slots.annual_income
        approved = ltv <= 0.85 and dti <= 4.5

        return Transition.end(
            result={
                "decision": "approved" if approved else "declined",
                "ltv_ratio": round(ltv, 4),
                "dti_ratio": round(dti, 4),
                "approved_principal": slots.loan_amount if approved else 0.0,
                "regulatory_disclosure": "FCA MCOB compliant deterministic assessment",
            }
        )


class MortgageDialogueClassifier(IntentClassifier):
    """Deterministic extractor for mortgage financial parameters."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        candidate_slots: dict[str, Any] = {}

        # Extract property value
        prop_pattern = r"property\s+(?:value\s+(?:is\s+)?|valuation\s+)?([£$]?\d+)"
        prop_m = re.search(prop_pattern, utterance, re.IGNORECASE)
        if prop_m:
            val_clean = prop_m.group(1).replace("£", "").replace("$", "")
            candidate_slots["property_value"] = float(val_clean)

        # Extract loan amount
        loan_pattern = r"loan\s+(?:amount\s+|borrowing\s+)?([£$]?\d+)"
        loan_m = re.search(loan_pattern, utterance, re.IGNORECASE)
        if loan_m:
            loan_clean = loan_m.group(1).replace("£", "").replace("$", "")
            candidate_slots["loan_amount"] = float(loan_clean)

        # Extract annual income
        income_m = re.search(r"income\s+(?:is\s+)?([£$]?\d+)", utterance, re.IGNORECASE)
        if income_m:
            inc_clean = income_m.group(1).replace("£", "").replace("$", "")
            candidate_slots["annual_income"] = float(inc_clean)

        return ExtractionResult(
            intent="intake_financials",
            candidate_slots=candidate_slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.1,
        )


async def main() -> None:
    """Simulate outer LangGraph orchestrator invoking the enclave tool."""
    print("--- Running LangChain/LangGraph Subflow Enclave Reference Agent ---")

    classifier = MortgageDialogueClassifier()

    # 1. Mount the enclave as a LangChain-compatible tool
    mortgage_tool = as_tool(
        MortgageOriginationEnclave,
        name="execute_mortgage_transaction",
        classifier=classifier,
    )

    print(f"Mounted Tool Name: {mortgage_tool.name}")
    print(f"Tool Argument Schema: {mortgage_tool.args_schema.model_fields.keys()}")

    session_id = "mortgage_enclave_sess_001"

    # Outer Orchestrator Turn 1: Invocation with partial information
    print("\n[Outer Orchestrator] Invoking enclave tool (Turn 1 - Partial Details)...")
    turn1_result = await mortgage_tool.ainvoke(
        {
            "session_id": session_id,
            "user_message": "The property value is £400000.",
        }
    )
    print(f"Enclave Response State: {turn1_result.state}")
    print(f"Yielded Message: {getattr(turn1_result, 'message', '')}")
    print(f"Missing Required Slots: {getattr(turn1_result, 'missing_slots', ())}")
    assert isinstance(turn1_result, BlockstateTurnYield)
    assert "loan_amount" in turn1_result.missing_slots
    assert "annual_income" in turn1_result.missing_slots

    # Outer Orchestrator Turn 2: Providing remaining underwriting slots
    print("\n[Outer Orchestrator] Invoking enclave tool (Turn 2 - Complete Financials)...")
    turn2_result = await mortgage_tool.ainvoke(
        {
            "session_id": session_id,
            "user_message": "Requested loan amount £300000 with gross annual income £120000.",
        }
    )
    print(f"Enclave Response State: {turn2_result.state}")
    print(f"Final Decision: {getattr(turn2_result, 'result', {})}")
    assert isinstance(turn2_result, BlockstateTurnComplete)
    assert turn2_result.result["decision"] == "approved"
    assert turn2_result.result["ltv_ratio"] == 0.75
    assert turn2_result.ledger_head_hash is not None

    # 2. Test run_as_subflow convenience helper
    print("\n[Outer Orchestrator] Testing run_as_subflow helper...")
    subflow_res = await run_as_subflow(
        MortgageOriginationEnclave,
        session_id="subflow_sess_002",
        user_message="Property value £500000, loan amount £350000, annual income £100000.",
        classifier=classifier,
    )
    print(f"Subflow Res: {subflow_res}")
    assert isinstance(subflow_res, BlockstateTurnComplete)
    assert subflow_res.result["decision"] == "approved"
    dec = subflow_res.result["decision"]
    ltv = subflow_res.result["ltv_ratio"]
    print(f"Subflow Result: {dec} (LTV: {ltv})")

    print("\n--- LangChain/LangGraph Subflow Enclave Reference Agent Completed Successfully ---")


if __name__ == "__main__":
    asyncio.run(main())
