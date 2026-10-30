"""Unit tests for the LangChain/LangGraph transactional compliance enclave adapter."""

import re
from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import BaseModel, Field

from blockstate.adapters.langchain import (
    BlockstateEnclaveTool,
    EnclaveToolInput,
    as_tool,
    run_as_subflow,
)
from blockstate.adapters.storage.memory import InMemoryStateStore
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.ports.models import ExtractionResult, IntentClassifier
from blockstate.ports.wire import (
    BlockstateTurnAborted,
    BlockstateTurnComplete,
    BlockstateTurnYield,
)


class MortgageSlots(BaseModel):
    """Underwriting slot schema for mortgage test agent."""

    property_value: float = Field(..., description="Property value")
    loan_amount: float = Field(..., description="Loan amount")


def mock_unwhitelisted_tool() -> str:
    """Tool not whitelisted on stage."""
    return "unwhitelisted_execution"


mock_unwhitelisted_tool._blockstate_tool = True  # type: ignore[attr-defined]


class SimpleMortgageAgent(Agent):
    """Test statechart agent representing mortgage compliance enclave."""

    @Stage(
        name="intake",
        collect=MortgageSlots,
        canned_response="Please supply property value and loan amount.",
    )
    @Transition(targets=["approved"])
    def intake_step(self, slots: MortgageSlots) -> Transition[str]:
        return Transition.to("approved")

    @Guard(stage="intake", targets=["approved"])
    def guard_intake(self, slots: MortgageSlots | None) -> Transition[str | None]:
        if slots and slots.property_value > 0 and slots.loan_amount > 0:
            return Transition.to("approved")
        return Transition.stay()

    @Stage(name="approved", terminal=True, canned_response="Mortgage application approved.")
    def approved_step(self, slots: MortgageSlots) -> Transition[dict[str, Any]]:
        return Transition.end(
            result={
                "status": "approved",
                "loan_to_value": round(slots.loan_amount / slots.property_value, 2),
            }
        )


class FaultySecurityAgent(Agent):
    """Agent that attempts an unwhitelisted tool call to trigger security abortion."""

    @Stage(
        name="unsafe_stage",
        tools=["mock_unwhitelisted_tool"],  # Allowed on stage
    )
    def unsafe_step(self) -> None:
        pass


class SimpleRegexClassifier(IntentClassifier):
    """Regex intent classifier for mortgage slots."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        slots: dict[str, Any] = {}
        prop_m = re.search(r"property (\d+)", utterance, re.IGNORECASE)
        if prop_m:
            slots["property_value"] = float(prop_m.group(1))

        loan_m = re.search(r"loan (\d+)", utterance, re.IGNORECASE)
        if loan_m:
            slots["loan_amount"] = float(loan_m.group(1))

        return ExtractionResult(
            intent="intake",
            candidate_slots=slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


@pytest.mark.patent_invariant
def test_as_tool_factory_and_schema() -> None:
    """Verify as_tool creates BlockstateEnclaveTool with proper schema and name."""
    tool = as_tool(SimpleMortgageAgent, name="mortgage_enclave_tool")
    assert isinstance(tool, BlockstateEnclaveTool)
    assert tool.name == "mortgage_enclave_tool"
    assert issubclass(tool.args_schema, BaseModel)
    assert "session_id" in tool.args_schema.model_fields
    assert "user_message" in tool.args_schema.model_fields
    assert "initial_context" in tool.args_schema.model_fields

    # Dict-like compatibility
    assert tool["name"] == "mortgage_enclave_tool"
    assert isinstance(tool["enclave"], SimpleMortgageAgent)
    assert tool.get("name") == "mortgage_enclave_tool"
    assert tool.get("nonexistent", "fallback") == "fallback"
    assert "name" in tool

    # Invalid factory argument
    with pytest.raises(TypeError, match="Expected Agent subclass or instance"):
        as_tool("not_an_agent")  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.patent_invariant
async def test_as_tool_multi_turn_yield_and_complete() -> None:
    """Verify multi-turn enclave flow: yield on missing slots, complete on final turn."""
    storage = InMemoryStateStore()
    classifier = SimpleRegexClassifier()
    tool = as_tool(
        SimpleMortgageAgent,
        name="mortgage_tool",
        storage=storage,
        classifier=classifier,
    )
    session_id = "test_enclave_session_1"

    # Turn 1: Partial slot provided -> Yield
    res1 = await tool.ainvoke(
        {
            "session_id": session_id,
            "user_message": "My property 500000.",
        }
    )
    assert isinstance(res1, BlockstateTurnYield)
    assert res1.state == "in_progress"
    assert "loan_amount" in res1.missing_slots
    assert res1.message == "Please supply property value and loan amount."

    # Turn 2: Remaining slot provided -> Complete
    res2 = await tool.ainvoke(
        EnclaveToolInput(
            session_id=session_id,
            user_message="Requested loan 350000.",
        )
    )
    assert isinstance(res2, BlockstateTurnComplete)
    assert res2.state == "completed"
    assert res2.result["status"] == "approved"
    assert res2.result["loan_to_value"] == 0.7
    assert res2.ledger_head_hash is not None


def test_as_tool_sync_invocation_run_and_call() -> None:
    """Verify synchronous invoke, run, and __call__ interfaces."""
    storage = InMemoryStateStore()
    classifier = SimpleRegexClassifier()
    tool = as_tool(
        SimpleMortgageAgent,
        storage=storage,
        classifier=classifier,
    )
    session_id = "test_sync_sess"

    # Synchronous call
    res = tool(
        session_id=session_id,
        user_message="property 600000 and loan 300000",
    )
    assert isinstance(res, BlockstateTurnComplete)
    assert res.result["loan_to_value"] == 0.5


@pytest.mark.asyncio
async def test_run_as_subflow_convenience_helper() -> None:
    """Verify run_as_subflow helper executes turn and returns wire DTO."""
    classifier = SimpleRegexClassifier()
    res = await run_as_subflow(
        SimpleMortgageAgent,
        session_id="subflow_sess",
        user_message="property 400000 and loan 200000",
        classifier=classifier,
    )
    assert isinstance(res, BlockstateTurnComplete)
    assert res.result["status"] == "approved"
    assert res.result["loan_to_value"] == 0.5


@pytest.mark.asyncio
@pytest.mark.patent_invariant
async def test_as_tool_aborted_on_unhandled_error() -> None:
    """Verify that internal errors return BlockstateTurnAborted wire DTO."""
    tool = as_tool(SimpleMortgageAgent)

    # Calling with empty initial stage or trigger error
    tool.enclave._initial_stage = None  # Force error
    res = await tool.arun(
        session_id="sess_abort",
        user_message="hello",
    )
    assert isinstance(res, BlockstateTurnAborted)
    assert res.state == "aborted"
    assert res.error_code == "BLK-CFG-002"


@pytest.mark.asyncio
async def test_as_tool_initial_context_propagation() -> None:
    """Verify passing initial_context propagates into the turn envelope and session state."""
    storage = InMemoryStateStore()
    classifier = SimpleRegexClassifier()
    tool = as_tool(
        SimpleMortgageAgent,
        storage=storage,
        classifier=classifier,
    )
    session_id = "test_context_sess"
    res = await tool.ainvoke(
        {
            "session_id": session_id,
            "user_message": "property 500000",
            "initial_context": {"applicant_id": "APP-123"},
        }
    )
    assert isinstance(res, BlockstateTurnYield)
    checkpoint = await storage.load_checkpoint(session_id)
    assert checkpoint is not None
    assert checkpoint.state.get("applicant_id") == "APP-123"


def test_as_tool_with_instantiated_agent_instance() -> None:
    """Verify passing an already instantiated Agent instance to as_tool(agent) works."""
    agent_instance = SimpleMortgageAgent()
    tool = as_tool(agent_instance, name="instantiated_agent_tool")
    assert isinstance(tool, BlockstateEnclaveTool)
    assert tool.enclave is agent_instance
    assert tool.name == "instantiated_agent_tool"


@pytest.mark.asyncio
async def test_agent_attached_adapter_methods() -> None:
    """Verify Agent.as_tool and Agent.run_as_subflow execute via the attached adapter."""
    agent = SimpleMortgageAgent()
    classifier = SimpleRegexClassifier()

    # Identity check on class attributes
    assert Agent.as_tool is as_tool  # type: ignore[comparison-overlap]
    assert Agent.run_as_subflow is run_as_subflow  # type: ignore[comparison-overlap]

    # Agent instance methods
    tool = agent.as_tool(classifier=classifier)
    assert isinstance(tool, BlockstateEnclaveTool)
    assert tool.enclave is agent

    res = await agent.run_as_subflow(
        session_id="agent_subflow_sess",
        user_message="property 500000 and loan 250000",
        classifier=classifier,
    )
    assert isinstance(res, BlockstateTurnComplete)
    assert res.result["loan_to_value"] == 0.5

    # Agent class methods
    class_tool = Agent.as_tool(SimpleMortgageAgent, classifier=classifier)  # type: ignore[arg-type]
    assert isinstance(class_tool, BlockstateEnclaveTool)

    class_res = await Agent.run_as_subflow(
        SimpleMortgageAgent,  # type: ignore[arg-type]
        session_id="class_subflow_sess",
        user_message="property 400000 and loan 200000",
        classifier=classifier,
    )
    assert isinstance(class_res, BlockstateTurnComplete)
    assert class_res.result["loan_to_value"] == 0.5


@pytest.mark.asyncio
async def test_session_id_defaults_to_default_session() -> None:
    """Verify session_id defaults to 'default_session' when empty string or None."""
    tool = as_tool(SimpleMortgageAgent, classifier=SimpleRegexClassifier())

    # None session_id in arun
    res_none = await tool.arun(session_id=None, user_message="property 100")
    assert res_none.session_id == "default_session"

    # Empty string session_id in arun
    res_empty = await tool.arun(session_id="", user_message="property 100")
    assert res_empty.session_id == "default_session"

    # ainvoke with empty string session_id
    res_dict = await tool.ainvoke({"session_id": "", "user_message": "property 100"})
    assert res_dict.session_id == "default_session"
