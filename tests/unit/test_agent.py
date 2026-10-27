"""Unit tests for Declarative Control Grammar (Agent, @Stage, @Transition, @Guard)."""

import pytest
from pydantic import BaseModel

from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.transitions import ChoicePayload
from blockstate.errors import ConfigurationError, DuplicateStageError


class ClaimSlots(BaseModel):
    policy_number: str
    incident_date: str


def helper_tool(x: int) -> int:
    return x * 2


def test_agent_valid_declaration() -> None:
    """Verify standard Agent declaration with stages, guards, and transition targets."""

    class ClaimsAgent(Agent):
        @Stage(
            name="collect_claim",
            collect=ClaimSlots,
            tools=["verify_policy", helper_tool],
            max_turns=3,
            allow_digressions=["faq_digression"],
            allow_slot_overrides=True,
            on_breach="escalate_fraud",
        )
        @Transition(targets=["process_payment", "escalate_fraud"])
        def collect_stage(self, slots: ClaimSlots) -> Transition[str]:
            if slots.policy_number.startswith("POL-"):
                return Transition.to("process_payment")
            return Transition.to("escalate_fraud")

        @Guard(stage="collect_claim", targets=["process_payment"])
        def guard_collect(self) -> Transition[str]:
            return Transition.to("process_payment")

        @Stage(name="process_payment", terminal=True)
        def payment_stage(self) -> Transition[None]:
            return Transition.end(result="paid")

        @Stage(name="escalate_fraud", terminal=True)
        def fraud_stage(self) -> Transition[None]:
            return Transition.end(result="investigating")

    agent = ClaimsAgent(tools={"external_calc": helper_tool})
    assert len(agent.stages) == 3
    assert agent.initial_stage == "collect_claim"

    stage = agent.get_stage("collect_claim")
    assert stage.name == "collect_claim"
    assert stage.collect is ClaimSlots
    assert stage.tools == ("verify_policy", "helper_tool")
    assert stage.max_turns == 3
    assert stage.allow_digressions == ("faq_digression",)
    assert stage.allow_slot_overrides is True
    assert stage.on_breach == "escalate_fraud"
    assert stage.targets == ("process_payment", "escalate_fraud")
    assert len(stage.guards) == 1

    payment_stage = agent.get_stage("process_payment")
    assert payment_stage.terminal is True
    assert agent.gatekeeper.get_tool("external_calc") is helper_tool


def test_stage_name_defaults_to_function_name() -> None:
    """Verify @Stage defaults its identifier to the decorated function's __name__."""

    class AutoNameAgent(Agent):
        @Stage()
        def root_step(self) -> None:
            pass

    agent = AutoNameAgent()
    assert "root_step" in agent.stages


def test_agent_additional_coverage_branches() -> None:
    """Verify ChoicePayload direct passing, string targets in @Guard, and tool methods."""
    choice_direct = ChoicePayload(prompt="Select:", options=["A", "B"])

    class ToolAnnotatedAgent(Agent):
        def tool_method(self, x: int) -> int:
            return x + 1

        tool_method._blockstate_tool = True  # type: ignore[attr-defined]

        @Stage(
            name="stage1",
            choice_options=choice_direct,
        )
        @Transition("stage2")
        def step1(self) -> None:
            pass

        @Guard(stage="stage1", targets="stage2")
        def guard1(self) -> None:
            pass

        @Stage(name="stage2", terminal=True)
        def step2(self) -> None:
            pass

    agent = ToolAnnotatedAgent()
    stage1 = agent.get_stage("stage1")
    assert stage1.choice_options is choice_direct
    assert stage1.targets == ("stage2",)
    assert agent.gatekeeper.get_tool("tool_method") is not None


def test_duplicate_stage_name_raises_duplicate_stage_error() -> None:
    """Verify declaring two stages with identical names raises DuplicateStageError (BLK-CFG-001)."""
    with pytest.raises(DuplicateStageError) as exc_info:

        class InvalidAgent(Agent):
            @Stage(name="verify_identity")
            def step_one(self) -> None:
                pass

            @Stage(name="verify_identity")
            def step_two(self) -> None:
                pass

    assert exc_info.value.code == "BLK-CFG-001"
    assert exc_info.value.stage == "verify_identity"
    assert "Duplicate stage identifier 'verify_identity'" in str(exc_info.value)


def test_empty_stage_name_raises_configuration_error() -> None:
    """Verify empty or blank stage name raises ConfigurationError (BLK-CFG-002)."""
    with pytest.raises(ConfigurationError) as exc_info:

        class InvalidAgent(Agent):
            @Stage(name="   ")
            def step_one(self) -> None:
                pass

    assert exc_info.value.code == "BLK-CFG-002"
    assert "cannot be empty or blank" in str(exc_info.value)


def test_invalid_tool_in_stage_raises_configuration_error() -> None:
    """Verify passing invalid tool types into @Stage raises ConfigurationError."""
    with pytest.raises(ConfigurationError) as exc_info:

        class InvalidAgent(Agent):
            @Stage(name="step", tools=[12345])  # type: ignore[list-item]
            def step_one(self) -> None:
                pass

    assert exc_info.value.code == "BLK-CFG-002"
    assert "Invalid tool specification" in str(exc_info.value)


def test_empty_transition_target_raises_configuration_error() -> None:
    """Verify empty transition targets raise ConfigurationError (BLK-CFG-002)."""
    with pytest.raises(ConfigurationError) as exc_info:

        class InvalidAgent(Agent):
            @Stage(name="step")
            @Transition(targets=[""])
            def step_one(self) -> None:
                pass

    assert exc_info.value.code == "BLK-CFG-002"
    assert "must be a non-empty string identifier" in str(exc_info.value)


def test_dynamic_stage_registration_rejected() -> None:
    """Verify dynamic runtime stage registration is prohibited."""

    class ValidAgent(Agent):
        @Stage(name="root")
        def root_step(self) -> None:
            pass

    agent = ValidAgent()
    with pytest.raises(ConfigurationError) as exc_info:
        agent.register_dynamic_stage(name="dynamic_stage")

    assert exc_info.value.code == "BLK-CFG-002"
    assert "Dynamic runtime stage creation is prohibited" in str(exc_info.value)


def test_get_unknown_stage_raises_configuration_error() -> None:
    """Verify requesting an unregistered stage raises ConfigurationError."""

    class ValidAgent(Agent):
        @Stage(name="root")
        def root_step(self) -> None:
            pass

    agent = ValidAgent()
    with pytest.raises(ConfigurationError) as exc_info:
        agent.get_stage("non_existent")

    assert exc_info.value.code == "BLK-CFG-002"
    assert "is not registered on agent" in str(exc_info.value)


def test_choice_options_and_canned_response() -> None:
    """Verify stage with canned_response and choice_options constructs ChoicePayload."""

    class InteractiveAgent(Agent):
        @Stage(
            name="pick_department",
            canned_response="Which department do you need?",
            choice_options=["Sales", "Support", "Billing"],
        )
        def select_dept(self) -> None:
            pass

    agent = InteractiveAgent()
    stage = agent.get_stage("pick_department")
    assert isinstance(stage.choice_options, ChoicePayload)
    assert stage.choice_options.prompt == "Which department do you need?"
    assert stage.choice_options.options == ["Sales", "Support", "Billing"]


def test_choice_options_from_mapping_sequence() -> None:
    """Verify choice_options provided as sequence of mappings."""

    class MenuAgent(Agent):
        @Stage(
            name="menu",
            choice_options=[{"id": "opt1", "label": "Option 1"}],
        )
        def menu_step(self) -> None:
            pass

    agent = MenuAgent()
    stage = agent.get_stage("menu")
    assert isinstance(stage.choice_options, ChoicePayload)
    assert len(stage.choice_options.options) == 1


def test_enclave_adapter_interfaces() -> None:
    """Verify Agent enclave adapter interface hooks as_tool() and run_as_subflow()."""

    class EnclaveAgent(Agent):
        @Stage(name="main_step")
        def main_step(self) -> None:
            pass

    agent = EnclaveAgent()
    tool_spec = agent.as_tool("my_enclave_tool")
    assert tool_spec["name"] == "my_enclave_tool"
    assert tool_spec["enclave"] is agent

    default_tool_spec = agent.as_tool()
    assert default_tool_spec["name"] == "EnclaveAgent"


@pytest.mark.asyncio
async def test_agent_run_as_subflow() -> None:
    """Verify Agent run_as_subflow returns execution payload."""

    class EnclaveAgent(Agent):
        @Stage(name="main_step")
        def main_step(self) -> None:
            pass

    agent = EnclaveAgent()
    result = await agent.run_as_subflow("sess_123", "Hello agent", {"key": "val"})
    assert result["session_id"] == "sess_123"
    assert result["user_message"] == "Hello agent"
    assert result["initial_context"] == {"key": "val"}

    res_default = await agent.run_as_subflow("sess_123", "Hi", None)
    assert res_default["initial_context"] == {}
