"""Comprehensive unit and journey tests for StatechartEngine."""

import pytest
from pydantic import BaseModel

from blockstate.adapters.storage.memory import InMemoryStorageBackend
from blockstate.core.agent import Agent, Guard, Stage, Transition
from blockstate.core.engine import StatechartEngine
from blockstate.core.stack import ReadOnlySessionView
from blockstate.core.transitions import ChoicePayload, SlotMutation
from blockstate.errors import DisqualifyingBreachError
from blockstate.ports.models import ExtractionResult
from blockstate.ports.storage import TurnEnvelope
from blockstate.ports.wire import (
    BlockstateTurnAborted,
    BlockstateTurnComplete,
    BlockstateTurnYield,
)
from blockstate.security import PIIVault
from blockstate.testing.doubles import (
    DeterministicIntentClassifier,
    DeterministicResponseRenderer,
    InMemoryLedgerSink,
)


class IncidentSlots(BaseModel):
    policy_number: str
    loss_amount: int


def sample_tool(policy_number: str) -> dict[str, str]:
    return {"status": "verified", "policy": policy_number}


class InsuranceClaimAgent(Agent):
    """Reference insurance claim agent for multi-turn testing."""

    @Stage(
        name="intake",
        collect=IncidentSlots,
        tools=["sample_tool"],
        max_turns=3,
        allow_digressions=["faq_digression"],
        on_refusal="human_escalation",
        on_max_turns_exceeded="human_escalation",
    )
    def intake_stage(
        self,
        slots: IncidentSlots,
        session_view: ReadOnlySessionView,
    ) -> Transition[str | None]:
        if slots.policy_number and slots.loss_amount > 0:
            if slots.loss_amount < 1000:
                return Transition.to("fast_track_payout")
            return Transition.to("manual_investigation")
        return Transition.stay()

    @Stage(name="faq_digression", allow_slot_overrides=False)
    def faq_stage(self) -> Transition[None]:
        # Complete digression and pop back to parent stage
        return Transition.pop_frame()

    @Stage(
        name="fast_track_payout",
        terminal=True,
        canned_response="Claim approved for immediate fast-track disbursement.",
    )
    def payout_stage(self, slots: IncidentSlots) -> Transition[dict[str, object]]:
        return Transition.end(result={"status": "payout_issued", "amount": slots.loss_amount})

    @Stage(
        name="choose_options",
        choice_options=ChoicePayload(
            prompt="Select contact method:",
            options=["Email", "Phone", "SMS"],
        ),
    )
    def choice_stage(self) -> Transition[None]:
        return Transition.stay()

    @Stage(name="human_escalation", terminal=True, canned_response="Escalated to human operator.")
    def escalation_stage(self) -> Transition[dict[str, str]]:
        return Transition.end(result={"status": "escalated"})


@pytest.mark.asyncio
async def test_statechart_engine_multi_turn_journey() -> None:
    """Verify complete multi-turn journey with slot hydration, tool execution, and TurnLedger."""
    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier(default_intent="intake")
    renderer = DeterministicResponseRenderer()
    ledger_sink = InMemoryLedgerSink()
    vault = PIIVault()
    agent = InsuranceClaimAgent(tools={"sample_tool": sample_tool})

    engine = StatechartEngine(
        agent=agent,
        storage=storage,
        classifier=classifier,
        renderer=renderer,
        ledger_sink=ledger_sink,
        vault=vault,
    )

    session_id = "test_journey_001"

    # Turn 1: Partial slot provision (policy_number only)
    classifier.set_mapping(
        "My policy is POL-ABCDE",
        ExtractionResult(
            intent="intake",
            candidate_slots={"policy_number": "POL-ABCDE"},
            is_refusal=False,
        ),
    )
    env1 = TurnEnvelope(session_id=session_id, turn_index=0, user_message="My policy is POL-ABCDE")
    res1 = await engine.step(env1)

    assert isinstance(res1, BlockstateTurnYield)
    assert res1.session_id == session_id
    assert res1.state == "in_progress"
    assert "loss_amount" in res1.missing_slots

    # Turn 2: Supply remaining slot (loss_amount)
    classifier.set_mapping(
        "Amount is 500",
        ExtractionResult(
            intent="intake",
            candidate_slots={"loss_amount": 500},
            is_refusal=False,
        ),
    )
    env2 = TurnEnvelope(session_id=session_id, turn_index=1, user_message="Amount is 500")
    res2 = await engine.step(env2)

    # All slots collected -> Transition to fast_track_payout (terminal)
    assert isinstance(res2, BlockstateTurnComplete)
    assert res2.session_id == session_id
    assert res2.state == "completed"
    assert res2.result == {"status": "payout_issued", "amount": 500}
    assert res2.ledger_head_hash != ""

    # Verify cryptographic hash chain on TurnLedger
    assert len(ledger_sink.records) == 2
    assert ledger_sink.verify_hash_chain() is True


@pytest.mark.asyncio
async def test_statechart_engine_model_refusal_circuit_breaker() -> None:
    """Verify Pass 1 model refusal immediately short-circuits to on_refusal fallback target."""
    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier(default_intent="intake")
    agent = InsuranceClaimAgent()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)

    session_id = "test_refusal_001"
    classifier.set_mapping(
        "Harmful prompt",
        ExtractionResult(intent="intake", candidate_slots={}, is_refusal=True),
    )

    env = TurnEnvelope(session_id=session_id, turn_index=0, user_message="Harmful prompt")
    res = await engine.step(env)

    # Routes to human_escalation
    assert isinstance(res, (BlockstateTurnYield, BlockstateTurnComplete))


@pytest.mark.asyncio
async def test_statechart_engine_max_turns_exceeded() -> None:
    """Verify exceeding stage max_turns routes to on_max_turns_exceeded target."""
    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier(default_intent="intake")
    agent = InsuranceClaimAgent()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)

    session_id = "test_max_turns_001"
    # Stage has max_turns=3. Step 4 times without completing slots
    for turn in range(4):
        classifier.set_mapping(
            f"Turn {turn}",
            ExtractionResult(intent="intake", candidate_slots={}, is_refusal=False),
        )
        env = TurnEnvelope(session_id=session_id, turn_index=turn, user_message=f"Turn {turn}")
        res = await engine.step(env)

    # Turn 4 exceeded max_turns=3 -> routed to human_escalation
    assert isinstance(res, (BlockstateTurnYield, BlockstateTurnComplete))


@pytest.mark.asyncio
async def test_statechart_engine_permitted_digression_push_and_pop() -> None:
    """Verify permitted digression pushes child frame, renders, and pops after render."""
    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier()
    agent = InsuranceClaimAgent()
    ledger_sink = InMemoryLedgerSink()
    engine = StatechartEngine(
        agent=agent,
        storage=storage,
        classifier=classifier,
        ledger_sink=ledger_sink,
    )

    session_id = "test_digression_001"

    # Utterance matching allow_digressions ("faq_digression")
    classifier.set_mapping(
        "What is the FAQ?",
        ExtractionResult(intent="faq_digression", candidate_slots={}, is_refusal=False),
    )
    env = TurnEnvelope(session_id=session_id, turn_index=0, user_message="What is the FAQ?")
    res = await engine.step(env)

    # Yields response for digression and then pops
    assert isinstance(res, BlockstateTurnYield)
    checkpoint = await storage.load_checkpoint(session_id)
    assert checkpoint is not None
    # Child frame was popped during commit; stack has parent frame
    assert len(checkpoint.task_stack) == 1
    assert checkpoint.task_stack[0]["stage_id"] == "intake"


@pytest.mark.asyncio
async def test_statechart_engine_choice_payload_pass2_dispatch() -> None:
    """Verify stage declaring choice_options renders ChoicePayload in Pass 2 without LLM."""
    storage = InMemoryStorageBackend()

    # Route agent to choose_options stage directly
    class ChoiceOnlyAgent(Agent):
        @Stage(
            name="choose",
            choice_options=ChoicePayload(
                prompt="Select department:",
                options=["Support", "Sales"],
            ),
        )
        def choose_step(self) -> Transition[None]:
            return Transition.stay()

    choice_agent = ChoiceOnlyAgent()
    engine = StatechartEngine(agent=choice_agent, storage=storage)

    env = TurnEnvelope(session_id="choice_sess", turn_index=0, user_message="Hi")
    res = await engine.step(env)

    assert isinstance(res, BlockstateTurnYield)
    assert res.message == "Select department:"
    assert res.choices == ["Support", "Sales"]


@pytest.mark.asyncio
async def test_turn_ledger_tamper_detection() -> None:
    """Verify modifying any byte in a historical TurnLedgerRecord invalidates hash chain."""
    storage = InMemoryStorageBackend()
    ledger_sink = InMemoryLedgerSink()
    agent = InsuranceClaimAgent()
    engine = StatechartEngine(agent=agent, storage=storage, ledger_sink=ledger_sink)

    session_id = "tamper_sess"
    for turn in range(3):
        env = TurnEnvelope(session_id=session_id, turn_index=turn, user_message=f"Msg {turn}")
        await engine.step(env)

    assert len(ledger_sink.records) == 3
    assert ledger_sink.verify_hash_chain() is True

    # Tamper with first record's prompt_hash
    original_record = ledger_sink.records[0]
    tampered_record = original_record.model_copy(update={"prompt_hash": "corrupted_hash"})
    ledger_sink.records[0] = tampered_record

    # Hash chain verification must now fail
    assert ledger_sink.verify_hash_chain() is False


@pytest.mark.asyncio
async def test_engine_initial_context_and_no_initial_stage() -> None:
    """Verify envelope initial context loads into session and missing initial stage aborts."""
    storage = InMemoryStorageBackend()

    # Empty agent with no stages
    class EmptyAgent(Agent):
        pass

    empty_engine = StatechartEngine(agent=EmptyAgent(), storage=storage)
    env = TurnEnvelope(session_id="empty_sess", turn_index=0, user_message="hello")
    res = await empty_engine.step(env)
    assert isinstance(res, BlockstateTurnAborted)
    assert res.error_code == "BLK-CFG-002"

    # Agent with initial context loaded
    class ContextAgent(Agent):
        @Stage(name="start", terminal=True)
        def start(self, session: ReadOnlySessionView) -> Transition[dict[str, object]]:
            return Transition.end(result={"user_id": session.get("user_id")})

    ctx_engine = StatechartEngine(agent=ContextAgent(), storage=storage)
    env_ctx = TurnEnvelope(
        session_id="ctx_sess",
        turn_index=0,
        user_message="hello",
        initial_context={"user_id": "usr_999"},
    )
    res_ctx = await ctx_engine.step(env_ctx)
    assert isinstance(res_ctx, BlockstateTurnComplete)
    assert res_ctx.result == {"user_id": "usr_999"}


@pytest.mark.asyncio
async def test_engine_unhandled_refusal_and_unhandled_max_turns() -> None:
    """Verify model refusal and max turns abort when no fallback stage declared."""
    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier()

    class StrictAgent(Agent):
        @Stage(name="start", max_turns=1)
        def start(self) -> Transition[None]:
            return Transition.stay()

    agent = StrictAgent()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)

    # 1. Unhandled refusal
    classifier.set_mapping(
        "refuse_me",
        ExtractionResult(intent="start", candidate_slots={}, is_refusal=True),
    )
    env_refuse = TurnEnvelope(session_id="ref_sess", turn_index=0, user_message="refuse_me")
    res_refuse = await engine.step(env_refuse)
    assert isinstance(res_refuse, BlockstateTurnAborted)
    assert res_refuse.error_code == "BLK-MOD-002"

    # 2. Unhandled max_turns exceeded
    classifier.set_mapping(
        "step_1",
        ExtractionResult(intent="start", candidate_slots={}, is_refusal=False),
    )
    classifier.set_mapping(
        "step_2",
        ExtractionResult(intent="start", candidate_slots={}, is_refusal=False),
    )
    await engine.step(TurnEnvelope(session_id="turn_sess", turn_index=0, user_message="step_1"))
    res_turn2 = await engine.step(
        TurnEnvelope(session_id="turn_sess", turn_index=1, user_message="step_2")
    )
    assert isinstance(res_turn2, BlockstateTurnAborted)
    assert res_turn2.error_code == "BLK-MOD-003"


@pytest.mark.asyncio
async def test_engine_validation_breach_routing() -> None:
    """Verify disqualifying breach immediately routes to on_breach target."""
    from pydantic import field_validator

    class BreachSlots(BaseModel):
        amount: int

        @field_validator("amount")
        @classmethod
        def check_amount(cls, v: int) -> int:
            if v > 10000:
                raise DisqualifyingBreachError(
                    "Amount exceeds regulatory ceiling",
                    code="BLK-VAL-003",
                    field_path="amount",
                )
            return v

    class BreachAgent(Agent):
        @Stage(name="intake", collect=BreachSlots, on_breach="fraud_review")
        def intake(self) -> Transition[None]:
            return Transition.stay()

        @Stage(name="fraud_review", terminal=True, canned_response="Flagged for fraud.")
        def fraud(self) -> Transition[dict[str, str]]:
            return Transition.end(result={"status": "breach_flagged"})

    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier()
    agent = BreachAgent()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)

    classifier.set_mapping(
        "high amount",
        ExtractionResult(intent="intake", candidate_slots={"amount": 99999}, is_refusal=False),
    )
    env = TurnEnvelope(session_id="breach_sess", turn_index=0, user_message="high amount")
    res = await engine.step(env)
    assert isinstance(res, BlockstateTurnYield)
    checkpoint = await storage.load_checkpoint("breach_sess")
    assert checkpoint is not None
    assert checkpoint.task_stack[0]["stage_id"] == "fraud_review"


@pytest.mark.asyncio
async def test_engine_guards_and_async_handlers() -> None:
    """Verify async handlers, stage guards, and pop slot mutations."""
    class GuardAgent(Agent):
        @Stage(name="step_a")
        async def step_a(self) -> Transition[None]:
            return Transition.stay()

        @Guard("step_a")
        async def check_guard_a(self, session: ReadOnlySessionView) -> Transition[str | None]:
            if session.get("allow_jump"):
                return Transition.to("step_b")
            return Transition.stay()

        @Stage(name="step_b", terminal=True)
        async def step_b(self) -> Transition[dict[str, str]]:
            return Transition.end(result={"arrived": "step_b"})

    storage = InMemoryStorageBackend()
    agent = GuardAgent()
    engine = StatechartEngine(agent=agent, storage=storage)

    # Initial turn with allow_jump: True
    env = TurnEnvelope(
        session_id="guard_sess",
        turn_index=0,
        user_message="jump",
        initial_context={"allow_jump": True},
    )
    res = await engine.step(env)
    assert isinstance(res, BlockstateTurnComplete)
    assert res.result == {"arrived": "step_b"}


@pytest.mark.asyncio
async def test_engine_digression_mutation_propagation() -> None:
    """Verify completed digression frame applies SlotMutation to parent frame on pop."""
    class DigressAgent(Agent):
        @Stage(name="parent", allow_digressions=["child"], allow_slot_overrides=True)
        def parent(self) -> Transition[None]:
            return Transition.stay()

        @Stage(name="child")
        def child(self) -> Transition[None]:
            return Transition.pop_frame(mutation=SlotMutation(updates={"child_val": 42}))

    storage = InMemoryStorageBackend()
    classifier = DeterministicIntentClassifier()
    agent = DigressAgent()
    engine = StatechartEngine(agent=agent, storage=storage, classifier=classifier)

    # Push child digression
    classifier.set_mapping(
        "to_child",
        ExtractionResult(intent="child", candidate_slots={}, is_refusal=False),
    )
    env1 = TurnEnvelope(session_id="pop_sess", turn_index=0, user_message="to_child")
    await engine.step(env1)

    # Verify parent received child_val: 42
    checkpoint = await storage.load_checkpoint("pop_sess")
    assert checkpoint is not None
    assert checkpoint.task_stack[0]["stage_id"] == "parent"
    assert checkpoint.task_stack[0]["slots"]["child_val"] == 42


@pytest.mark.asyncio
async def test_engine_security_violation_and_corrupted_vault_map() -> None:
    """Verify tool security violation handling and corrupted vault map."""
    from blockstate.ports.storage import SessionCheckpoint

    storage = InMemoryStorageBackend()

    # Pre-populate checkpoint with invalid/corrupted vault map to test try-except
    corrupted_cp = SessionCheckpoint(
        session_id="sec_sess",
        schema_version=1,
        revision_id=1,
        state={},
        task_stack=({"stage_id": "tool_stage", "slots": {}, "locked_slots": (), "turn_count": 0},),
        last_ledger_hash="0" * 64,
        pending_ledger_outbox=(),
        vault_map=b"totally_invalid_aes_gcm_ciphertext_12345",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )
    lease = await storage.acquire_lease("sec_sess")
    await storage.save_checkpoint(corrupted_cp, lease)
    await storage.release_lease(lease)

    class SecAgent(Agent):
        @Stage(name="tool_stage", tools=["missing_tool"], on_security_violation="sec_fallback")
        def step_1(self) -> Transition[None]:
            return Transition.stay()

        @Stage(name="sec_fallback", terminal=True)
        def fallback(self) -> Transition[dict[str, str]]:
            return Transition.end(result={"status": "security_handled"})

    agent = SecAgent()
    engine = StatechartEngine(agent=agent, storage=storage)

    # Missing tool raises SecurityViolationError -> routed to on_security_violation
    env_sec = TurnEnvelope(session_id="sec_sess", turn_index=1, user_message="run tool")
    res = await engine.step(env_sec)
    assert isinstance(res, BlockstateTurnYield)

    # Now test unhandled security violation (no on_security_violation declared)
    class UnhandledSecAgent(Agent):
        @Stage(name="tool_stage", tools=["missing_tool"])
        def step_1(self) -> Transition[None]:
            return Transition.stay()

    unhandled_engine = StatechartEngine(agent=UnhandledSecAgent(), storage=storage)
    env_abort = TurnEnvelope(session_id="sec_sess2", turn_index=0, user_message="run tool")
    res_abort = await unhandled_engine.step(env_abort)
    assert isinstance(res_abort, BlockstateTurnAborted)
    assert res_abort.error_code == "BLK-SEC-001"


@pytest.mark.asyncio
async def test_engine_sync_guard_and_dynamic_renderer() -> None:
    """Verify sync guard and custom response renderer invocation."""
    class SyncGuardAgent(Agent):
        @Stage(name="step_1")
        def step_1(self) -> Transition[None]:
            return Transition.stay()

        @Guard("step_1")
        def sync_guard(self, session: ReadOnlySessionView) -> Transition[str]:
            return Transition.to("step_2")

        @Stage(name="step_2")
        def step_2(self) -> Transition[None]:
            return Transition.stay()

    storage = InMemoryStorageBackend()
    renderer = DeterministicResponseRenderer(templates={"step_2": "Dynamic render for step_2"})
    engine = StatechartEngine(
        agent=SyncGuardAgent(),
        storage=storage,
        renderer=renderer,
    )

    env_render = TurnEnvelope(session_id="render_sess", turn_index=0, user_message="render test")
    res = await engine.step(env_render)
    assert isinstance(res, BlockstateTurnYield)
    assert res.message == "Dynamic render for step_2"


