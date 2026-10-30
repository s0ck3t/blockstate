"""Unit tests and contract suites for Pass 1 and Pass 2 model adapters.

Verifies:
- IntentClassifierContractSuite and ResponseRendererContractSuite adherence.
- ONNXIntentClassifier sub-100ms Pass 1 extraction and thread offloading (p95 <= 50ms).
- PydanticAIAdapter Pass 1 extraction and Pass 2 stage-scoped tool whitelisting.
- LiteLLMAdapter Pass 1 extraction, refusal circuit breakers, and Pass 2 tool scoping.
- Defensive optional dependency imports and error taxonomy (BLK-MOD-001, BLK-MOD-003).
"""

import asyncio
import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockstate.adapters.models import (
    LiteLLMAdapter,
    ONNXIntentClassifier,
    PydanticAIAdapter,
)
from blockstate.adapters.models.litellm import _callable_to_tool_schema
from blockstate.adapters.models.pydantic_ai import ExtractionPayload
from blockstate.errors import ModelError, Pass1TimeoutError
from blockstate.testing.contracts import (
    IntentClassifierContractSuite,
    ResponseRendererContractSuite,
)

# =============================================================================
# Contract Test Suite Implementations
# =============================================================================


class TestONNXIntentClassifierContract(IntentClassifierContractSuite):
    """Verify ONNXIntentClassifier against IntentClassifierContractSuite."""

    __test__ = True

    def create_classifier(self) -> ONNXIntentClassifier:
        return ONNXIntentClassifier(
            intent_keywords={
                "check_balance": ["balance", "funds"],
                "transfer_funds": ["transfer", "send"],
            },
            slot_keywords={
                "account_number": ["account", "acc"],
            },
        )


class TestPydanticAIIntentClassifierContract(IntentClassifierContractSuite):
    """Verify PydanticAIAdapter against IntentClassifierContractSuite."""

    __test__ = True

    def create_classifier(self) -> PydanticAIAdapter:
        def dynamic_mock(utterance: str) -> str:
            if "Patagonia" in utterance or "unknown" in utterance:
                return json.dumps({"intent": "unmapped", "candidate_slots": {}})
            if "bypass security" in utterance:
                return json.dumps({"is_refusal": True})
            return json.dumps(
                {
                    "intent": "check_balance",
                    "candidate_slots": {"account_number": "ACC123"},
                    "confidence": 0.95,
                }
            )

        return PydanticAIAdapter(
            intent_keywords={"check_balance": ["balance"]},
            mock_response=dynamic_mock,
        )


class TestPydanticAIResponseRendererContract(ResponseRendererContractSuite):
    """Verify PydanticAIAdapter against ResponseRendererContractSuite."""

    __test__ = True

    def create_renderer(self) -> PydanticAIAdapter:
        def balance_check(account_id: str) -> str:
            """Check account balance."""
            return "Balance: £500"

        def dangerous_tool(cmd: str) -> str:
            """Unwhitelisted dangerous tool."""
            return "Hacked"

        return PydanticAIAdapter(
            tools={"balance_check": balance_check, "dangerous_tool": dangerous_tool},
            mock_response="Your balance is £500.",
        )


class TestLiteLLMIntentClassifierContract(IntentClassifierContractSuite):
    """Verify LiteLLMAdapter against IntentClassifierContractSuite."""

    __test__ = True

    def create_classifier(self) -> LiteLLMAdapter:
        def dynamic_mock(utterance: str) -> str:
            if "Patagonia" in utterance or "unknown" in utterance:
                return json.dumps({"intent": "unmapped", "candidate_slots": {}})
            if "bypass security" in utterance:
                return json.dumps({"is_refusal": True})
            return json.dumps(
                {
                    "intent": "check_balance",
                    "candidate_slots": {"account_number": "ACC123"},
                    "confidence": 0.95,
                }
            )

        return LiteLLMAdapter(
            model="gpt-4o-mini",
            mock_response=dynamic_mock,
        )


class TestLiteLLMResponseRendererContract(ResponseRendererContractSuite):
    """Verify LiteLLMAdapter against ResponseRendererContractSuite."""

    __test__ = True

    def create_renderer(self) -> LiteLLMAdapter:
        def balance_check(account_id: str) -> str:
            """Check account balance."""
            return "Balance: £500"

        def dangerous_tool(cmd: str) -> str:
            """Unwhitelisted dangerous tool."""
            return "Hacked"

        return LiteLLMAdapter(
            model="gpt-4o-mini",
            mock_response="Your balance is £500.",
            tools={"balance_check": balance_check, "dangerous_tool": dangerous_tool},
        )


# =============================================================================
# ONNXIntentClassifier Unit Tests
# =============================================================================


@pytest.mark.asyncio
async def test_onnx_thread_offloading_asyncio_to_thread() -> None:
    """Verify CPU-bound inference is offloaded to worker threads via asyncio.to_thread."""
    classifier = ONNXIntentClassifier(
        intent_keywords={"greeting": ["hello", "hi"]},
    )
    with patch("asyncio.to_thread", wraps=asyncio.to_thread) as mock_to_thread:
        res = await classifier.extract("Hello world", {})
        assert res.intent == "greeting"
        assert mock_to_thread.called


@pytest.mark.asyncio
async def test_onnx_p95_latency_sub_50ms() -> None:
    """Verify local System-1 classification achieves sub-50ms p95 latency SLA."""
    classifier = ONNXIntentClassifier(
        intent_keywords={
            "check_balance": ["balance"],
            "transfer": ["transfer"],
        },
        slot_keywords={"account": ["acc", "account"]},
    )
    schema = {"properties": {"account": {"type": "string"}}}

    latencies: list[float] = []
    for _ in range(30):
        res = await classifier.extract("Check my balance for account ACC999", schema)
        latencies.append(res.latency_ms)

    latencies.sort()
    p95_index = int(len(latencies) * 0.95)
    p95_latency = latencies[p95_index]
    assert p95_latency <= 50.0, f"p95 latency was {p95_latency}ms, exceeding 50ms"


@pytest.mark.asyncio
async def test_onnx_fail_closed_unmapped_utterance() -> None:
    """Verify unmapped or out-of-domain utterances fail closed with empty candidate slots."""
    classifier = ONNXIntentClassifier(
        intent_keywords={"check_balance": ["balance"]},
        confidence_threshold=0.7,
    )
    schema = {"properties": {"account": {"type": "string"}}}

    # Out-of-domain text
    res = await classifier.extract("What is the recipe for chocolate cake?", schema)
    assert res.intent == "unmapped"
    assert res.candidate_slots == {}
    assert res.confidence == 0.0
    assert not res.is_refusal


@pytest.mark.asyncio
async def test_onnx_empty_or_whitespace_fails_closed() -> None:
    """Verify empty or pure whitespace utterances fail closed immediately."""
    classifier = ONNXIntentClassifier()
    res = await classifier.extract("   \n\t  ", {})
    assert res.intent == "unmapped"
    assert res.candidate_slots == {}
    assert res.confidence == 0.0


@pytest.mark.asyncio
async def test_onnx_slot_extraction_types_and_patterns() -> None:
    """Verify slot extraction across integers, numbers, dates, accounts, and custom patterns."""
    classifier = ONNXIntentClassifier(
        intent_keywords={"update_details": ["update"]},
        slot_patterns={"custom_code": r"\bCODE-([0-9]{4})\b"},
    )
    schema = {
        "properties": {
            "account_number": {"type": "string"},
            "birth_date": {"type": "string"},
            "amount": {"type": "number"},
            "count": {"type": "integer"},
            "custom_code": {"type": "string"},
        }
    }
    utterance = (
        "Please update account ACC12345 with date 1995-12-31, amount 250.50, count 3, CODE-7890"
    )
    res = await classifier.extract(utterance, schema)

    assert res.intent == "update_details"
    assert res.candidate_slots["account_number"] == "ACC12345"
    assert res.candidate_slots["birth_date"] == "1995-12-31"
    assert res.candidate_slots["amount"] == 250.5
    assert res.candidate_slots["count"] == 3
    assert res.candidate_slots["custom_code"] == "7890"


@pytest.mark.asyncio
async def test_onnx_refusal_circuit_breaker() -> None:
    """Verify utterances matching safety refusal patterns set is_refusal=True."""
    classifier = ONNXIntentClassifier(
        refusal_patterns=["my custom exploit keyword"],
    )
    res = await classifier.extract("I want to run my custom exploit keyword now", {})
    assert res.is_refusal is True
    assert res.intent == "refusal"
    assert res.candidate_slots == {}


@pytest.mark.asyncio
async def test_onnx_timeout_budget_enforcement() -> None:
    """Verify Pass1TimeoutError (BLK-MOD-003) is raised when timeout budget is breached."""
    classifier = ONNXIntentClassifier()
    with pytest.raises(Pass1TimeoutError) as exc_info:
        await classifier.extract("Hello", {}, timeout_ms=0)
    assert exc_info.value.code == "BLK-MOD-003"


@pytest.mark.asyncio
async def test_onnx_session_inference_with_mock_session() -> None:
    """Verify ONNX runtime session execution, tensor preparation, softmax, and argmax."""
    import numpy as np

    mock_input = MagicMock()
    mock_input.name = "input_ids"

    mock_session = MagicMock()
    mock_session.get_inputs.return_value = [mock_input]
    # Return logits for 3 classes: [0.1, 2.5, 0.2] -> argmax 1
    mock_session.run.return_value = [np.array([[0.1, 2.5, 0.2]], dtype=np.float32)]

    classifier = ONNXIntentClassifier(
        session=mock_session,
        intent_labels=["balance", "transfer", "logout"],
    )
    res = await classifier.extract("Transfer £100", {})
    assert res.intent == "transfer"
    assert res.confidence > 0.8
    assert mock_session.run.called


@pytest.mark.asyncio
async def test_onnx_session_inference_error_fallback() -> None:
    """Verify session execution errors fail closed gracefully to unmapped."""
    mock_session = MagicMock()
    mock_session.get_inputs.side_effect = RuntimeError("Inference runtime corrupted")

    classifier = ONNXIntentClassifier(session=mock_session)
    res = await classifier.extract("Some random utterance", {})
    assert res.intent == "unmapped"
    assert res.candidate_slots == {}


def test_onnx_missing_dependency_import_error() -> None:
    """Verify informative ImportError is raised when onnxruntime is absent and required."""
    with (
        patch("blockstate.adapters.models.onnx_classifier.ort", None),
        pytest.raises(ImportError, match="pip install blockstate\\[onnx\\]"),
    ):
        ONNXIntentClassifier(require_onnx=True)

    with (
        patch("blockstate.adapters.models.onnx_classifier.ort", None),
        pytest.raises(ImportError, match="pip install blockstate\\[onnx\\]"),
    ):
        ONNXIntentClassifier(model_path="nonexistent_model.onnx")


# =============================================================================
# PydanticAIAdapter Unit Tests
# =============================================================================


@pytest.mark.asyncio
async def test_pydantic_ai_pass1_structured_extraction() -> None:
    """Verify PydanticAIAdapter Pass 1 extraction parsing structured JSON."""
    adapter = PydanticAIAdapter(
        mock_response=json.dumps(
            {
                "intent": "confirm_details",
                "candidate_slots": {"account_id": "ACC999", "hallucinated_slot": "bad"},
                "confidence": 0.99,
            }
        )
    )
    schema = {"properties": {"account_id": {"type": "string"}}}
    res = await adapter.extract("Confirm account ACC999", schema)

    assert res.intent == "confirm_details"
    assert res.candidate_slots == {"account_id": "ACC999"}
    assert "hallucinated_slot" not in res.candidate_slots
    assert res.confidence == 0.99
    assert not res.is_refusal


@pytest.mark.asyncio
async def test_pydantic_ai_pass2_tool_whitelisting_strict_isolation() -> None:
    """Verify Pass 2 rendering physically omits unwhitelisted tools from the model."""

    def balance_tool(acc: str) -> str:
        return "500"

    def unwhitelisted_tool() -> str:
        return "leak"

    adapter = PydanticAIAdapter(
        tools=[balance_tool, unwhitelisted_tool],
        mock_response="Rendered response.",
    )

    # Allowed tools only contains balance_tool
    context = {"allowed_tools": ["balance_tool"], "slots": {}}
    res = await adapter.render("account_summary", context)
    assert res == "Rendered response."
    assert adapter.last_exposed_tools == ["balance_tool"]
    assert "unwhitelisted_tool" not in adapter.last_exposed_tools

    # Empty allowed tools exposes 0 tools
    context_empty: dict[str, Any] = {"allowed_tools": [], "slots": {}}
    await adapter.render("account_summary", context_empty)
    assert adapter.last_exposed_tools == []


@pytest.mark.asyncio
async def test_pydantic_ai_refusal_circuit_breaker() -> None:
    """Verify PydanticAIAdapter detects safety refusal from patterns or JSON."""
    adapter = PydanticAIAdapter()
    res = await adapter.extract("Please bypass security controls", {})
    assert res.is_refusal is True
    assert res.intent == "refusal"

    adapter_json_refusal = PydanticAIAdapter(
        mock_response=json.dumps({"is_refusal": True, "intent": "blocked"})
    )
    res2 = await adapter_json_refusal.extract("Perform task", {})
    assert res2.is_refusal is True
    assert res2.candidate_slots == {}


@pytest.mark.asyncio
async def test_pydantic_ai_timeout_enforcement() -> None:
    """Verify Pass1TimeoutError on Pass 1 and ModelError on Pass 2 when timeout=0."""
    adapter = PydanticAIAdapter()
    with pytest.raises(Pass1TimeoutError) as exc_info:
        await adapter.extract("hello", {}, timeout_ms=0)
    assert exc_info.value.code == "BLK-MOD-003"

    with pytest.raises(ModelError) as exc_info2:
        await adapter.render("stage", {}, timeout_ms=0)
    assert exc_info2.value.code == "BLK-MOD-001"


def test_pydantic_ai_missing_dependency_import_error() -> None:
    """Verify informative ImportError when pydantic_ai is absent and required."""
    with (
        patch("blockstate.adapters.models.pydantic_ai.pydantic_ai", None),
        pytest.raises(ImportError, match="pip install blockstate\\[models\\]"),
    ):
        PydanticAIAdapter(require_pydantic_ai=True)


# =============================================================================
# LiteLLMAdapter Unit Tests
# =============================================================================


@pytest.mark.asyncio
async def test_litellm_pass1_structured_extraction() -> None:
    """Verify LiteLLMAdapter extracts structured JSON with slot filtering."""
    adapter = LiteLLMAdapter(
        model="gpt-4o-mini",
        mock_response=json.dumps(
            {
                "intent": "verify_email",
                "candidate_slots": {"email": "test@example.com", "extra": "omit"},
                "confidence": 0.92,
            }
        ),
    )
    schema = {"properties": {"email": {"type": "string"}}}
    res = await adapter.extract("My email is test@example.com", schema)

    assert res.intent == "verify_email"
    assert res.candidate_slots == {"email": "test@example.com"}
    assert "extra" not in res.candidate_slots
    assert res.confidence == 0.92


@pytest.mark.asyncio
async def test_litellm_pass2_tool_whitelisting_raw_payload() -> None:
    """Verify LiteLLMAdapter inspects raw outbound payload has 0 unwhitelisted tools."""

    def check_balance(account_id: str) -> str:
        """Check balance."""
        return "£100"

    def transfer_money(amount: float) -> str:
        """Transfer money."""
        return "OK"

    adapter = LiteLLMAdapter(
        model="gpt-4o-mini",
        tools={"check_balance": check_balance, "transfer_money": transfer_money},
        mock_response="Here is your balance.",
    )

    # 1. Allowed tools only contains check_balance
    context = {"allowed_tools": ["check_balance"], "slots": {}}
    await adapter.render("view_balance", context)

    assert adapter.last_exposed_tools == ["check_balance"]
    assert "transfer_money" not in adapter.last_exposed_tools

    # Inspect raw outbound payload
    outbound_tools = adapter.last_outbound_payload.get("tools")
    assert outbound_tools is not None
    assert len(outbound_tools) == 1
    assert outbound_tools[0]["function"]["name"] == "check_balance"

    # 2. Empty allowed tools -> tools is None
    context_empty: dict[str, Any] = {"allowed_tools": [], "slots": {}}
    await adapter.render("view_balance", context_empty)
    assert adapter.last_exposed_tools == []
    assert adapter.last_outbound_payload.get("tools") is None


@pytest.mark.asyncio
async def test_litellm_refusal_content_filter_and_exception() -> None:
    """Verify finish_reason='content_filter' and safety exceptions set is_refusal=True."""
    adapter = LiteLLMAdapter(refusal_patterns=["harmful payload"])
    res = await adapter.extract("This is a harmful payload", {})
    assert res.is_refusal is True

    # Mock litellm returning finish_reason="content_filter"
    mock_resp = MagicMock()
    mock_choice = MagicMock()
    mock_choice.finish_reason = "content_filter"
    mock_choice.message.refusal = None
    mock_resp.choices = [mock_choice]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_resp)):
        adapter2 = LiteLLMAdapter()
        res2 = await adapter2.extract("Some boundary prompt", {})
        assert res2.is_refusal is True


@pytest.mark.asyncio
async def test_litellm_timeout_enforcement() -> None:
    """Verify Pass1TimeoutError on Pass 1 and ModelError on Pass 2 when timeout=0."""
    adapter = LiteLLMAdapter()
    with pytest.raises(Pass1TimeoutError) as exc_info:
        await adapter.extract("hello", {}, timeout_ms=0)
    assert exc_info.value.code == "BLK-MOD-003"

    with pytest.raises(ModelError) as exc_info2:
        await adapter.render("stage", {}, timeout_ms=0)
    assert exc_info2.value.code == "BLK-MOD-001"


def test_litellm_missing_dependency_import_error() -> None:
    """Verify informative ImportError when litellm is absent and required."""
    with (
        patch("blockstate.adapters.models.litellm.litellm", None),
        pytest.raises(ImportError, match="pip install blockstate\\[litellm\\]"),
    ):
        LiteLLMAdapter(require_litellm=True)


def test_callable_to_tool_schema_conversion() -> None:
    """Verify automatic generation of OpenAI-compatible schemas from Python functions."""

    def sample_func(name: str, count: int, ratio: float, active: bool, items: list[str]) -> str:
        """Sample documentation string."""
        return "ok"

    schema = _callable_to_tool_schema("sample_func", sample_func)
    fn_def = schema["function"]
    assert fn_def["name"] == "sample_func"
    assert fn_def["description"] == "Sample documentation string."
    props = fn_def["parameters"]["properties"]
    assert props["name"]["type"] == "string"
    assert props["count"]["type"] == "integer"
    assert props["ratio"]["type"] == "number"
    assert props["active"]["type"] == "boolean"
    assert props["items"]["type"] == "array"
    assert set(fn_def["parameters"]["required"]) == {"name", "count", "ratio", "active", "items"}


def test_models_package_exports() -> None:
    """Verify public exports from blockstate.adapters.models."""
    import blockstate.adapters.models as models_pkg

    assert hasattr(models_pkg, "ONNXIntentClassifier")
    assert hasattr(models_pkg, "PydanticAIAdapter")
    assert hasattr(models_pkg, "LiteLLMAdapter")
    assert "ONNXIntentClassifier" in models_pkg.__all__
    assert "PydanticAIAdapter" in models_pkg.__all__
    assert "LiteLLMAdapter" in models_pkg.__all__


# =============================================================================
# Additional Coverage Tests for Edge Cases & Branch Verification
# =============================================================================


@pytest.mark.asyncio
async def test_onnx_extended_branches() -> None:
    """Verify ONNXIntentClassifier slot keywords, standalone numbers, and custom tokeniser."""
    import numpy as np

    mock_session = MagicMock()
    mock_input = MagicMock()
    mock_input.name = "tokens"
    mock_session.get_inputs.return_value = [mock_input]
    mock_session.run.return_value = [np.array([[2.0, 0.1]], dtype=np.float32)]

    tokeniser_called = False

    def custom_tokeniser(text: str) -> np.ndarray:
        nonlocal tokeniser_called
        tokeniser_called = True
        return np.array([[1.0, 2.0]], dtype=np.float32)

    with patch("blockstate.adapters.models.onnx_classifier.ort") as mock_ort:
        mock_ort.InferenceSession.return_value = mock_session
        classifier = ONNXIntentClassifier(
            model_path="test_model.onnx",
            tokeniser=custom_tokeniser,
            intent_labels={0: "lookup", 1: "other"},
            slot_keywords={"account_number": ["account", "acc"]},
        )
        assert mock_ort.InferenceSession.called

    schema = {
        "properties": {
            "account_number": {"type": "string"},
            "amount": {"type": "integer"},
            "status": {"type": "string"},
        }
    }
    # Utterance matching slot keyword "account: ACC999", standalone number, and generic status
    res = await classifier.extract("lookup account: ACC999 amount 50 status is active", schema)
    assert tokeniser_called is True
    assert res.intent == "lookup"
    assert res.candidate_slots.get("account_number") == "ACC999"
    assert res.candidate_slots.get("amount") == 50
    assert res.candidate_slots.get("status") == "active"


@pytest.mark.asyncio
async def test_pydantic_ai_agent_run_and_branches() -> None:
    """Verify PydanticAIAdapter agent execution, slot heuristics, and render fallbacks."""
    from pydantic_ai.models.test import TestModel

    # 1. Extraction with TestModel returning structured JSON
    success_json = json.dumps(
        {
            "intent": "verify_identity",
            "candidate_slots": {"user_id": "USR-101"},
            "confidence": 0.98,
        }
    )
    adapter1 = PydanticAIAdapter(model=TestModel(custom_output_text=success_json))
    schema = {"properties": {"user_id": {"type": "string"}}}
    res1 = await adapter1.extract("My id is USR-101", schema, timeout_ms=2000)
    assert res1.intent == "verify_identity"
    assert res1.candidate_slots == {"user_id": "USR-101"}
    assert res1.confidence == 0.98

    # 2. TestModel returning refusal in JSON
    refusal_json = json.dumps({"is_refusal": True})
    adapter2 = PydanticAIAdapter(model=TestModel(custom_output_text=refusal_json))
    res2 = await adapter2.extract("Do something bad", {}, timeout_ms=2000)
    assert res2.is_refusal is True

    # 3. TestModel returning low confidence
    low_conf_json = json.dumps({"intent": "query", "confidence": 0.1})
    adapter3 = PydanticAIAdapter(model=TestModel(custom_output_text=low_conf_json))
    res3 = await adapter3.extract("ambiguous text", {}, timeout_ms=2000)
    assert res3.intent == "unmapped"
    assert res3.candidate_slots == {}

    # 4. Intent keywords with heuristic slot extraction (dates, accounts, numbers, generics)
    adapter4 = PydanticAIAdapter(
        intent_keywords={"claim": ["claim"]},
        tools={"tool_a": lambda x: x},
    )
    multi_schema = {
        "properties": {
            "account": {"type": "string"},
            "incident_date": {"type": "string"},
            "damage_cost": {"type": "number"},
            "item_name": {"type": "string"},
        }
    }
    utterance = "claim account ACC888 date 2026-05-12 damage_cost: 1500.75 item_name is Laptop"
    res4 = await adapter4.extract(utterance, multi_schema, timeout_ms=2000)
    assert res4.intent == "claim"
    assert res4.candidate_slots["account"] == "ACC888"
    assert res4.candidate_slots["incident_date"] == "2026-05-12"
    assert res4.candidate_slots["damage_cost"] == 1500.75
    assert res4.candidate_slots["item_name"] == "Laptop"

    # 5. Render execution via Agent.run
    adapter5 = PydanticAIAdapter(
        model=TestModel(custom_output_text="Agent rendered summary."),
        tools={"dummy": lambda: "ok"},
    )
    rendered = await adapter5.render("stage_final", {"allowed_tools": ["dummy"], "slots": {}})
    assert rendered == "Agent rendered summary."

    # 6. Render fallback without model
    adapter6 = PydanticAIAdapter(mock_response=None)
    adapter6._model = None
    fallback_msg = await adapter6.render(
        "stage_slots",
        {"slots": {"balance": 200}},
    )
    assert "Response for stage 'stage_slots' with slots: balance=200." in fallback_msg


@pytest.mark.asyncio
async def test_litellm_extended_branches() -> None:
    """Verify LiteLLMAdapter callable schemas, tool configuration options, and acompletion calls."""

    # 1. _callable_to_tool_schema parameters: context, default, dict, float, bool
    def full_tool(
        context: Any,
        data: dict[str, Any],
        flag: bool = True,
        opt: str = "default_opt",
    ) -> str:
        """Full documentation."""
        return "ok"

    schema = _callable_to_tool_schema("full_tool", full_tool)
    props = schema["function"]["parameters"]["properties"]
    assert "context" not in props
    assert props["data"]["type"] == "object"
    assert props["flag"]["type"] == "boolean"
    assert "data" in schema["function"]["parameters"]["required"]
    assert "flag" not in schema["function"]["parameters"]["required"]
    assert "opt" not in schema["function"]["parameters"]["required"]

    # 2. Tool configuration variants: tool_schemas list & mapping, tools list & mapping
    adapter_cfg = LiteLLMAdapter(
        model="gpt-4o",
        api_key="sk-test-key",
        base_url="https://api.example.com",
        tool_schemas=[
            {"name": "tool_list_item"},
            {"function": {"name": "tool_list_func"}},
        ],
        tools={"my_fn": lambda x: x},
    )
    assert "tool_list_item" in adapter_cfg._tool_schemas
    assert "tool_list_func" in adapter_cfg._tool_schemas
    assert "my_fn" in adapter_cfg._tool_schemas

    adapter_cfg2 = LiteLLMAdapter(
        tool_schemas={"tool_dict_key": {"function": {"name": "tool_dict_val"}}},
        tools=[lambda: None],
    )
    assert "tool_dict_val" in adapter_cfg2._tool_schemas

    # 3. Direct litellm.acompletion invocation via patch
    mock_resp_refusal = MagicMock()
    mock_choice_refusal = MagicMock()
    mock_choice_refusal.finish_reason = "stop"
    mock_choice_refusal.message.refusal = None
    mock_choice_refusal.message.content = json.dumps({"is_refusal": True})
    mock_resp_refusal.choices = [mock_choice_refusal]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_resp_refusal)):
        adapter = LiteLLMAdapter(force_litellm_call=True)
        res = await adapter.extract("Any query", {}, timeout_ms=2000)
        assert res.is_refusal is True

    # 4. Low confidence and unmapped from litellm.acompletion
    mock_resp_low = MagicMock()
    mock_choice_low = MagicMock()
    mock_choice_low.finish_reason = "stop"
    mock_choice_low.message.refusal = None
    mock_choice_low.message.content = json.dumps({"intent": "query", "confidence": 0.1})
    mock_resp_low.choices = [mock_choice_low]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_resp_low)):
        adapter_low = LiteLLMAdapter(force_litellm_call=True)
        res_low = await adapter_low.extract("Any query", {}, timeout_ms=2000)
        assert res_low.intent == "unmapped"

    # 5. Invalid JSON fallback to heuristic slot match
    mock_resp_invalid = MagicMock()
    mock_choice_invalid = MagicMock()
    mock_choice_invalid.finish_reason = "stop"
    mock_choice_invalid.message.refusal = None
    mock_choice_invalid.message.content = "Not JSON text at all"
    mock_resp_invalid.choices = [mock_choice_invalid]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_resp_invalid)):
        adapter_invalid = LiteLLMAdapter(force_litellm_call=True)
        schema_acc = {"properties": {"account": {"type": "string"}}}
        res_heur = await adapter_invalid.extract("My account ACC777", schema_acc, timeout_ms=2000)
        assert res_heur.candidate_slots.get("account") == "ACC777"

    # 6. Safety exception from litellm.acompletion
    with patch("litellm.acompletion", AsyncMock(side_effect=Exception("content_filter triggered"))):
        adapter_exc = LiteLLMAdapter(force_litellm_call=True)
        res_exc = await adapter_exc.extract("Dangerous input", {}, timeout_ms=2000)
        assert res_exc.is_refusal is True

    # 7. Render with litellm.acompletion success and exception fallback
    mock_resp_render = MagicMock()
    mock_choice_render = MagicMock()
    mock_choice_render.message.content = "Rendered from mock API"
    mock_resp_render.choices = [mock_choice_render]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_resp_render)):
        adapter_render = LiteLLMAdapter(force_litellm_call=True)
        out1 = await adapter_render.render("stage_a", {}, timeout_ms=2000)
        assert out1 == "Rendered from mock API"

    with patch("litellm.acompletion", AsyncMock(side_effect=RuntimeError("API down"))):
        adapter_fail = LiteLLMAdapter(force_litellm_call=True)
        out2 = await adapter_fail.render("stage_b", {"slots": {"amount": 99}}, timeout_ms=2000)
        assert "Response for stage 'stage_b' with slots: amount=99." in out2


@pytest.mark.asyncio
async def test_pydantic_ai_extraction_payload_branches() -> None:
    """Verify PydanticAIAdapter with ExtractionPayload instances and malformed JSON."""
    adapter = PydanticAIAdapter(system_prompt="Custom extraction system prompt")

    # 1. ExtractionPayload success
    mock_run_res = MagicMock()
    mock_run_res.output = ExtractionPayload(
        intent="pay_invoice",
        candidate_slots={"invoice_id": "INV-100", "hallucination": "omit"},
        confidence=0.99,
        is_refusal=False,
    )
    with patch("pydantic_ai.Agent.run", AsyncMock(return_value=mock_run_res)):
        schema = {"properties": {"invoice_id": {"type": "string"}}}
        res = await adapter.extract("Pay invoice INV-100", schema, timeout_ms=2000)
        assert res.intent == "pay_invoice"
        assert res.candidate_slots == {"invoice_id": "INV-100"}

    # 2. ExtractionPayload refusal
    mock_run_res_refusal = MagicMock()
    mock_run_res_refusal.output = ExtractionPayload(
        intent="refusal",
        candidate_slots={},
        confidence=1.0,
        is_refusal=True,
    )
    with patch("pydantic_ai.Agent.run", AsyncMock(return_value=mock_run_res_refusal)):
        res2 = await adapter.extract("Dangerous action", {}, timeout_ms=2000)
        assert res2.is_refusal is True

    # 3. ExtractionPayload unmapped / low confidence
    mock_run_res_unmapped = MagicMock()
    mock_run_res_unmapped.output = ExtractionPayload(
        intent="unmapped",
        candidate_slots={},
        confidence=0.1,
        is_refusal=False,
    )
    with patch("pydantic_ai.Agent.run", AsyncMock(return_value=mock_run_res_unmapped)):
        res3 = await adapter.extract("What is the meaning of life?", {}, timeout_ms=2000)
        assert res3.intent == "unmapped"

    # 4. Malformed JSON string falling through
    adapter_malformed = PydanticAIAdapter(mock_response="{invalid json: not parsed}")
    res4 = await adapter_malformed.extract("random query", {}, timeout_ms=2000)
    assert res4.intent == "unmapped"

    # 5. Empty delta_schema in heuristic slot matching
    assert adapter._extract_slots_heuristic("utterance", {}) == {}

    # 6. Render with system prompt and callable mock
    adapter_render_callable = PydanticAIAdapter(mock_response=lambda s: f"Rendered stage {s}")
    render_out = await adapter_render_callable.render("checkout", {})
    assert render_out == "Rendered stage checkout"


@pytest.mark.asyncio
async def test_litellm_mock_and_heuristic_coverage() -> None:
    """Verify LiteLLMAdapter render mock variants and heuristic slot extraction."""
    # 1. Render with callable and string mock_response
    adapter_call = LiteLLMAdapter(mock_response=lambda s: f"Stage {s}")
    assert await adapter_call.render("stage1", {}) == "Stage stage1"

    adapter_str = LiteLLMAdapter(mock_response="Static stage output")
    assert await adapter_str.render("stage2", {}) == "Static stage output"

    # 2. _heuristic_slot_match directly with dates, accounts, numbers, and generics
    adapter_heur = LiteLLMAdapter()
    assert adapter_heur._heuristic_slot_match("text", {}) == {}

    schema = {
        "properties": {
            "account": {"type": "string"},
            "expiry": {"type": "string"},
            "amount": {"type": "number"},
            "tag": {"type": "string"},
        }
    }
    match = adapter_heur._heuristic_slot_match(
        "Account ACC12345 expiry 2028-10-31 amount: 99.5 tag is premium",
        schema,
    )
    assert match["account"] == "ACC12345"
    assert match["expiry"] == "2028-10-31"
    assert match["amount"] == 99.5
    assert match["tag"] == "premium"


@pytest.mark.asyncio
async def test_onnx_heuristic_standalone_numbers_and_labels() -> None:
    """Verify ONNXIntentClassifier standalone numbers for id, age, count, and empty schema."""
    classifier = ONNXIntentClassifier(
        intent_keywords={"register": ["register"]},
        intent_labels=["reg", "query"],
    )
    assert classifier._extract_slots("utterance", {}) == {}

    schema = {
        "properties": {
            "id": {"type": "integer"},
            "age": {"type": "integer"},
            "count": {"type": "integer"},
        }
    }
    # Utterance with standalone numbers
    res = await classifier.extract("register id 1042 age 28 count 5", schema)
    assert res.intent == "register"
    assert res.candidate_slots["id"] == 1042
    assert res.candidate_slots["age"] == 28
    assert res.candidate_slots["count"] == 5


@pytest.mark.asyncio
async def test_empty_utterance_and_timeout_branches() -> None:
    """Verify empty utterances, timeout handlers, and slotless render fallbacks."""
    # 1. Empty utterances for PydanticAI and LiteLLM
    pydantic_adapter = PydanticAIAdapter()
    res_pai_empty = await pydantic_adapter.extract("   \t\n  ", {})
    assert res_pai_empty.intent == "unmapped"
    assert res_pai_empty.candidate_slots == {}

    litellm_adapter = LiteLLMAdapter()
    res_lite_empty = await litellm_adapter.extract("   \t\n  ", {})
    assert res_lite_empty.intent == "unmapped"
    assert res_lite_empty.candidate_slots == {}

    # 2. Render without slots fallback
    pydantic_adapter._model = None
    res_pai_render = await pydantic_adapter.render("welcome", {})
    assert res_pai_render == "Response for stage 'welcome'."

    res_lite_render = await litellm_adapter.render("welcome", {})
    assert res_lite_render == "Response for stage 'welcome'."

    # 3. Timeout handler branches (TimeoutError caught and re-raised as BLK-MOD exceptions)
    async def slow_fn(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(0.1)
        return "slow"

    slow_pai = PydanticAIAdapter()
    with patch("pydantic_ai.Agent.run", slow_fn):
        with pytest.raises(Pass1TimeoutError):
            await slow_pai.extract("hello", {}, timeout_ms=5)

        with pytest.raises(ModelError):
            await slow_pai.render("stage", {}, timeout_ms=5)

    with patch("litellm.acompletion", slow_fn):
        slow_lite = LiteLLMAdapter(force_litellm_call=True)
        with pytest.raises(Pass1TimeoutError):
            await slow_lite.extract("hello", {}, timeout_ms=5)

        with pytest.raises(ModelError):
            await slow_lite.render("stage", {}, timeout_ms=5)

    async def slow_to_thread(fn: Any, *args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(0.1)
        return fn(*args, **kwargs)

    slow_onnx = ONNXIntentClassifier()
    with patch("asyncio.to_thread", slow_to_thread), pytest.raises(Pass1TimeoutError):
        await slow_onnx.extract("hello", {}, timeout_ms=5)


def test_callable_to_tool_schema_ignores_var_positional_and_var_keyword() -> None:
    """Verify *args and **kwargs are excluded from tool parameter properties and required."""

    def sample_func(user_id: str, count: int = 1, *args: Any, **kwargs: Any) -> str:
        """Process user action."""
        return "ok"

    schema = _callable_to_tool_schema("sample_func", sample_func)
    params = schema["function"]["parameters"]
    assert "user_id" in params["properties"]
    assert "count" in params["properties"]
    assert "args" not in params["properties"]
    assert "kwargs" not in params["properties"]
    assert params["required"] == ["user_id"]


@pytest.mark.asyncio
async def test_schema_properties_none_handled_safely() -> None:
    """Verify delta_schema with properties=None does not trigger TypeError in adapters."""
    schema_none: dict[str, Any] = {"type": "object", "properties": None}

    pai = PydanticAIAdapter(
        mock_response=json.dumps({"intent": "query", "candidate_slots": {"foo": "bar"}})
    )
    res_pai = await pai.extract("test utterance", schema_none)
    assert res_pai.intent == "query"
    assert res_pai.candidate_slots == {}

    lite = LiteLLMAdapter(
        mock_response=json.dumps({"intent": "query", "candidate_slots": {"foo": "bar"}})
    )
    res_lite = await lite.extract("test utterance", schema_none)
    assert res_lite.intent == "query"
    assert res_lite.candidate_slots == {}


@pytest.mark.asyncio
async def test_onnx_confidence_nan_fails_closed() -> None:
    """Verify NaN confidence from ONNX inference fails closed to unmapped intent."""
    classifier = ONNXIntentClassifier()

    def mock_run_nan(utterance: str) -> tuple[str, float]:
        return "classified_intent", float("nan")

    with patch.object(classifier, "_run_onnx_session", side_effect=mock_run_nan):
        res = await classifier.extract("some utterance", {})
        assert res.intent == "unmapped"
        assert res.confidence == 0.0
        assert res.candidate_slots == {}


def test_onnx_multi_input_session_handling() -> None:
    """Verify _run_onnx_session handles transformer multi-input sessions."""
    import numpy as np

    class MockInput:
        def __init__(self, name: str) -> None:
            self.name = name

    class MockMultiInputSession:
        def get_inputs(self) -> list[MockInput]:
            return [
                MockInput("input_ids"),
                MockInput("attention_mask"),
                MockInput("token_type_ids"),
            ]

        def run(self, output_names: Any, input_feed: dict[str, Any]) -> list[Any]:
            assert "input_ids" in input_feed
            assert "attention_mask" in input_feed
            assert "token_type_ids" in input_feed
            return [np.array([[2.0, 0.5]])]

    classifier = ONNXIntentClassifier(
        session=MockMultiInputSession(),
        intent_labels={0: "primary_intent", 1: "secondary_intent"},
    )
    intent, conf = classifier._run_onnx_session("hello world")
    assert intent == "primary_intent"
    assert conf > 0.5

    # Also test tokeniser returning a mapping with input_ids
    def mock_tok(text: str) -> dict[str, Any]:
        return {"input_ids": np.array([[1, 2, 3]])}

    classifier_tok = ONNXIntentClassifier(
        session=MockMultiInputSession(),
        tokeniser=mock_tok,
        intent_labels={0: "tok_intent"},
    )
    intent_tok, conf_tok = classifier_tok._run_onnx_session("hello")
    assert intent_tok == "tok_intent"
    assert conf_tok > 0.5

    # Test single input session with single key mapping
    class MockSingleInputSession:
        def get_inputs(self) -> list[MockInput]:
            return [MockInput("dense_input")]

        def run(self, output_names: Any, input_feed: dict[str, Any]) -> list[Any]:
            assert "dense_input" in input_feed
            return [np.array([[2.0]])]

    classifier_single = ONNXIntentClassifier(
        session=MockSingleInputSession(),
        tokeniser=lambda t: {"tokens": np.array([[1]])},
        intent_labels={0: "single_intent"},
    )
    intent_single, _ = classifier_single._run_onnx_session("hi")
    assert intent_single == "single_intent"


@pytest.mark.asyncio
async def test_pydantic_ai_unexpected_agent_run_raises_model_error() -> None:
    """Verify unexpected agent.run exceptions are wrapped into ModelError (BLK-MOD-001)."""

    async def failing_run(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("GPU memory bus crash")

    adapter = PydanticAIAdapter()
    with patch("pydantic_ai.Agent.run", failing_run):
        with pytest.raises(ModelError) as exc_info:
            await adapter.extract("hello", {})
        assert exc_info.value.code == "BLK-MOD-001"

        with pytest.raises(ModelError) as exc_info_render:
            await adapter.render("stage", {})
        assert exc_info_render.value.code == "BLK-MOD-001"


@pytest.mark.asyncio
async def test_pydantic_ai_prefers_model_output_over_keyword_match() -> None:
    """Verify model output takes precedence over keyword fallback matching."""
    adapter = PydanticAIAdapter(
        intent_keywords={"keyword_intent": ["balance"]},
        mock_response=json.dumps(
            {
                "intent": "model_extracted_intent",
                "candidate_slots": {"account_id": "ACC999"},
                "confidence": 0.99,
            }
        ),
    )
    schema = {
        "type": "object",
        "properties": {"account_id": {"type": "string"}},
    }
    res = await adapter.extract("I want to check my balance", schema)
    assert res.intent == "model_extracted_intent"
    assert res.candidate_slots == {"account_id": "ACC999"}


@pytest.mark.asyncio
async def test_engine_render_ctx_contains_allowed_tools() -> None:
    """Verify TwoPassStatechartEngine.step() passes allowed_tools into renderer.render context."""
    from blockstate.adapters.storage.memory import InMemoryStorageBackend
    from blockstate.core.agent import Agent, Stage, Transition
    from blockstate.core.engine import StatechartEngine
    from blockstate.ports.storage import TurnEnvelope

    captured_context: dict[str, Any] = {}

    class MockRenderer:
        async def render(
            self,
            stage: str,
            context: Mapping[str, Any],
            timeout_ms: int = 5000,
        ) -> str:
            captured_context.update(context)
            return "Rendered mock response"

    def balance_check() -> str:
        return "ok"

    def transfer_tool() -> str:
        return "ok"

    class ToolScopingAgent(Agent):
        @Stage(name="initial_stage", tools=["balance_check", "transfer_tool"])
        def start_stage(self) -> Transition[None]:
            return Transition.stay()

    test_agent = ToolScopingAgent(
        tools={"balance_check": balance_check, "transfer_tool": transfer_tool}
    )
    storage = InMemoryStorageBackend()
    engine = StatechartEngine(
        agent=test_agent,
        storage=storage,
        renderer=MockRenderer(),
    )

    env = TurnEnvelope(session_id="sess_tools_1", turn_index=0, user_message="Hello")
    await engine.step(env)
    assert "allowed_tools" in captured_context
    assert set(captured_context["allowed_tools"]) == {"balance_check", "transfer_tool"}


def test_litellm_stores_tools_dictionary() -> None:
    """Verify LiteLLMAdapter preserves self._tools dictionary."""

    def custom_tool(x: int) -> int:
        return x * 2

    adapter = LiteLLMAdapter(tools={"custom_tool": custom_tool})
    assert "custom_tool" in adapter._tools
    assert adapter._tools["custom_tool"] is custom_tool
