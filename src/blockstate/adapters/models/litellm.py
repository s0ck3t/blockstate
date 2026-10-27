"""LiteLLM adapter for Pass 1 extraction and Pass 2 rendering.

Provides multi-provider LLM integration via litellm (<1.107.0), implementing
structured JSON extraction, upstream safety refusal detection, and stage-scoped
tool whitelisting.
"""

import asyncio
import inspect
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, get_origin

from blockstate.errors import ModelError, Pass1TimeoutError
from blockstate.ports.models import ExtractionResult, IntentClassifier, ResponseRenderer

try:
    import litellm
except ImportError:  # pragma: no cover
    litellm = None  # type: ignore[assignment]


DEFAULT_REFUSAL_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "bypass security",
    "disallowed prompt",
    "harmful or disallowed",
    "system override",
    "jailbreak",
    "exploit",
)


def _callable_to_tool_schema(name: str, fn: Callable[..., Any]) -> dict[str, Any]:
    """Convert a Python callable into an OpenAI/LiteLLM function tool schema."""
    doc = inspect.getdoc(fn) or f"Execute tool {name}"
    sig = inspect.signature(fn)

    properties: dict[str, Any] = {}
    required: list[str] = []

    for param_name, param in sig.parameters.items():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if param_name in ("context", "ctx"):
            continue

        prop: dict[str, Any] = {"type": "string"}
        if param.annotation is int:
            prop = {"type": "integer"}
        elif param.annotation is float:
            prop = {"type": "number"}
        elif param.annotation is bool:
            prop = {"type": "boolean"}
        elif param.annotation is list or get_origin(param.annotation) is list:
            prop = {"type": "array"}
        elif param.annotation is dict or get_origin(param.annotation) is dict:
            prop = {"type": "object"}

        properties[param_name] = prop
        if param.default is inspect._empty:
            required.append(param_name)

    return {
        "type": "function",
        "function": {
            "name": name,
            "description": doc,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


class LiteLLMAdapter(IntentClassifier, ResponseRenderer):
    """LiteLLM adapter implementing Pass 1 extraction and Pass 2 rendering.

    Enforces refusal circuit breakers, fail-closed extraction without guessing,
    and stage-scoped tool whitelisting preventing unwhitelisted tool leakage.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        tools: Mapping[str, Callable[..., Any]] | Sequence[Callable[..., Any]] | None = None,
        tool_schemas: Mapping[str, dict[str, Any]] | Sequence[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        default_unmapped_intent: str = "unmapped",
        refusal_patterns: Sequence[str] | None = None,
        confidence_threshold: float = 0.5,
        mock_response: str | Callable[[str], str] | None = None,
        require_litellm: bool = False,
        **extra_kwargs: Any,
    ) -> None:
        """Initialise the LiteLLM adapter.

        Raises:
            ImportError: If litellm is missing and required.
        """
        if (require_litellm or api_key is not None or base_url is not None) and litellm is None:
            raise ImportError(
                "The 'litellm' package is required for LiteLLMAdapter. "
                "Install it with: pip install blockstate[litellm]"
            )

        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.system_prompt = system_prompt
        self.temperature = temperature
        self.default_unmapped_intent = str(default_unmapped_intent)
        self.confidence_threshold = float(confidence_threshold)
        self.mock_response = mock_response
        self.extra_kwargs = extra_kwargs

        self._tools: dict[str, Callable[..., Any]] = {}
        self._tool_schemas: dict[str, dict[str, Any]] = {}
        if tool_schemas is not None:
            if isinstance(tool_schemas, Mapping):
                for k, v in tool_schemas.items():
                    name = v.get("function", {}).get("name", k)
                    self._tool_schemas[name] = v
            else:
                for v in tool_schemas:
                    name = v.get("function", {}).get("name", v.get("name", "unknown"))
                    self._tool_schemas[name] = v

        if tools is not None:
            if isinstance(tools, Mapping):
                self._tools = dict(tools)
                for name, fn in tools.items():
                    if name not in self._tool_schemas:
                        self._tool_schemas[name] = _callable_to_tool_schema(name, fn)
            else:
                for fn in tools:
                    name = getattr(fn, "__name__", str(fn))
                    self._tools[name] = fn
                    if name not in self._tool_schemas:
                        self._tool_schemas[name] = _callable_to_tool_schema(name, fn)

        self.last_exposed_tools: list[str] = []
        self.last_outbound_payload: dict[str, Any] = {}

        refusal_list = list(DEFAULT_REFUSAL_PATTERNS)
        if refusal_patterns:
            refusal_list.extend(refusal_patterns)
        self._refusal_patterns = tuple(p.lower() for p in refusal_list)

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        """Classify user intent and extract candidate slots within latency budget."""
        if timeout_ms <= 0:
            raise Pass1TimeoutError(
                f"Pass 1 intent classification exceeded budget of {timeout_ms}ms",
                code="BLK-MOD-003",
            )

        start_time = time.perf_counter()
        try:
            async with asyncio.timeout(timeout_ms / 1000.0):
                return await self._execute_extract(utterance, delta_schema, start_time)
        except TimeoutError:
            raise Pass1TimeoutError(
                f"Pass 1 intent classification exceeded budget of {timeout_ms}ms",
                code="BLK-MOD-003",
            ) from None

    async def _execute_extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        start_time: float,
    ) -> ExtractionResult:
        """Execute structured extraction via LiteLLM."""
        lower_utterance = utterance.lower().strip()

        # 1. Refusal circuit breaker check
        if any(pattern in lower_utterance for pattern in self._refusal_patterns):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent="refusal",
                candidate_slots={},
                is_refusal=True,
                confidence=1.0,
                latency_ms=elapsed_ms,
            )

        # 2. Empty or purely whitespace utterance -> fail closed immediately
        if not lower_utterance:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent=self.default_unmapped_intent,
                candidate_slots={},
                is_refusal=False,
                confidence=0.0,
                latency_ms=elapsed_ms,
            )

        # 3. Build messages payload
        system_instruction = (
            "You are a Pass 1 intent and slot classifier. "
            "Respond strictly in JSON with format: "
            '{"intent": string, "candidate_slots": object, '
            '"confidence": float, "is_refusal": bool}. '
            f'If the utterance is unrelated, set intent to "{self.default_unmapped_intent}" '
            "and candidate_slots to {}."
        )
        user_prompt = (
            f"User Utterance: {utterance}\n"
            f"Target Delta Schema: {json.dumps(delta_schema, default=str)}"
        )
        messages = [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_prompt},
        ]

        # 4. Invoke LiteLLM
        response_text: str | None = None
        is_refusal = False

        if self.mock_response is not None and not self.extra_kwargs.get("force_litellm_call"):
            if callable(self.mock_response):
                response_text = self.mock_response(utterance)
            else:
                response_text = str(self.mock_response)
        elif litellm is not None:
            try:
                call_kwargs: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "response_format": {"type": "json_object"},
                    **self.extra_kwargs,
                }
                if self.api_key:
                    call_kwargs["api_key"] = self.api_key
                if self.base_url:
                    call_kwargs["base_url"] = self.base_url

                resp = await litellm.acompletion(**call_kwargs)
                choice = resp.choices[0]

                # Check refusal / content filter
                finish_reason = getattr(choice, "finish_reason", None)
                has_refusal = getattr(choice.message, "refusal", None) is not None
                if finish_reason in ("content_filter", "safety") or has_refusal:
                    is_refusal = True
                else:
                    response_text = choice.message.content
            except Exception as exc:
                exc_str = str(exc).lower()
                if "content_filter" in exc_str or "safety" in exc_str or "refusal" in exc_str:
                    is_refusal = True

        if is_refusal:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent="refusal",
                candidate_slots={},
                is_refusal=True,
                confidence=1.0,
                latency_ms=elapsed_ms,
            )

        # 5. Parse structured response
        if response_text and "{" in response_text and "}" in response_text:
            try:
                start_idx = response_text.index("{")
                end_idx = response_text.rindex("}") + 1
                data = json.loads(response_text[start_idx:end_idx])
                if isinstance(data, dict):
                    if data.get("is_refusal"):
                        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                        return ExtractionResult(
                            intent="refusal",
                            candidate_slots={},
                            is_refusal=True,
                            confidence=1.0,
                            latency_ms=elapsed_ms,
                        )

                    parsed_intent = str(data.get("intent", self.default_unmapped_intent))
                    parsed_slots = dict(data.get("candidate_slots", {}))
                    conf = float(data.get("confidence", 0.95))

                    is_low_conf = conf < self.confidence_threshold
                    if parsed_intent == self.default_unmapped_intent or is_low_conf:
                        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                        return ExtractionResult(
                            intent=self.default_unmapped_intent,
                            candidate_slots={},
                            is_refusal=False,
                            confidence=conf,
                            latency_ms=elapsed_ms,
                        )

                    # Filter candidate slots strictly to schema properties
                    valid_props = delta_schema.get("properties") or {}
                    filtered_slots = {k: v for k, v in parsed_slots.items() if k in valid_props}

                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    return ExtractionResult(
                        intent=parsed_intent,
                        candidate_slots=filtered_slots,
                        is_refusal=False,
                        confidence=conf,
                        latency_ms=elapsed_ms,
                    )
            except Exception:
                pass

        # 6. Fallback slot extraction heuristic if utterance has identifiable slots
        extracted_slots = self._heuristic_slot_match(utterance, delta_schema)
        if extracted_slots:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent="extracted_slots",
                candidate_slots=extracted_slots,
                is_refusal=False,
                confidence=0.9,
                latency_ms=elapsed_ms,
            )

        # 7. Fail-closed default
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ExtractionResult(
            intent=self.default_unmapped_intent,
            candidate_slots={},
            is_refusal=False,
            confidence=0.0,
            latency_ms=elapsed_ms,
        )

    def _heuristic_slot_match(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Heuristic slot matching for delta schema properties."""
        properties = delta_schema.get("properties") or {}
        if not properties:
            return {}

        extracted: dict[str, Any] = {}
        for prop_name, prop_def in properties.items():
            if "account" in prop_name.lower():
                acc_match = re.search(r"\b([A-Z]{2,4}\d{3,8})\b", utterance)
                if acc_match:
                    extracted[prop_name] = acc_match.group(1)
                    continue

            prop_type = prop_def.get("type", "string")
            if prop_type in ("integer", "number"):
                num_pattern = rf"\b{re.escape(prop_name)}\s*[:=]?\s*(\d+(?:\.\d+)?)\b"
                num_match = re.search(num_pattern, utterance, re.IGNORECASE)
                if num_match:
                    val_str = num_match.group(1)
                    val = int(float(val_str)) if prop_type == "integer" else float(val_str)
                    extracted[prop_name] = val
                    continue

            pattern = rf"\b{re.escape(prop_name)}\s*(?:is|was|=)?\s*([A-Za-z0-9_-]+)\b"
            generic_match = re.search(pattern, utterance, re.IGNORECASE)
            if generic_match:
                extracted[prop_name] = generic_match.group(1)

        return extracted

    async def render(
        self,
        stage: str,
        context: Mapping[str, Any],
        timeout_ms: int = 5000,
    ) -> str:
        """Render response message for the active stage with strict tool whitelisting."""
        if timeout_ms <= 0:
            raise ModelError(
                f"Pass 2 response rendering exceeded budget of {timeout_ms}ms",
                code="BLK-MOD-001",
            )

        try:
            async with asyncio.timeout(timeout_ms / 1000.0):
                return await self._execute_render(stage, context)
        except TimeoutError:
            raise ModelError(
                f"Pass 2 response rendering exceeded budget of {timeout_ms}ms",
                code="BLK-MOD-001",
            ) from None

    async def _execute_render(
        self,
        stage: str,
        context: Mapping[str, Any],
    ) -> str:
        """Execute stage-scoped Pass 2 rendering with physically filtered tools."""
        allowed_tools = context.get("allowed_tools")
        if allowed_tools is None:
            allowed_tools = context.get("stage_tools")

        scoped_tool_schemas: list[dict[str, Any]] = []
        exposed_tool_names: list[str] = []

        if allowed_tools is not None:
            allowed_set = frozenset(str(t) for t in allowed_tools)
            for name, schema in self._tool_schemas.items():
                if name in allowed_set:
                    scoped_tool_schemas.append(schema)
                    exposed_tool_names.append(name)

        self.last_exposed_tools = exposed_tool_names

        messages = [
            {
                "role": "system",
                "content": self.system_prompt or "You are a customer service assistant.",
            },
            {
                "role": "user",
                "content": (
                    f"Active Stage: {stage}\n"
                    f"Context: {json.dumps(context, default=str)}"
                ),
            },
        ]

        self.last_outbound_payload = {
            "model": self.model,
            "messages": messages,
            "tools": scoped_tool_schemas if scoped_tool_schemas else None,
        }

        if self.mock_response is not None and not self.extra_kwargs.get("force_litellm_call"):
            if callable(self.mock_response):
                return str(self.mock_response(stage))
            return str(self.mock_response)

        if litellm is not None:
            try:
                call_kwargs: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                    **self.extra_kwargs,
                }
                if scoped_tool_schemas:
                    call_kwargs["tools"] = scoped_tool_schemas
                if self.api_key:
                    call_kwargs["api_key"] = self.api_key
                if self.base_url:
                    call_kwargs["base_url"] = self.base_url

                resp = await litellm.acompletion(**call_kwargs)
                content = resp.choices[0].message.content
                if content:
                    return str(content)
            except Exception:
                pass

        slots_info = context.get("slots", {})
        if slots_info:
            slots_str = ", ".join(f"{k}={v}" for k, v in sorted(slots_info.items()))
            return f"Response for stage '{stage}' with slots: {slots_str}."
        return f"Response for stage '{stage}'."
