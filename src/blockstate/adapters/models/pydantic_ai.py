"""PydanticAI model adapter for Pass 1 extraction and Pass 2 rendering.

Provides framework integration with PydanticAI agents, supporting structured
intent and slot extraction in Pass 1 and stage-scoped tool whitelisting in Pass 2.
"""

import asyncio
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from pydantic import BaseModel, Field

from blockstate.errors import ModelError, Pass1TimeoutError
from blockstate.ports.models import ExtractionResult, IntentClassifier, ResponseRenderer

try:
    import pydantic_ai
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel
except ImportError:  # pragma: no cover
    pydantic_ai = None  # type: ignore[assignment]
    Agent = None  # type: ignore[assignment, misc]
    TestModel = None  # type: ignore[assignment, misc]


DEFAULT_REFUSAL_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "bypass security",
    "disallowed prompt",
    "harmful or disallowed",
    "system override",
    "jailbreak",
    "exploit",
)


class ExtractionPayload(BaseModel):
    """Structured extraction payload schema for Pass 1 intent and slot collection."""

    intent: str = "unmapped"
    candidate_slots: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    is_refusal: bool = False


class PydanticAIAdapter(IntentClassifier, ResponseRenderer):
    """PydanticAI adapter implementing Pass 1 extraction and Pass 2 response rendering.

    Enforces fail-closed extraction without probabilistic guessing and guarantees
    that Pass 2 outbound model payloads physically omit unwhitelisted stage tools.
    """

    def __init__(
        self,
        model: Any = None,
        *,
        tools: Mapping[str, Callable[..., Any]] | Sequence[Callable[..., Any]] | None = None,
        system_prompt: str | None = None,
        default_unmapped_intent: str = "unmapped",
        refusal_patterns: Sequence[str] | None = None,
        confidence_threshold: float = 0.5,
        intent_keywords: Mapping[str, Sequence[str]] | None = None,
        mock_response: str | Callable[[str], str] | None = None,
        require_pydantic_ai: bool = False,
    ) -> None:
        """Initialise the PydanticAI adapter.

        Raises:
            ImportError: If pydantic-ai-slim is missing and required.
        """
        if (require_pydantic_ai or model is not None) and pydantic_ai is None:
            raise ImportError(
                "The 'pydantic-ai-slim' package is required for PydanticAIAdapter. "
                "Install it with: pip install blockstate[models]"
            )

        if model is None:
            if TestModel is not None:
                self._model: Any = TestModel(custom_output_text="Response rendered successfully.")
            else:  # pragma: no cover
                self._model = None
        else:
            self._model = model

        # Normalise tools mapping
        self._tools: dict[str, Callable[..., Any]] = {}
        if tools is not None:
            if isinstance(tools, Mapping):
                self._tools = dict(tools)
            else:
                for fn in tools:
                    name = getattr(fn, "__name__", str(fn))
                    self._tools[name] = fn

        self.system_prompt = system_prompt
        self.default_unmapped_intent = str(default_unmapped_intent)
        self.confidence_threshold = float(confidence_threshold)
        self.mock_response = mock_response
        self.last_exposed_tools: list[str] = []

        refusal_list = list(DEFAULT_REFUSAL_PATTERNS)
        if refusal_patterns:
            refusal_list.extend(refusal_patterns)
        self._refusal_patterns = tuple(p.lower() for p in refusal_list)

        self._intent_keywords: dict[str, list[str]] = (
            {str(k): [str(w).lower() for w in words] for k, words in intent_keywords.items()}
            if intent_keywords
            else {}
        )

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
        """Execute intent and slot extraction logic."""
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

        # 2. Check for empty or whitespace utterance -> fail closed
        if not lower_utterance:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent=self.default_unmapped_intent,
                candidate_slots={},
                is_refusal=False,
                confidence=0.0,
                latency_ms=elapsed_ms,
            )

        # 3. Keyword / semantic intent matching fallback
        matched_intent: str | None = None
        for intent_name, keywords in self._intent_keywords.items():
            if any(kw in lower_utterance for kw in keywords):
                matched_intent = intent_name
                break

        # 4. If mock_response is supplied or agent execution is possible
        raw_output_text: str | None = None
        if self.mock_response is not None:
            if callable(self.mock_response):
                raw_output_text = self.mock_response(utterance)
            else:
                raw_output_text = str(self.mock_response)
        elif Agent is not None and self._model is not None:
            try:
                agent_kwargs: dict[str, Any] = {"model": self._model}
                if self.system_prompt is not None:
                    agent_kwargs["system_prompt"] = self.system_prompt
                agent: Agent[None, Any] = Agent(**agent_kwargs)
                prompt = (
                    f"Extract intent and slots from utterance: {utterance}\n"
                    f"Schema: {json.dumps(delta_schema, default=str)}"
                )
                run_res = await agent.run(prompt)
                raw_output = getattr(run_res, "output", getattr(run_res, "data", None))
                if isinstance(raw_output, ExtractionPayload):
                    parsed_intent = raw_output.intent
                    parsed_slots = raw_output.candidate_slots
                    conf = raw_output.confidence
                    if raw_output.is_refusal:
                        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                        return ExtractionResult(
                            intent="refusal",
                            candidate_slots={},
                            is_refusal=True,
                            confidence=1.0,
                            latency_ms=elapsed_ms,
                        )
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
                if isinstance(raw_output, str):
                    raw_output_text = raw_output
            except Exception as exc:
                exc_str = str(exc).lower()
                if "refusal" in exc_str or "safety" in exc_str:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    return ExtractionResult(
                        intent="refusal",
                        candidate_slots={},
                        is_refusal=True,
                        confidence=1.0,
                        latency_ms=elapsed_ms,
                    )
                raise ModelError(
                    f"PydanticAI agent execution failed: {exc}",
                    code="BLK-MOD-001",
                ) from exc

        # 5. Parse JSON from output text if present (prefer model output)
        if raw_output_text is not None and "{" in raw_output_text and "}" in raw_output_text:
            try:
                start_idx = raw_output_text.index("{")
                end_idx = raw_output_text.rindex("}") + 1
                data = json.loads(raw_output_text[start_idx:end_idx])
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
                    conf = float(data.get("confidence", 0.9))
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

        # 6. Fallback: Keyword intent matching with heuristic slots
        if matched_intent is not None:
            candidate_slots = self._extract_slots_heuristic(utterance, delta_schema)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent=matched_intent,
                candidate_slots=candidate_slots,
                is_refusal=False,
                confidence=0.9,
                latency_ms=elapsed_ms,
            )

        # 7. Fail-closed default: never guess on unmapped utterances
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ExtractionResult(
            intent=self.default_unmapped_intent,
            candidate_slots={},
            is_refusal=False,
            confidence=0.0,
            latency_ms=elapsed_ms,
        )

    def _extract_slots_heuristic(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Extract candidate slots using stage schema property specifications."""
        properties = delta_schema.get("properties") or {}
        if not properties:
            return {}

        extracted: dict[str, Any] = {}
        for prop_name, prop_def in properties.items():
            prop_type = prop_def.get("type", "string")

            if "account" in prop_name.lower():
                acc_match = re.search(r"\b([A-Z]{2,4}\d{3,8})\b", utterance)
                if acc_match:
                    extracted[prop_name] = acc_match.group(1)
                    continue

            if "date" in prop_name.lower():
                date_match = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", utterance)
                if date_match:
                    extracted[prop_name] = date_match.group(1)
                    continue

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
        """Execute stage-scoped Pass 2 rendering."""
        # Physically scope tools to ONLY those whitelisted by the active stage
        allowed_tools = context.get("allowed_tools")
        if allowed_tools is None:
            allowed_tools = context.get("stage_tools")

        scoped_tool_callables: list[Callable[..., Any]] = []
        exposed_tool_names: list[str] = []

        if allowed_tools is not None:
            allowed_set = frozenset(str(t) for t in allowed_tools)
            for name, fn in self._tools.items():
                if name in allowed_set:
                    scoped_tool_callables.append(fn)
                    exposed_tool_names.append(name)

        self.last_exposed_tools = exposed_tool_names

        if self.mock_response is not None:
            if callable(self.mock_response):
                return str(self.mock_response(stage))
            return str(self.mock_response)

        # If Agent is available, run agent with strictly scoped tools
        if Agent is not None and self._model is not None:
            agent_kwargs = {"model": self._model, "tools": scoped_tool_callables}
            if self.system_prompt is not None:
                agent_kwargs["system_prompt"] = self.system_prompt
            agent = Agent(**agent_kwargs)
            prompt = f"Active Stage: {stage}\nContext: {json.dumps(context, default=str)}"
            try:
                run_res = await agent.run(prompt)
                output = getattr(run_res, "output", getattr(run_res, "data", None))
                if output is not None:
                    return str(output)
            except Exception as exc:
                raise ModelError(
                    f"PydanticAI agent execution failed: {exc}",
                    code="BLK-MOD-001",
                ) from exc

        slots_info = context.get("slots", {})
        if slots_info:
            slots_str = ", ".join(f"{k}={v}" for k, v in sorted(slots_info.items()))
            return f"Response for stage '{stage}' with slots: {slots_str}."
        return f"Response for stage '{stage}'."
