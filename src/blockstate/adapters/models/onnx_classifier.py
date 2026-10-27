"""ONNX System-1 intent classifier adapter for sub-100ms Pass 1 extraction.

Executes CPU-bound ONNX model inference and semantic slot extraction offloaded
to worker threads via asyncio.to_thread to maintain strict latency SLAs (p95 <= 50ms)
without blocking the active asyncio event loop thread.
"""

import asyncio
import math
import re
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from blockstate.errors import Pass1TimeoutError
from blockstate.ports.models import ExtractionResult, IntentClassifier

try:
    import onnxruntime as _ort  # type: ignore[import-untyped]

    ort = _ort
except ImportError:  # pragma: no cover
    ort = None


DEFAULT_REFUSAL_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "bypass security",
    "disallowed prompt",
    "harmful or disallowed",
    "system override",
    "jailbreak",
    "exploit",
)


class ONNXIntentClassifier(IntentClassifier):
    """Pass 1 local System-1 intent classifier using ONNX Runtime.

    Offloads CPU-bound inference and tokenisation to worker threads via
    asyncio.to_thread to achieve sub-50ms p95 latency. Enforces fail-closed
    extraction where unmapped or low-confidence utterances return empty
    candidate slots rather than guessing transition targets.
    """

    def __init__(
        self,
        model_path: str | Path | None = None,
        *,
        session: Any = None,
        tokeniser: Any = None,
        intent_labels: Sequence[str] | Mapping[int, str] | None = None,
        intent_keywords: Mapping[str, Sequence[str]] | None = None,
        slot_keywords: Mapping[str, Sequence[str]] | None = None,
        slot_patterns: Mapping[str, str | re.Pattern[str]] | None = None,
        confidence_threshold: float = 0.5,
        refusal_patterns: Sequence[str] | None = None,
        default_unmapped_intent: str = "unmapped",
        require_onnx: bool = False,
    ) -> None:
        """Initialise the ONNX intent classifier.

        Raises:
            ImportError: If onnxruntime is missing and required.
        """
        if (require_onnx or model_path is not None) and ort is None and session is None:
            raise ImportError(
                "The 'onnxruntime' package is required for ONNXIntentClassifier. "
                "Install it with: pip install blockstate[onnx]"
            )

        self._session = session
        if model_path is not None and session is None:
            if ort is None:  # pragma: no cover
                raise ImportError(
                    "The 'onnxruntime' package is required for ONNXIntentClassifier. "
                    "Install it with: pip install blockstate[onnx]"
                )
            self._session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"],
            )

        self._tokeniser = tokeniser
        if intent_labels is None:
            self._intent_labels: dict[int, str] = {}
        elif isinstance(intent_labels, Mapping):
            self._intent_labels = {int(k): str(v) for k, v in intent_labels.items()}
        else:
            self._intent_labels = {i: str(lbl) for i, lbl in enumerate(intent_labels)}

        self._intent_keywords: dict[str, list[str]] = (
            {str(k): [str(w).lower() for w in words] for k, words in intent_keywords.items()}
            if intent_keywords
            else {}
        )
        self._slot_keywords: dict[str, list[str]] = (
            {str(k): [str(w).lower() for w in words] for k, words in slot_keywords.items()}
            if slot_keywords
            else {}
        )
        self._slot_patterns: dict[str, re.Pattern[str]] = {}
        if slot_patterns:
            for k, pattern in slot_patterns.items():
                if isinstance(pattern, re.Pattern):
                    self._slot_patterns[str(k)] = pattern
                else:
                    self._slot_patterns[str(k)] = re.compile(pattern, re.IGNORECASE)

        self.confidence_threshold = float(confidence_threshold)
        self.default_unmapped_intent = str(default_unmapped_intent)

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
                result = await asyncio.to_thread(
                    self._sync_classify,
                    utterance,
                    delta_schema,
                    start_time,
                )
                return result
        except TimeoutError:
            raise Pass1TimeoutError(
                f"Pass 1 intent classification exceeded budget of {timeout_ms}ms",
                code="BLK-MOD-003",
            ) from None

    def _sync_classify(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        start_time: float,
    ) -> ExtractionResult:
        """Synchronously execute tokenisation, model inference, and slot extraction.

        Runs inside a worker thread to ensure the asyncio event loop remains unblocked.
        """
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

        # 2. Check for empty or purely whitespace utterance -> fail closed immediately
        if not lower_utterance:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent=self.default_unmapped_intent,
                candidate_slots={},
                is_refusal=False,
                confidence=0.0,
                latency_ms=elapsed_ms,
            )

        # 3. ONNX Session inference if session is configured
        predicted_intent: str | None = None
        confidence = 0.0

        if self._session is not None:
            predicted_intent, confidence = self._run_onnx_session(utterance)

        # 4. Fallback or primary keyword semantic matching
        if predicted_intent is None or predicted_intent == self.default_unmapped_intent:
            for intent_name, keywords in self._intent_keywords.items():
                if any(kw in lower_utterance for kw in keywords):
                    predicted_intent = intent_name
                    confidence = 0.95
                    break

        # 5. Fail-closed if unmapped or below confidence threshold
        if (
            predicted_intent is None
            or predicted_intent == self.default_unmapped_intent
            or math.isnan(confidence)
            or confidence < self.confidence_threshold
        ):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ExtractionResult(
                intent=self.default_unmapped_intent,
                candidate_slots={},
                is_refusal=False,
                confidence=0.0 if math.isnan(confidence) else confidence,
                latency_ms=elapsed_ms,
            )

        # 6. Slot extraction against delta_schema
        candidate_slots = self._extract_slots(utterance, delta_schema)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ExtractionResult(
            intent=predicted_intent,
            candidate_slots=candidate_slots,
            is_refusal=False,
            confidence=confidence,
            latency_ms=elapsed_ms,
        )

    def _run_onnx_session(self, utterance: str) -> tuple[str, float]:
        """Execute inference against the ONNX Runtime session."""
        try:
            inputs = self._session.get_inputs()
            input_names = [inp.name for inp in inputs]

            if self._tokeniser is not None and callable(self._tokeniser):
                encoded = self._tokeniser(utterance)
            else:
                # Default character / length feature vector
                import numpy as np

                vector = np.array([[len(utterance), len(utterance.split())]], dtype=np.float32)
                encoded = vector

            feed_dict: dict[str, Any] = {}
            if isinstance(encoded, Mapping):
                for inp_name in input_names:
                    if inp_name in encoded:
                        feed_dict[inp_name] = encoded[inp_name]
                    elif "mask" in inp_name.lower() and "input_ids" in encoded:
                        import numpy as np

                        feed_dict[inp_name] = np.ones_like(encoded["input_ids"])
                    elif "token_type" in inp_name.lower() and "input_ids" in encoded:
                        import numpy as np

                        feed_dict[inp_name] = np.zeros_like(encoded["input_ids"])
                    elif len(input_names) == 1 and len(encoded) == 1:
                        feed_dict[inp_name] = next(iter(encoded.values()))
            else:
                # encoded is a single tensor / array
                if len(input_names) == 1:
                    feed_dict[input_names[0]] = encoded
                else:
                    import numpy as np

                    for inp_name in input_names:
                        if "mask" in inp_name.lower():
                            feed_dict[inp_name] = np.ones_like(encoded, dtype=np.int64)
                        elif "token_type" in inp_name.lower():
                            feed_dict[inp_name] = np.zeros_like(encoded, dtype=np.int64)
                        else:
                            feed_dict[inp_name] = encoded

            outputs = self._session.run(None, feed_dict)
            logits = outputs[0][0]

            # Softmax calculation
            import numpy as np

            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / np.sum(exp_logits)
            pred_idx = int(np.argmax(probs))
            conf = float(probs[pred_idx])

            intent = self._intent_labels.get(pred_idx, f"intent_{pred_idx}")
            return intent, conf
        except Exception:
            return self.default_unmapped_intent, 0.0

    def _extract_slots(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Extract candidate slot values defined by the stage delta schema."""
        properties = delta_schema.get("properties", {})
        if not properties:
            return {}

        extracted: dict[str, Any] = {}
        for prop_name, prop_def in properties.items():
            # Check custom regex patterns
            if prop_name in self._slot_patterns:
                match = self._slot_patterns[prop_name].search(utterance)
                if match:
                    extracted[prop_name] = match.group(1) if match.groups() else match.group(0)
                    continue

            # Check keyword hints
            if prop_name in self._slot_keywords:
                for kw in self._slot_keywords[prop_name]:
                    if kw in utterance.lower():
                        pattern = rf"\b{re.escape(kw)}\s*[:=]?\s*([A-Za-z0-9_-]+)\b"
                        m = re.search(pattern, utterance, re.IGNORECASE)
                        if m:
                            extracted[prop_name] = m.group(1)
                            break

            if prop_name in extracted:
                continue

            # Standard heuristics based on property names and types
            prop_type = prop_def.get("type", "string")
            if prop_type in ("integer", "number"):
                num_pattern = rf"\b{re.escape(prop_name)}\s*[:=]?\s*(\d+(?:\.\d+)?)\b"
                num_match = re.search(num_pattern, utterance, re.IGNORECASE)
                if num_match:
                    val_str = num_match.group(1)
                    val = int(float(val_str)) if prop_type == "integer" else float(val_str)
                    extracted[prop_name] = val
                    continue

                standalone_num = re.search(r"\b(\d+(?:\.\d+)?)\b", utterance)
                if standalone_num and prop_name in ("id", "amount", "count", "age"):
                    val_str = standalone_num.group(1)
                    val = int(float(val_str)) if prop_type == "integer" else float(val_str)
                    extracted[prop_name] = val
                    continue

            # Common identifiers like account_number, user_id, email, etc.
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

            # Generic property name matching
            pattern = rf"\b{re.escape(prop_name)}\s*(?:is|was|=)?\s*([A-Za-z0-9_-]+)\b"
            generic_match = re.search(pattern, utterance, re.IGNORECASE)
            if generic_match:
                extracted[prop_name] = generic_match.group(1)

        return extracted
