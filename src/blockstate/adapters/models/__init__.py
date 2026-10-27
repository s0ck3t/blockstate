"""Model adapters for intent classification and response rendering.

Provides ONNXIntentClassifier (sub-100ms System-1 classification), PydanticAIAdapter
(PydanticAI structured extraction and Pass 2 rendering), and LiteLLMAdapter
(multi-provider LLM integration with tool whitelisting and refusal circuit breakers).
"""

try:
    from blockstate.adapters.models.onnx_classifier import ONNXIntentClassifier
except ImportError:  # pragma: no cover
    ONNXIntentClassifier = None  # type: ignore[assignment, misc]

try:
    from blockstate.adapters.models.pydantic_ai import PydanticAIAdapter
except ImportError:  # pragma: no cover
    PydanticAIAdapter = None  # type: ignore[assignment, misc]

try:
    from blockstate.adapters.models.litellm import LiteLLMAdapter
except ImportError:  # pragma: no cover
    LiteLLMAdapter = None  # type: ignore[assignment, misc]

__all__: list[str] = [
    "LiteLLMAdapter",
    "ONNXIntentClassifier",
    "PydanticAIAdapter",
]
