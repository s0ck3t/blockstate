"""Pass 1 classifier and Pass 2 renderer protocol specifications and DTOs.

Defines the interfaces for intent classification, slot extraction, and
canned/generative response rendering.
"""

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class ExtractionResult(BaseModel):
    """Extraction output from Pass 1 intent and slot classifier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent: str
    candidate_slots: Mapping[str, Any] = Field(default_factory=dict)
    is_refusal: bool = False
    confidence: float = 1.0
    latency_ms: float = 0.0


@runtime_checkable
class IntentClassifier(Protocol):
    """Pass 1 semantic classifier protocol for intent classification and slot extraction."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        """Classify user intent and extract candidate slots within latency budget."""
        ...


@runtime_checkable
class ResponseRenderer(Protocol):
    """Pass 2 response generation protocol for templates and natural language rendering."""

    async def render(
        self,
        stage: str,
        context: Mapping[str, Any],
        timeout_ms: int = 5000,
    ) -> str:
        """Render response message for the resolved active stage."""
        ...
