"""PII boundary protocol specifications and sanitisation DTOs.

Defines the PIIVault ingress and egress sanitisation contracts for tokenising
sensitive entities into deterministic HMAC-SHA256 session-scoped tokens.
"""

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class SanitisedPayload(BaseModel):
    """Sanitised text payload carrying mapped token representations."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sanitised_text: str
    vault_tokens: Mapping[str, str] = Field(default_factory=dict)


@runtime_checkable
class PIIStripper(Protocol):
    """Protocol for stripping and tokenising sensitive PII/PHI entities."""

    async def sanitise(self, text: str, session_id: str) -> SanitisedPayload:
        """Sanitise text by replacing sensitive entities with session tokens."""
        ...

    async def sanitise_mapping(
        self,
        data: Mapping[str, Any],
        session_id: str,
    ) -> Mapping[str, Any]:
        """Recursively sanitise dictionary or mapping values."""
        ...

    def detokenise(
        self,
        text: str,
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> str:
        """Restore tokens in text to their original plaintexts."""
        ...

    def detokenise_mapping(
        self,
        data: Mapping[str, Any],
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Recursively detokenise all string values in a mapping."""
        ...
