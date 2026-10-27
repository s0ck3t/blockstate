"""Deterministic test doubles for IntentClassifier, ResponseRenderer, and LedgerSink."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from blockstate.ports.ledger import TurnLedgerRecord
from blockstate.ports.models import ExtractionResult


class DeterministicIntentClassifier:
    """Configurable test double implementing the Pass 1 IntentClassifier protocol."""

    def __init__(
        self,
        default_intent: str = "default",
        intent_map: Mapping[str, ExtractionResult] | None = None,
    ) -> None:
        self.default_intent = default_intent
        self.intent_map: dict[str, ExtractionResult] = dict(intent_map) if intent_map else {}

    def set_mapping(self, utterance: str, result: ExtractionResult) -> None:
        """Register a canned extraction result for an utterance."""
        self.intent_map[utterance] = result

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        """Extract candidate slots and classify intent deterministically."""
        if utterance in self.intent_map:
            return self.intent_map[utterance]

        for key, res in self.intent_map.items():
            if key in utterance:
                return res

        # Extract any candidate slots matching schema field names from keywords
        extracted_slots: dict[str, Any] = {}
        for field_name in delta_schema.get("properties", {}):
            if field_name.lower() in utterance.lower():
                extracted_slots[field_name] = f"extracted_{field_name}"

        return ExtractionResult(
            intent=self.default_intent,
            candidate_slots=extracted_slots,
            is_refusal=False,
            confidence=1.0,
            latency_ms=1.0,
        )


class DeterministicResponseRenderer:
    """Configurable test double implementing the Pass 2 ResponseRenderer protocol."""

    def __init__(self, templates: Mapping[str, str] | None = None) -> None:
        self.templates: dict[str, str] = dict(templates) if templates else {}

    async def render(
        self,
        stage: str,
        context: Mapping[str, Any],
        timeout_ms: int = 5000,
    ) -> str:
        """Render response template for the resolved active stage."""
        if stage in self.templates:
            return self.templates[stage]
        return f"Response for stage '{stage}'"


class InMemoryLedgerSink:
    """In-memory append-only sink for TurnLedgerRecords with hash-chain verification."""

    def __init__(self) -> None:
        self.records: list[TurnLedgerRecord] = []

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a validated turn record to the audit ledger."""
        self.records.append(record)

    async def flush(self) -> None:
        """No-op for in-memory buffer."""
        pass

    async def close(self) -> None:
        """No-op for in-memory buffer."""
        pass

    def verify_hash_chain(self) -> bool:
        """Verify the cryptographic SHA-256 hash chain across all stored records."""
        for i, rec in enumerate(self.records):
            expected_prev = "0" * 64 if i == 0 else self.records[i - 1].record_hash

            if rec.prev_record_hash != expected_prev:
                return False

            payload = {
                "prev_record_hash": rec.prev_record_hash,
                "session_id": rec.session_id,
                "turn_index": rec.turn_index,
                "stage_from": rec.stage_from,
                "stage_to": rec.stage_to,
                "exposed_tools": list(rec.exposed_tools),
                "prompt_hash": rec.prompt_hash,
                "vaulted_input_hash": rec.vaulted_input_hash,
                "vaulted_output_hash": rec.vaulted_output_hash,
                "guard_outcome": rec.guard_outcome,
                "timestamp_utc": rec.timestamp_utc,
            }
            canonical_jcs = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            digest = hashlib.sha256(canonical_jcs).hexdigest()

            if digest != rec.record_hash:
                return False

        return True


__all__: list[str] = [
    "DeterministicIntentClassifier",
    "DeterministicResponseRenderer",
    "InMemoryLedgerSink",
]
