"""Unit tests for Blockstate port interfaces, SPI protocols, and wire DTOs."""

from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import ValidationError

from blockstate.ports import (
    BlockstateTurnAborted,
    BlockstateTurnComplete,
    BlockstateTurnYield,
    ExtractionResult,
    IntentClassifier,
    LeaseHandle,
    LedgerSink,
    PIIStripper,
    ResponseRenderer,
    SanitisedPayload,
    SessionCheckpoint,
    StateStore,
    StorageBackend,
    TurnEnvelope,
    TurnLedgerRecord,
)


class DummyStorageBackend:
    """Mock storage backend implementing all required StorageBackend protocol methods."""

    async def acquire_lease(
        self,
        session_id: str,
        ttl_ms: int = 30000,
        wait_timeout_ms: int = 2000,
    ) -> LeaseHandle:
        return LeaseHandle(
            session_id=session_id,
            lease_id="test-lease-01",
            expires_at_epoch_ms=100000,
        )

    async def release_lease(self, lease: LeaseHandle) -> None:
        pass

    async def renew_lease(
        self,
        lease: LeaseHandle,
        ttl_ms: int = 30000,
    ) -> LeaseHandle:
        return lease

    async def load_checkpoint(self, session_id: str) -> SessionCheckpoint | None:
        return None

    async def save_checkpoint(
        self,
        checkpoint: SessionCheckpoint,
        lease: LeaseHandle,
    ) -> None:
        pass

    async def close(self) -> None:
        pass


class IncompleteStorageBackend:
    """Mock storage backend intentionally lacking acquire_lease method."""

    async def release_lease(self, lease: LeaseHandle) -> None:
        pass


def test_storage_backend_protocol_adherence() -> None:
    """Verify runtime_checkable protocol validation for StorageBackend and StateStore."""
    backend = DummyStorageBackend()
    assert isinstance(backend, StorageBackend)
    assert isinstance(backend, StateStore)

    incomplete = IncompleteStorageBackend()
    assert not isinstance(incomplete, StorageBackend)
    assert not isinstance(incomplete, StateStore)


def test_lease_handle_immutability() -> None:
    """Verify LeaseHandle DTO is frozen and rejects attribute mutations and extra attributes."""
    lease = LeaseHandle(
        session_id="session-001",
        lease_id="lease-abc",
        expires_at_epoch_ms=1700000000000,
        fence_token=1,
    )

    with pytest.raises(ValidationError):
        lease.session_id = "mutated-session"

    with pytest.raises(ValidationError):
        LeaseHandle.model_validate({
            "session_id": "session-001",
            "lease_id": "lease-abc",
            "expires_at_epoch_ms": 1700000000000,
            "unrecognised_extra": True,
        })


def test_session_checkpoint_and_turn_envelope_immutability() -> None:
    """Verify SessionCheckpoint and TurnEnvelope are frozen and initialised with defaults."""
    checkpoint = SessionCheckpoint(
        session_id="session-001",
        schema_version=1,
        revision_id=0,
    )
    assert checkpoint.schema_version == 1
    assert checkpoint.revision_id == 0
    assert checkpoint.state == {}
    assert checkpoint.task_stack == ()

    with pytest.raises(ValidationError):
        checkpoint.revision_id = 1

    envelope = TurnEnvelope(
        session_id="session-001",
        turn_index=1,
        user_message="Hello",
    )
    assert envelope.turn_index == 1
    assert envelope.user_message == "Hello"

    with pytest.raises(ValidationError):
        envelope.turn_index = 2


def test_wire_dto_turn_yield_immutability() -> None:
    """Verify BlockstateTurnYield rejects field mutation and extra attributes."""
    yield_dto = BlockstateTurnYield(
        session_id="s1",
        message="Please provide your date of birth",
        missing_slots=("date_of_birth",),
    )

    assert yield_dto.state == "in_progress"
    assert yield_dto.missing_slots == ("date_of_birth",)

    with pytest.raises(ValidationError):
        yield_dto.session_id = "s2"

    with pytest.raises(ValidationError):
        BlockstateTurnYield.model_validate({"session_id": "s1", "extra_field": "bad"})


def test_wire_dto_turn_aborted_immutability() -> None:
    """Verify BlockstateTurnAborted rejects field mutation and unrecognised attributes."""
    aborted = BlockstateTurnAborted(
        session_id="s1",
        error_code="BLK-SEC-001",
        reason="Unauthorised tool invocation attempted",
    )

    assert aborted.state == "aborted"
    assert aborted.error_code == "BLK-SEC-001"

    with pytest.raises(ValidationError):
        aborted.reason = "New reason"

    with pytest.raises(ValidationError):
        BlockstateTurnAborted.model_validate({
            "session_id": "s1",
            "error_code": "BLK-SEC-001",
            "reason": "Unauthorised tool",
            "unrecognised_extra": True,
        })


def test_wire_dto_turn_complete_generic_typing_and_immutability() -> None:
    """Verify BlockstateTurnComplete preserves generic typing and enforces immutability."""
    result_data = {"claim_id": "CLM-9999", "status": "approved"}
    complete = BlockstateTurnComplete[dict[str, Any]](
        session_id="s1",
        result=result_data,
        ledger_head_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    assert complete.state == "completed"
    assert complete.result == result_data

    with pytest.raises(ValidationError):
        complete.result = {}

    with pytest.raises(ValidationError):
        BlockstateTurnComplete.model_validate({
            "session_id": "s1",
            "result": result_data,
            "ledger_head_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "unrecognised_extra": True,
        })


def test_wire_dto_serialisation_round_trip() -> None:
    """Verify wire DTOs can be serialised to dictionary and restored cleanly."""
    original = BlockstateTurnYield(
        session_id="sess-round-trip",
        message="Verification required",
        choices=["Accept", "Decline"],
        missing_slots=["identity_document"],
    )

    data = original.model_dump()
    restored = BlockstateTurnYield.model_validate(data)

    assert restored == original


class DummyIntentClassifier:
    """Mock intent classifier adhering to IntentClassifier protocol."""

    async def extract(
        self,
        utterance: str,
        delta_schema: Mapping[str, Any],
        timeout_ms: int = 100,
    ) -> ExtractionResult:
        return ExtractionResult(intent="confirm_claim")


class DummyResponseRenderer:
    """Mock response renderer adhering to ResponseRenderer protocol."""

    async def render(
        self,
        stage: str,
        context: Mapping[str, Any],
        timeout_ms: int = 5000,
    ) -> str:
        return "Claim confirmed."


def test_model_protocols_and_extraction_dto() -> None:
    """Verify IntentClassifier and ResponseRenderer protocols and ExtractionResult DTO."""
    classifier = DummyIntentClassifier()
    assert isinstance(classifier, IntentClassifier)

    renderer = DummyResponseRenderer()
    assert isinstance(renderer, ResponseRenderer)

    res = ExtractionResult(
        intent="provide_nino",
        candidate_slots={"nino": "<VAULT:NINO_01>"},
        confidence=0.98,
    )
    assert res.intent == "provide_nino"
    assert res.candidate_slots["nino"] == "<VAULT:NINO_01>"

    with pytest.raises(ValidationError):
        res.confidence = 1.0


class DummyLedgerSink:
    """Mock audit ledger sink adhering to LedgerSink protocol."""

    async def append(self, record: TurnLedgerRecord) -> None:
        pass

    async def flush(self) -> None:
        pass

    async def close(self) -> None:
        pass


def test_ledger_protocols_and_turn_record_dto() -> None:
    """Verify LedgerSink protocol and TurnLedgerRecord DTO immutability."""
    sink = DummyLedgerSink()
    assert isinstance(sink, LedgerSink)

    record = TurnLedgerRecord(
        prev_record_hash="0000000000000000000000000000000000000000000000000000000000000000",
        session_id="s1",
        turn_index=0,
        stage_from="init",
        stage_to="login",
        exposed_tools=("lookup_user",),
        prompt_hash="abc",
        vaulted_input_hash="def",
        vaulted_output_hash="ghi",
        guard_outcome="success",
        timestamp_utc="2026-10-27T12:00:00.000000Z",
        record_hash="1111111111111111111111111111111111111111111111111111111111111111",
    )
    assert record.turn_index == 0
    assert record.exposed_tools == ("lookup_user",)

    with pytest.raises(ValidationError):
        record.turn_index = 1


class DummyPIIStripper:
    """Mock PII stripper adhering to PIIStripper protocol."""

    async def sanitise(self, text: str, session_id: str) -> SanitisedPayload:
        return SanitisedPayload(sanitised_text=text)

    async def sanitise_mapping(
        self,
        data: Mapping[str, Any],
        session_id: str,
    ) -> Mapping[str, Any]:
        return dict(data)

    def detokenise(
        self,
        text: str,
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> str:
        return text

    def detokenise_mapping(
        self,
        data: Mapping[str, Any],
        vault_map: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> Mapping[str, Any]:
        return dict(data)


def test_security_protocols_and_sanitised_payload_dto() -> None:
    """Verify PIIStripper protocol and SanitisedPayload DTO immutability."""
    stripper = DummyPIIStripper()
    assert isinstance(stripper, PIIStripper)

    payload = SanitisedPayload(
        sanitised_text="Hello <VAULT:NINO_01>",
        vault_tokens={"<VAULT:NINO_01>": "MASKED_NINO_VALUE"},
    )
    assert payload.sanitised_text == "Hello <VAULT:NINO_01>"

    with pytest.raises(ValidationError):
        payload.sanitised_text = "new text"
