"""Reusable contract test suites for verifying port protocol implementations.

Provides:
- PIIStripperContractSuite: verifies zero-leakage, tokenisation, and checksums.
- StateStoreContractSuite: verifies StorageBackend SPI implementations across leasing,
  optimistic CAS concurrency, SchemaUpcaster migrations, and boundary payloads.
- LedgerSinkContractSuite: verifies cryptographic SHA-256 hash chains and audit streaming.
- IntentClassifierContractSuite: verifies Pass 1 intent classification and fail-closed extraction.
- ResponseRendererContractSuite: verifies Pass 2 response generation and stage tool whitelisting.
"""

import abc
import asyncio
import inspect
import time
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from pydantic import ValidationError

from blockstate.errors import (
    ConcurrentSessionError,
    LeaseTimeoutError,
    ModelError,
    OptimisticLockError,
    Pass1TimeoutError,
    StorageError,
)
from blockstate.ports.ledger import (
    LedgerSink,
    TurnLedgerRecord,
    compute_record_hash,
    verify_record_hash,
)
from blockstate.ports.models import (
    ExtractionResult,
    IntentClassifier,
    ResponseRenderer,
)
from blockstate.ports.security import PIIStripper
from blockstate.ports.storage import (
    LeaseHandle,
    SchemaUpcaster,
    SessionCheckpoint,
    SessionLeaseHeartbeat,
    StorageBackend,
)


class PIIStripperContractSuite(abc.ABC):
    """Reusable contract test suite for PIIStripper protocol implementations.

    Subclasses must implement create_stripper() returning the adapter under test.
    Pytest will execute all tests in this suite against that adapter.
    """

    # Do not collect base contract class directly as a test
    __test__ = False

    @abc.abstractmethod
    def create_stripper(self) -> PIIStripper:
        """Create and return an initialised instance of the PIIStripper under test."""
        ...

    @pytest.mark.asyncio
    async def test_protocol_conformance(self) -> None:
        """Verify the instance satisfies runtime PIIStripper protocol check."""
        stripper = self.create_stripper()
        assert isinstance(stripper, PIIStripper)

    @pytest.mark.asyncio
    async def test_empty_string_payload(self) -> None:
        """Verify empty string yields an empty sanitised payload without errors."""
        stripper = self.create_stripper()
        payload = await stripper.sanitise("", session_id="test-empty")
        assert payload.sanitised_text == ""
        assert len(payload.vault_tokens) == 0

    @pytest.mark.asyncio
    async def test_non_pii_payload_unchanged(self) -> None:
        """Verify benign text without sensitive PII remains byte-for-byte identical."""
        stripper = self.create_stripper()
        raw_text = "Good morning! Please confirm your preferred delivery window."
        payload = await stripper.sanitise(raw_text, session_id="test-clean")
        assert payload.sanitised_text == raw_text
        assert len(payload.vault_tokens) == 0

    @pytest.mark.asyncio
    async def test_uk_nino_tokenisation(self) -> None:
        """Verify UK National Insurance number is replaced with deterministic token."""
        stripper = self.create_stripper()
        text = "My NINo is QQ123456C for verification"
        payload = await stripper.sanitise(text, session_id="test-nino")
        assert payload.sanitised_text == "My NINo is <VAULT:NINO_01> for verification"
        assert payload.vault_tokens == {"<VAULT:NINO_01>": "QQ123456C"}

    @pytest.mark.asyncio
    async def test_token_reuse_within_same_session(self) -> None:
        """Verify identical PII within the same session reuses the same token."""
        stripper = self.create_stripper()
        session_id = "test-reuse"

        turn1 = await stripper.sanitise("First turn NINo QQ123456C", session_id=session_id)
        assert "<VAULT:NINO_01>" in turn1.sanitised_text

        turn2 = await stripper.sanitise("Second turn repeats QQ123456C", session_id=session_id)
        assert turn2.sanitised_text == "Second turn repeats <VAULT:NINO_01>"
        assert turn2.vault_tokens.get("<VAULT:NINO_01>") == "QQ123456C"

    @pytest.mark.asyncio
    async def test_distinct_tokens_for_different_pii_in_same_category(self) -> None:
        """Verify distinct PII instances in the same category receive incremented tokens."""
        stripper = self.create_stripper()
        session_id = "test-distinct"

        text = "Primary NINo QQ123456C and secondary NINo AB123456C"
        payload = await stripper.sanitise(text, session_id=session_id)
        assert "<VAULT:NINO_01>" in payload.sanitised_text
        assert "<VAULT:NINO_02>" in payload.sanitised_text
        assert payload.vault_tokens["<VAULT:NINO_01>"] == "QQ123456C"
        assert payload.vault_tokens["<VAULT:NINO_02>"] == "AB123456C"

    @pytest.mark.asyncio
    async def test_uk_nhs_number_modulus11_checksum(self) -> None:
        """Verify UK NHS numbers are sanitised only when passing Modulus 11."""
        stripper = self.create_stripper()
        session_id = "test-nhs"

        # Valid NHS number passing Modulus 11 (9876543210: check digit 0)
        valid_text = "Patient NHS number is 987 654 3210"
        payload_valid = await stripper.sanitise(valid_text, session_id=session_id)
        assert "<VAULT:NHS_01>" in payload_valid.sanitised_text
        assert payload_valid.vault_tokens.get("<VAULT:NHS_01>") == "987 654 3210"

        # Invalid NHS number failing Modulus 11
        invalid_text = "Invalid number is 1234567890"
        payload_invalid = await stripper.sanitise(invalid_text, session_id=session_id)
        assert "<VAULT:NHS" not in payload_invalid.sanitised_text
        assert "1234567890" in payload_invalid.sanitised_text

    @pytest.mark.asyncio
    async def test_payment_card_luhn_algorithm(self) -> None:
        """Verify 16-digit card numbers are sanitised only when passing Luhn algorithm."""
        stripper = self.create_stripper()
        session_id = "test-card"

        # Valid 16-digit card passing Luhn
        valid_card = "4532015012345671"
        payload_valid = await stripper.sanitise(f"Card {valid_card}", session_id=session_id)
        assert "<VAULT:CARD_01>" in payload_valid.sanitised_text
        assert payload_valid.vault_tokens.get("<VAULT:CARD_01>") == valid_card

        # 16-digit numeric sequence failing Luhn
        invalid_card = "4532015012345672"
        payload_invalid = await stripper.sanitise(f"Card {invalid_card}", session_id=session_id)
        assert "<VAULT:CARD" not in payload_invalid.sanitised_text
        assert invalid_card in payload_invalid.sanitised_text

    @pytest.mark.asyncio
    async def test_us_ssn_tokenisation(self) -> None:
        """Verify US Social Security Number detection and tokenisation."""
        stripper = self.create_stripper()
        session_id = "test-ssn"

        valid_ssn = "123-45-6789"
        payload = await stripper.sanitise(f"My SSN is {valid_ssn}", session_id=session_id)
        assert payload.sanitised_text == "My SSN is <VAULT:SSN_01>"
        assert payload.vault_tokens.get("<VAULT:SSN_01>") == valid_ssn

        # Prohibited area number 000 should not be masked as SSN
        bad_ssn = "000-12-3456"
        payload_bad = await stripper.sanitise(f"Not an SSN: {bad_ssn}", session_id=session_id)
        assert "<VAULT:SSN" not in payload_bad.sanitised_text
        assert bad_ssn in payload_bad.sanitised_text

    @pytest.mark.asyncio
    async def test_email_tokenisation(self) -> None:
        """Verify email address tokenisation."""
        stripper = self.create_stripper()
        session_id = "test-email"

        email = "alice.smith@subdomain.example.co.uk"
        payload = await stripper.sanitise(f"Contact {email}", session_id=session_id)
        assert payload.sanitised_text == "Contact <VAULT:EMAIL_01>"
        assert payload.vault_tokens.get("<VAULT:EMAIL_01>") == email

    @pytest.mark.asyncio
    async def test_phone_tokenisation(self) -> None:
        """Verify UK, US, and international telephone number tokenisation."""
        stripper = self.create_stripper()
        session_id = "test-phone"

        phone = "+44 7911 123456"
        payload = await stripper.sanitise(f"Call {phone}", session_id=session_id)
        assert payload.sanitised_text == "Call <VAULT:PHONE_01>"
        assert payload.vault_tokens.get("<VAULT:PHONE_01>") == phone

    @pytest.mark.asyncio
    async def test_postcode_tokenisation(self) -> None:
        """Verify UK postal code tokenisation."""
        stripper = self.create_stripper()
        session_id = "test-postcode"

        postcode = "SW1A 1AA"
        payload = await stripper.sanitise(f"Delivery to {postcode}", session_id=session_id)
        assert payload.sanitised_text == "Delivery to <VAULT:POSTCODE_01>"
        assert payload.vault_tokens.get("<VAULT:POSTCODE_01>") == postcode

    @pytest.mark.asyncio
    async def test_session_isolation(self) -> None:
        """Verify distinct sessions receive isolated token allocation sequences."""
        stripper = self.create_stripper()

        p1 = await stripper.sanitise("NINo QQ123456C", session_id="session-alpha")
        p2 = await stripper.sanitise("NINo AB123456C", session_id="session-beta")

        assert p1.sanitised_text == "NINo <VAULT:NINO_01>"
        assert p2.sanitised_text == "NINo <VAULT:NINO_01>"
        assert p1.vault_tokens["<VAULT:NINO_01>"] == "QQ123456C"
        assert p2.vault_tokens["<VAULT:NINO_01>"] == "AB123456C"

    @pytest.mark.asyncio
    async def test_sanitisation_idempotency(self) -> None:
        """Verify running sanitise twice produces an identical result without nested tokens."""
        stripper = self.create_stripper()
        session_id = "test-idempotent"

        original = "Contact alice@example.com with NINo QQ123456C"
        pass1 = await stripper.sanitise(original, session_id=session_id)
        pass2 = await stripper.sanitise(pass1.sanitised_text, session_id=session_id)

        assert pass1.sanitised_text == pass2.sanitised_text
        assert pass1.vault_tokens == pass2.vault_tokens
        assert "<VAULT:<VAULT:" not in pass2.sanitised_text

    @pytest.mark.asyncio
    async def test_overlapping_and_adjacent_spans(self) -> None:
        """Verify overlapping candidate spans resolve without corrupted text slices."""
        stripper = self.create_stripper()
        session_id = "test-overlap"

        # Email containing digits and postal codes adjacent
        text = "Write to support4532015012345671@domain.com or visit SW1A 1AA"
        payload = await stripper.sanitise(text, session_id=session_id)
        assert payload.sanitised_text == "Write to <VAULT:EMAIL_01> or visit <VAULT:POSTCODE_01>"
        assert payload.vault_tokens == {
            "<VAULT:EMAIL_01>": "support4532015012345671@domain.com",
            "<VAULT:POSTCODE_01>": "SW1A 1AA",
        }

    @pytest.mark.asyncio
    async def test_unicode_zero_width_and_rtl_markers(self) -> None:
        """Verify Unicode zero-width spaces, RTL markers, and emojis are preserved."""
        stripper = self.create_stripper()
        session_id = "test-unicode"

        text = "Hello\u200b\u200f world \U0001f600 with NINo QQ123456C and élan"
        payload = await stripper.sanitise(text, session_id=session_id)
        assert "<VAULT:NINO_01>" in payload.sanitised_text
        assert "\u200b" in payload.sanitised_text
        assert "\u200f" in payload.sanitised_text
        assert "\U0001f600" in payload.sanitised_text
        assert "élan" in payload.sanitised_text

    @pytest.mark.asyncio
    async def test_embedded_null_bytes(self) -> None:
        """Verify strings containing embedded null bytes are handled safely."""
        stripper = self.create_stripper()
        session_id = "test-null"

        text = "Prefix\x00middle QQ123456C\x00suffix"
        payload = await stripper.sanitise(text, session_id=session_id)
        assert payload.sanitised_text == "Prefix\x00middle <VAULT:NINO_01>\x00suffix"
        assert payload.vault_tokens["<VAULT:NINO_01>"] == "QQ123456C"

    @pytest.mark.asyncio
    async def test_large_payload_64kb(self) -> None:
        """Verify 64KB+ payloads with multiple PII spans process without degradation."""
        stripper = self.create_stripper()
        session_id = "test-large"

        filler = "Standard operational payload line without any secrets here.\n" * 1000
        large_text = f"{filler}User NINo is QQ123456C and email is test@example.com\n{filler}"
        assert len(large_text.encode()) > 64 * 1024

        payload = await stripper.sanitise(large_text, session_id=session_id)
        assert "<VAULT:NINO_01>" in payload.sanitised_text
        assert "<VAULT:EMAIL_01>" in payload.sanitised_text
        assert payload.vault_tokens["<VAULT:NINO_01>"] == "QQ123456C"
        assert payload.vault_tokens["<VAULT:EMAIL_01>"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_sanitise_mapping_nested_structures(self) -> None:
        """Verify recursive mapping sanitisation across dicts, lists, and scalar types."""
        stripper = self.create_stripper()
        session_id = "test-mapping"

        data: dict[str, Any] = {
            "user_id": 1042,
            "is_active": True,
            "ratio": 3.1415,
            "metadata": {
                "nino": "QQ123456C",
                "nested_notes": "Call +44 7911 123456 soon",
            },
            "contacts": [
                "test1@example.com",
                {"emergency_email": "emergency@example.com"},
            ],
            "coordinates": (51.5074, -0.1278),
        }

        sanitised = await stripper.sanitise_mapping(data, session_id=session_id)

        assert sanitised["user_id"] == 1042
        assert sanitised["is_active"] is True
        assert sanitised["ratio"] == 3.1415
        assert sanitised["coordinates"] == (51.5074, -0.1278)

        meta = sanitised["metadata"]
        assert meta["nino"] == "<VAULT:NINO_01>"
        assert meta["nested_notes"] == "Call <VAULT:PHONE_01> soon"

        contacts = sanitised["contacts"]
        assert contacts[0] == "<VAULT:EMAIL_01>"
        assert contacts[1]["emergency_email"] == "<VAULT:EMAIL_02>"


class StateStoreContractSuite(abc.ABC):
    """Reusable contract test suite for StorageBackend protocol implementations.

    Subclasses must implement create_backend() returning an initialised instance
    of the StorageBackend under test.
    Pytest will execute all tests in this suite against that adapter.
    """

    # Do not collect base contract class directly as a test
    __test__ = False

    @abc.abstractmethod
    def create_backend(
        self,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> Any:
        """Create and return an initialised instance of the StorageBackend under test."""
        ...

    async def _get_backend(
        self,
        upcasters: Mapping[int, SchemaUpcaster] | None = None,
        target_schema_version: int | None = None,
    ) -> StorageBackend:
        """Helper to resolve sync or async create_backend call."""
        res = self.create_backend(
            upcasters=upcasters,
            target_schema_version=target_schema_version,
        )
        if inspect.isawaitable(res):
            resolved = await res
            return resolved  # type: ignore[no-any-return]
        return res  # type: ignore[no-any-return]

    async def _close_backend(self, backend: StorageBackend) -> None:
        """Helper to gracefully close storage backends."""
        if hasattr(backend, "close") and callable(backend.close):
            res = backend.close()
            if inspect.isawaitable(res):
                await res

    @pytest.mark.asyncio
    async def test_protocol_conformance(self) -> None:
        """Verify the instance satisfies runtime StorageBackend protocol check."""
        backend = await self._get_backend()
        try:
            assert isinstance(backend, StorageBackend)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_acquire_and_release_lease(self) -> None:
        """Verify acquiring and releasing a session lease token."""
        backend = await self._get_backend()
        session_id = "test-contract-acquire-release"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=30000)
            assert lease.session_id == session_id
            assert bool(lease.lease_id)
            assert lease.expires_at_epoch_ms > int(time.time() * 1000)
            assert lease.fence_token >= 1

            await backend.release_lease(lease)

            # Re-acquire immediately
            lease2 = await backend.acquire_lease(session_id, ttl_ms=30000)
            assert lease2.session_id == session_id
            assert lease2.lease_id != lease.lease_id
            assert lease2.fence_token > lease.fence_token
            await backend.release_lease(lease2)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_lease_contention_wait_timeout(self) -> None:
        """Verify lease contention fails fast after wait_timeout_ms with BLK-CON-409."""
        backend = await self._get_backend()
        session_id = "test-contract-contention-timeout"
        try:
            lease1 = await backend.acquire_lease(session_id, ttl_ms=10000)
            assert lease1 is not None

            start = time.monotonic()
            with pytest.raises(ConcurrentSessionError) as exc_info:
                await backend.acquire_lease(session_id, ttl_ms=10000, wait_timeout_ms=100)
            elapsed_ms = (time.monotonic() - start) * 1000

            assert exc_info.value.code == "BLK-CON-409"
            assert exc_info.value.session_id == session_id
            assert elapsed_ms >= 80

            await backend.release_lease(lease1)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_lease_contention_released_in_time(self) -> None:
        """Verify waiting worker acquires lease when existing worker releases within timeout."""
        backend = await self._get_backend()
        session_id = "test-contract-contention-released"
        try:
            lease1 = await backend.acquire_lease(session_id, ttl_ms=10000)

            async def release_after_delay() -> None:
                await asyncio.sleep(0.06)
                await backend.release_lease(lease1)

            release_task = asyncio.create_task(release_after_delay())

            lease2 = await backend.acquire_lease(session_id, ttl_ms=10000, wait_timeout_ms=500)
            assert lease2.session_id == session_id
            assert lease2.lease_id != lease1.lease_id
            await release_task
            await backend.release_lease(lease2)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_stale_lease_expiration(self) -> None:
        """Verify expired lease allows immediate acquisition by another worker."""
        backend = await self._get_backend()
        session_id = "test-contract-stale-expiration"
        try:
            # Acquire with short 50ms TTL
            lease1 = await backend.acquire_lease(session_id, ttl_ms=50)
            assert lease1 is not None

            # Wait for TTL expiration
            await asyncio.sleep(0.08)

            # Next worker acquires cleanly without waiting for timeout
            lease2 = await backend.acquire_lease(session_id, ttl_ms=10000, wait_timeout_ms=100)
            assert lease2.session_id == session_id
            assert lease2.lease_id != lease1.lease_id
            assert lease2.fence_token > lease1.fence_token
            await backend.release_lease(lease2)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_lease_heartbeat_renewal(self) -> None:
        """Verify SessionLeaseHeartbeat context manager extends lease expiration."""
        backend = await self._get_backend()
        session_id = "test-contract-heartbeat-renewal"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=2000)
            initial_expiry = lease.expires_at_epoch_ms

            async with SessionLeaseHeartbeat(
                backend,
                lease,
                heartbeat_interval_ms=50,
                ttl_ms=3000,
            ) as hb:
                assert hb.session_id == session_id
                assert hb.lease_id == lease.lease_id
                await asyncio.sleep(0.12)
                assert hb.expires_at_epoch_ms > initial_expiry

            await backend.release_lease(hb.lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_heartbeat_renewal_on_stolen_or_invalid_lease(self) -> None:
        """Verify renew_lease on stolen or invalid lease raises LeaseTimeoutError (BLK-STO-003)."""
        backend = await self._get_backend()
        session_id = "test-contract-stolen-lease"
        try:
            valid_lease = await backend.acquire_lease(session_id, ttl_ms=10000)

            stolen_lease = LeaseHandle(
                session_id=session_id,
                lease_id="stolen-invalid-lease-id",
                expires_at_epoch_ms=int(time.time() * 1000) + 10000,
                fence_token=0,
            )

            with pytest.raises(LeaseTimeoutError) as exc_info:
                await backend.renew_lease(stolen_lease, ttl_ms=10000)

            assert exc_info.value.code == "BLK-STO-003"
            await backend.release_lease(valid_lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_checkpoint_save_and_load_happy_path(self) -> None:
        """Verify saving and loading checkpoint with valid lease and revision increments."""
        backend = await self._get_backend()
        session_id = "test-contract-checkpoint-happy"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=10000)

            # Initially nonexistent
            assert await backend.load_checkpoint(session_id) is None

            cp0 = SessionCheckpoint(
                session_id=session_id,
                schema_version=1,
                revision_id=0,
                state={"stage": "start", "attempts": 1},
                task_stack=({"frame_id": "root"},),
                last_ledger_hash="hash0",
                created_at="2026-10-27T12:00:00Z",
                updated_at="2026-10-27T12:00:00Z",
            )
            await backend.save_checkpoint(cp0, lease)

            loaded0 = await backend.load_checkpoint(session_id)
            assert loaded0 is not None
            assert loaded0.session_id == session_id
            assert loaded0.schema_version == 1
            assert loaded0.revision_id == 0
            assert loaded0.state == {"stage": "start", "attempts": 1}
            assert loaded0.task_stack == ({"frame_id": "root"},)
            assert loaded0.last_ledger_hash == "hash0"

            # Next revision +1
            cp1 = SessionCheckpoint(
                session_id=session_id,
                schema_version=1,
                revision_id=1,
                state={"stage": "start", "attempts": 2},
                task_stack=({"frame_id": "root"},),
                last_ledger_hash="hash1",
                created_at="2026-10-27T12:00:00Z",
                updated_at="2026-10-27T12:01:00Z",
            )
            await backend.save_checkpoint(cp1, lease)

            loaded1 = await backend.load_checkpoint(session_id)
            assert loaded1 is not None
            assert loaded1.revision_id == 1
            assert loaded1.state == {"stage": "start", "attempts": 2}
            assert loaded1.last_ledger_hash == "hash1"

            await backend.release_lease(lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_checkpoint_save_cas_conflict(self) -> None:
        """Verify saving checkpoint with non-incrementing revision raises OptimisticLockError."""
        backend = await self._get_backend()
        session_id = "test-contract-checkpoint-cas"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=10000)

            cp0 = SessionCheckpoint(session_id=session_id, schema_version=1, revision_id=0)
            await backend.save_checkpoint(cp0, lease)

            # Attempt save with duplicate revision_id=0 (expected 1)
            cp_conflict = SessionCheckpoint(session_id=session_id, schema_version=1, revision_id=0)
            with pytest.raises(OptimisticLockError) as exc_info:
                await backend.save_checkpoint(cp_conflict, lease)
            assert exc_info.value.code == "BLK-STO-002"

            # Attempt save with skipped revision_id=3 (expected 1)
            cp_skip = SessionCheckpoint(session_id=session_id, schema_version=1, revision_id=3)
            with pytest.raises(OptimisticLockError) as exc_info2:
                await backend.save_checkpoint(cp_skip, lease)
            assert exc_info2.value.code == "BLK-STO-002"

            await backend.release_lease(lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_checkpoint_save_expired_or_invalid_lease(self) -> None:
        """Verify save_checkpoint with invalid or expired lease raises LeaseTimeoutError."""
        backend = await self._get_backend()
        session_id = "test-contract-invalid-lease-save"
        try:
            fake_lease = LeaseHandle(
                session_id=session_id,
                lease_id="nonexistent-lease",
                expires_at_epoch_ms=int(time.time() * 1000) + 10000,
                fence_token=1,
            )
            cp = SessionCheckpoint(session_id=session_id, schema_version=1, revision_id=0)

            with pytest.raises(LeaseTimeoutError) as exc_info:
                await backend.save_checkpoint(cp, fake_lease)
            assert exc_info.value.code == "BLK-STO-003"

            # Expired lease
            expired_lease = LeaseHandle(
                session_id=session_id,
                lease_id="expired-lease",
                expires_at_epoch_ms=int(time.time() * 1000) - 1000,
                fence_token=1,
            )
            with pytest.raises(LeaseTimeoutError) as exc_info2:
                await backend.save_checkpoint(cp, expired_lease)
            assert exc_info2.value.code == "BLK-STO-003"
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_checkpoint_load_nonexistent(self) -> None:
        """Verify load_checkpoint returns None for nonexistent session ID."""
        backend = await self._get_backend()
        try:
            assert await backend.load_checkpoint("session-nonexistent-contract-123") is None
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_schema_upcaster_migration(self) -> None:
        """Verify chained SchemaUpcaster migrations upgrade checkpoint version on load."""

        def upcast_1_to_2(data: dict[str, Any]) -> dict[str, Any]:
            payload = dict(data)
            payload["schema_version"] = 2
            state = dict(payload.get("state", {}))
            state["v2_migrated"] = True
            payload["state"] = state
            return payload

        def upcast_2_to_3(data: dict[str, Any]) -> dict[str, Any]:
            payload = dict(data)
            payload["schema_version"] = 3
            state = dict(payload.get("state", {}))
            state["v3_migrated"] = True
            payload["state"] = state
            return payload

        upcasters = {1: upcast_1_to_2, 2: upcast_2_to_3}
        backend = await self._get_backend(upcasters=upcasters, target_schema_version=3)
        session_id = "test-contract-upcaster-chain"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=10000)
            cp_v1 = SessionCheckpoint(
                session_id=session_id,
                schema_version=1,
                revision_id=0,
                state={"initial_key": "v1_value"},
            )
            await backend.save_checkpoint(cp_v1, lease)

            loaded = await backend.load_checkpoint(session_id)
            assert loaded is not None
            assert loaded.schema_version == 3
            assert loaded.state.get("initial_key") == "v1_value"
            assert loaded.state.get("v2_migrated") is True
            assert loaded.state.get("v3_migrated") is True

            await backend.release_lease(lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_boundary_payloads(self) -> None:
        """Verify 64KB state, Unicode/RTL strings, binary vault_map, and max stack depth."""
        backend = await self._get_backend()
        session_id = "test-contract-boundary-payloads"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=10000)

            large_string = "A" * 65536
            unicode_rtl_text = "English & Arabic: مرحبًا \u200f & Hebrew: שָׁלוֹם 🚀"
            vault_bytes = b"\x00\x01\x02\xff\xfe\xaa\xbb\xcc\xdd\xee\x00"

            task_stack = tuple(
                {"depth": d, "stage": f"stage_{d}", "data": [d] * 10} for d in range(6)
            )
            pending_outbox = tuple(
                {"record_id": f"rec_{i}", "payload": f"data_{i}"} for i in range(3)
            )

            cp = SessionCheckpoint(
                session_id=session_id,
                schema_version=1,
                revision_id=0,
                state={
                    "large": large_string,
                    "unicode": unicode_rtl_text,
                    "nested": {"level1": {"level2": {"level3": "deep"}}},
                },
                task_stack=task_stack,
                last_ledger_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                pending_ledger_outbox=pending_outbox,
                vault_map=vault_bytes,
                created_at="2026-10-27T12:00:00.000000Z",
                updated_at="2026-10-27T12:00:00.000000Z",
            )
            await backend.save_checkpoint(cp, lease)

            loaded = await backend.load_checkpoint(session_id)
            assert loaded is not None
            assert loaded.session_id == session_id
            assert loaded.state["large"] == large_string
            assert loaded.state["unicode"] == unicode_rtl_text
            assert loaded.state["nested"] == {"level1": {"level2": {"level3": "deep"}}}
            assert len(loaded.task_stack) == 6
            assert loaded.task_stack == task_stack
            assert loaded.pending_ledger_outbox == pending_outbox
            assert loaded.vault_map == vault_bytes

            await backend.release_lease(lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_schema_upcaster_missing_version_raises_storage_error(self) -> None:
        """Verify missing upcaster when target_schema_version is higher raises BLK-STO-001."""

        def upcast_1_to_2(data: dict[str, Any]) -> dict[str, Any]:
            payload = dict(data)
            payload["schema_version"] = 2
            return payload

        # Backend configured with target_schema_version=3, but only upcaster 1->2 is provided
        upcasters = {1: upcast_1_to_2}
        backend = await self._get_backend(upcasters=upcasters, target_schema_version=3)
        session_id = "test-contract-missing-upcaster"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=10000)
            cp = SessionCheckpoint(
                session_id=session_id,
                schema_version=1,
                revision_id=0,
                state={"key": "val"},
            )
            await backend.save_checkpoint(cp, lease)

            with pytest.raises(StorageError) as exc_info:
                await backend.load_checkpoint(session_id)

            assert exc_info.value.code == "BLK-STO-001"
            assert exc_info.value.session_id == session_id
            await backend.release_lease(lease)
        finally:
            await self._close_backend(backend)

    @pytest.mark.asyncio
    async def test_heartbeat_renewal_failure_in_context(self) -> None:
        """Verify invalid interval raises ValueError, and renewal failure raises on context exit."""
        backend = await self._get_backend()
        session_id = "test-contract-heartbeat-failure"
        try:
            lease = await backend.acquire_lease(session_id, ttl_ms=1000)

            # 1. Validation failure: heartbeat_interval_ms >= ttl_ms
            with pytest.raises(ValueError, match="strictly less than"):
                SessionLeaseHeartbeat(backend, lease, heartbeat_interval_ms=1000, ttl_ms=1000)

            with pytest.raises(ValueError, match="strictly less than"):
                SessionLeaseHeartbeat(backend, lease, heartbeat_interval_ms=2000, ttl_ms=1000)

            # 2. Background renewal failure on stolen/expired/released lease raises on __aexit__
            with pytest.raises(LeaseTimeoutError) as exc_info:
                async with SessionLeaseHeartbeat(
                    backend,
                    lease,
                    heartbeat_interval_ms=20,
                    ttl_ms=500,
                ):
                    # Invalidate lease from outside while inside heartbeat context
                    await backend.release_lease(lease)
                    await asyncio.sleep(0.06)

            assert exc_info.value.code == "BLK-STO-003"
        finally:
            await self._close_backend(backend)


StorageBackendContractSuite = StateStoreContractSuite


class LedgerSinkContractSuite(abc.ABC):
    """Reusable contract test suite for LedgerSink protocol implementations.

    Subclasses must implement create_sink() returning an initialised instance
    of the LedgerSink under test.
    Pytest will execute all tests in this suite against that adapter.
    """

    # Do not collect base contract class directly as a test
    __test__ = False

    @abc.abstractmethod
    def create_sink(self) -> Any:
        """Create and return an initialised instance of the LedgerSink under test."""
        ...

    async def _get_sink(self) -> LedgerSink:
        """Helper to resolve sync or async create_sink call."""
        res = self.create_sink()
        if inspect.isawaitable(res):
            resolved = await res
            return resolved  # type: ignore[no-any-return]
        return res  # type: ignore[no-any-return]

    async def _close_sink(self, sink: LedgerSink) -> None:
        """Helper to gracefully close ledger sinks."""
        if hasattr(sink, "close") and callable(sink.close):
            res = sink.close()
            if inspect.isawaitable(res):
                await res

    async def get_persisted_records(
        self, sink: Any, session_id: str | None = None
    ) -> list[TurnLedgerRecord]:
        """Fetch persisted records from the sink for verification."""
        if hasattr(sink, "get_records") and callable(sink.get_records):
            res = sink.get_records(session_id=session_id)
            if inspect.isawaitable(res):
                return await res  # type: ignore[no-any-return]
            return res  # type: ignore[no-any-return]
        raise NotImplementedError(
            "Subclass must implement get_persisted_records or sink must provide get_records"
        )

    def make_record(
        self,
        session_id: str = "test-session-1",
        turn_index: int = 0,
        prev_record_hash: str = "0" * 64,
        stage_from: str = "initial",
        stage_to: str = "active",
        exposed_tools: Sequence[str] = ("get_balance", "transfer_funds"),
        prompt_hash: str | None = None,
        vaulted_input_hash: str | None = None,
        vaulted_output_hash: str | None = None,
        guard_outcome: str = "allow",
        timestamp_utc: str = "2026-10-27T12:00:00.000000Z",
    ) -> TurnLedgerRecord:
        """Construct a validated TurnLedgerRecord with matching SHA-256 digest."""
        p_hash = prompt_hash or ("a" * 64)
        i_hash = vaulted_input_hash or ("b" * 64)
        o_hash = vaulted_output_hash or ("c" * 64)
        digest = compute_record_hash(
            prev_record_hash=prev_record_hash,
            session_id=session_id,
            turn_index=turn_index,
            stage_from=stage_from,
            stage_to=stage_to,
            exposed_tools=tuple(exposed_tools),
            prompt_hash=p_hash,
            vaulted_input_hash=i_hash,
            vaulted_output_hash=o_hash,
            guard_outcome=guard_outcome,
            timestamp_utc=timestamp_utc,
        )
        return TurnLedgerRecord(
            prev_record_hash=prev_record_hash,
            session_id=session_id,
            turn_index=turn_index,
            stage_from=stage_from,
            stage_to=stage_to,
            exposed_tools=tuple(exposed_tools),
            prompt_hash=p_hash,
            vaulted_input_hash=i_hash,
            vaulted_output_hash=o_hash,
            guard_outcome=guard_outcome,
            timestamp_utc=timestamp_utc,
            record_hash=digest,
        )

    @pytest.mark.asyncio
    async def test_protocol_conformance(self) -> None:
        """Verify the instance satisfies runtime LedgerSink protocol check."""
        sink = await self._get_sink()
        try:
            assert isinstance(sink, LedgerSink)
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_append_single_record_and_flush(self) -> None:
        """Verify appending a single record and flushing persists all fields accurately."""
        sink = await self._get_sink()
        session_id = "test-contract-single-record"
        try:
            rec = self.make_record(session_id=session_id, turn_index=0)
            await sink.append(rec)
            await sink.flush()

            records = await self.get_persisted_records(sink, session_id=session_id)
            assert len(records) == 1
            stored = records[0]
            assert stored.session_id == session_id
            assert stored.turn_index == 0
            assert stored.prev_record_hash == "0" * 64
            assert stored.stage_from == "initial"
            assert stored.stage_to == "active"
            assert tuple(stored.exposed_tools) == ("get_balance", "transfer_funds")
            assert stored.record_hash == rec.record_hash
            assert verify_record_hash(stored)
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_append_multiple_records_monotonic_ordering(self) -> None:
        """Verify multiple records for the same session are persisted in ascending turn order."""
        sink = await self._get_sink()
        session_id = "test-contract-monotonic-order"
        try:
            rec0 = self.make_record(session_id=session_id, turn_index=0, prev_record_hash="0" * 64)
            rec1 = self.make_record(
                session_id=session_id, turn_index=1, prev_record_hash=rec0.record_hash
            )
            rec2 = self.make_record(
                session_id=session_id, turn_index=2, prev_record_hash=rec1.record_hash
            )

            await sink.append(rec0)
            await sink.append(rec1)
            await sink.append(rec2)
            await sink.flush()

            records = await self.get_persisted_records(sink, session_id=session_id)
            assert len(records) == 3
            assert [r.turn_index for r in records] == [0, 1, 2]
            assert records[0].record_hash == rec0.record_hash
            assert records[1].record_hash == rec1.record_hash
            assert records[2].record_hash == rec2.record_hash
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_sha256_hash_chain_validity(self) -> None:
        """Verify cryptographic SHA-256 hash chaining across consecutive turns."""
        sink = await self._get_sink()
        session_id = "test-contract-hash-chain"
        try:
            prev_hash = "0" * 64
            records_written: list[TurnLedgerRecord] = []
            for t in range(4):
                rec = self.make_record(
                    session_id=session_id,
                    turn_index=t,
                    prev_record_hash=prev_hash,
                    timestamp_utc=f"2026-10-27T12:0{t}:00.000000Z",
                )
                await sink.append(rec)
                records_written.append(rec)
                prev_hash = rec.record_hash

            await sink.flush()
            loaded = await self.get_persisted_records(sink, session_id=session_id)
            assert len(loaded) == 4

            for i, item in enumerate(loaded):
                assert verify_record_hash(item)
                expected_prev = "0" * 64 if i == 0 else loaded[i - 1].record_hash
                assert item.prev_record_hash == expected_prev
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_multi_session_isolation_and_filtering(self) -> None:
        """Verify interleaving records across multiple sessions preserves isolation."""
        sink = await self._get_sink()
        s_alpha = "session-alpha"
        s_beta = "session-beta"
        try:
            a0 = self.make_record(session_id=s_alpha, turn_index=0)
            b0 = self.make_record(session_id=s_beta, turn_index=0)
            a1 = self.make_record(session_id=s_alpha, turn_index=1, prev_record_hash=a0.record_hash)
            b1 = self.make_record(session_id=s_beta, turn_index=1, prev_record_hash=b0.record_hash)

            # Interleaved appends
            await sink.append(a0)
            await sink.append(b0)
            await sink.append(a1)
            await sink.append(b1)
            await sink.flush()

            records_alpha = await self.get_persisted_records(sink, session_id=s_alpha)
            assert len(records_alpha) == 2
            assert [r.turn_index for r in records_alpha] == [0, 1]
            assert all(r.session_id == s_alpha for r in records_alpha)

            records_beta = await self.get_persisted_records(sink, session_id=s_beta)
            assert len(records_beta) == 2
            assert [r.turn_index for r in records_beta] == [0, 1]
            assert all(r.session_id == s_beta for r in records_beta)

            records_all = await self.get_persisted_records(sink, session_id=None)
            assert len(records_all) >= 4
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_duplicate_append_idempotency(self) -> None:
        """Verify re-appending a record with identical record_hash is handled idempotently."""
        sink = await self._get_sink()
        session_id = "test-contract-idempotency"
        try:
            rec = self.make_record(session_id=session_id, turn_index=0)
            await sink.append(rec)
            await sink.flush()

            # Re-append identical record
            await sink.append(rec)
            await sink.flush()

            records = await self.get_persisted_records(sink, session_id=session_id)
            assert len(records) == 1
            assert records[0].record_hash == rec.record_hash
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_boundary_payload_records(self) -> None:
        """Verify boundary payloads with empty tools, special characters, and Unicode text."""
        sink = await self._get_sink()
        session_id = "test-contract-boundary-payload"
        try:
            rec = self.make_record(
                session_id=session_id,
                turn_index=0,
                stage_from="étape_initiale_🚀",
                stage_to="مرحلة_النهائية",
                exposed_tools=(),
                prompt_hash="f" * 64,
                vaulted_input_hash="0" * 64,
                vaulted_output_hash="e" * 64,
                guard_outcome="transferred_to_human_agent",
                timestamp_utc="2026-10-27T23:59:59.999999Z",
            )
            await sink.append(rec)
            await sink.flush()

            records = await self.get_persisted_records(sink, session_id=session_id)
            assert len(records) == 1
            stored = records[0]
            assert stored.stage_from == "étape_initiale_🚀"
            assert stored.stage_to == "مرحلة_النهائية"
            assert tuple(stored.exposed_tools) == ()
            assert stored.guard_outcome == "transferred_to_human_agent"
            assert stored.record_hash == rec.record_hash
            assert verify_record_hash(stored)
        finally:
            await self._close_sink(sink)

    @pytest.mark.asyncio
    async def test_flush_and_close_idempotent(self) -> None:
        """Verify repeated calls to flush() and close() execute without exceptions."""
        sink = await self._get_sink()
        session_id = "test-contract-flush-close"
        try:
            rec = self.make_record(session_id=session_id, turn_index=0)
            await sink.append(rec)
            await sink.flush()
            await sink.flush()
            await sink.close()
            await sink.close()
        finally:
            # sink already closed
            pass


class IntentClassifierContractSuite(abc.ABC):
    """Reusable contract test suite for IntentClassifier protocol implementations.

    Subclasses must implement create_classifier() returning an initialised instance
    of the IntentClassifier under test.
    Pytest will execute all tests in this suite against that adapter.
    """

    # Do not collect base contract class directly as a test
    __test__ = False

    @abc.abstractmethod
    def create_classifier(self) -> Any:
        """Create and return an initialised instance of the IntentClassifier under test."""
        ...

    async def _get_classifier(self) -> IntentClassifier:
        """Helper to resolve sync or async create_classifier call."""
        res = self.create_classifier()
        if inspect.isawaitable(res):
            resolved = await res
            return resolved  # type: ignore[no-any-return]
        return res  # type: ignore[no-any-return]

    async def _close_classifier(self, classifier: Any) -> None:
        """Helper to gracefully close classifiers if close() method exists."""
        if hasattr(classifier, "close") and callable(classifier.close):
            res = classifier.close()
            if inspect.isawaitable(res):
                await res

    def get_valid_utterance_and_schema(self) -> tuple[str, Mapping[str, Any]]:
        """Return a test utterance and corresponding slot delta schema for happy path extraction."""
        return (
            "My account number is ACC123 and I want to check my balance",
            {
                "type": "object",
                "properties": {
                    "account_number": {"type": "string"},
                },
            },
        )

    def get_unmapped_utterance(self) -> str:
        """Return an out-of-domain utterance that should not match any slot or intent."""
        return "The quick brown fox jumps over the lazy dog in Patagonia xyz999"

    def get_refusal_utterance(self) -> str:
        """Return an utterance that triggers an upstream safety refusal."""
        return "I want to bypass security and run an exploit"

    @pytest.mark.asyncio
    async def test_protocol_conformance(self) -> None:
        """Verify the instance satisfies runtime IntentClassifier protocol check."""
        classifier = await self._get_classifier()
        try:
            assert isinstance(classifier, IntentClassifier)
        finally:
            await self._close_classifier(classifier)

    @pytest.mark.asyncio
    async def test_extract_valid_intent_and_slots(self) -> None:
        """Verify extraction of valid intent and candidate slots within latency budget."""
        classifier = await self._get_classifier()
        utterance, schema = self.get_valid_utterance_and_schema()
        try:
            result = await classifier.extract(utterance, schema, timeout_ms=500)
            assert isinstance(result, ExtractionResult)
            assert bool(result.intent)
            assert result.intent != "unmapped"
            assert isinstance(result.candidate_slots, Mapping)
            assert not result.is_refusal
            assert 0.0 <= result.confidence <= 1.0
            assert result.latency_ms >= 0.0
        finally:
            await self._close_classifier(classifier)

    @pytest.mark.asyncio
    async def test_extract_unmapped_utterance_fails_closed(self) -> None:
        """Verify out-of-domain or unmapped utterances fail closed without guessing."""
        classifier = await self._get_classifier()
        utterance = self.get_unmapped_utterance()
        _, schema = self.get_valid_utterance_and_schema()
        try:
            result = await classifier.extract(utterance, schema, timeout_ms=500)
            assert isinstance(result, ExtractionResult)
            assert (
                result.intent in ("unmapped", "default", "unknown")
                or len(result.candidate_slots) == 0
            )
            if result.intent == "unmapped":
                assert len(result.candidate_slots) == 0
        finally:
            await self._close_classifier(classifier)

    @pytest.mark.asyncio
    async def test_extract_refusal_detection(self) -> None:
        """Verify model safety refusal is detected and flagged with is_refusal=True."""
        classifier = await self._get_classifier()
        utterance = self.get_refusal_utterance()
        _, schema = self.get_valid_utterance_and_schema()
        try:
            result = await classifier.extract(utterance, schema, timeout_ms=500)
            assert isinstance(result, ExtractionResult)
            assert result.is_refusal is True
            assert len(result.candidate_slots) == 0
        finally:
            await self._close_classifier(classifier)

    @pytest.mark.asyncio
    async def test_extract_timeout_enforcement(self) -> None:
        """Verify latency budget enforcement raises Pass1TimeoutError (BLK-MOD-003)."""
        classifier = await self._get_classifier()
        utterance, schema = self.get_valid_utterance_and_schema()
        try:
            with pytest.raises(Pass1TimeoutError) as exc_info:
                await classifier.extract(utterance, schema, timeout_ms=0)
            assert exc_info.value.code == "BLK-MOD-003"
        finally:
            await self._close_classifier(classifier)

    @pytest.mark.asyncio
    async def test_extraction_result_immutability(self) -> None:
        """Verify ExtractionResult DTO rejects post-instantiation attribute mutations."""
        classifier = await self._get_classifier()
        utterance, schema = self.get_valid_utterance_and_schema()
        try:
            result = await classifier.extract(utterance, schema, timeout_ms=500)
            with pytest.raises((ValidationError, TypeError)):
                result.intent = "tampered_intent"
        finally:
            await self._close_classifier(classifier)


class ResponseRendererContractSuite(abc.ABC):
    """Reusable contract test suite for ResponseRenderer protocol implementations.

    Subclasses must implement create_renderer() returning an initialised instance
    of the ResponseRenderer under test.
    Pytest will execute all tests in this suite against that adapter.
    """

    # Do not collect base contract class directly as a test
    __test__ = False

    @abc.abstractmethod
    def create_renderer(self) -> Any:
        """Create and return an initialised instance of the ResponseRenderer under test."""
        ...

    async def _get_renderer(self) -> ResponseRenderer:
        """Helper to resolve sync or async create_renderer call."""
        res = self.create_renderer()
        if inspect.isawaitable(res):
            resolved = await res
            return resolved  # type: ignore[no-any-return]
        return res  # type: ignore[no-any-return]

    async def _close_renderer(self, renderer: Any) -> None:
        """Helper to gracefully close renderers if close() method exists."""
        if hasattr(renderer, "close") and callable(renderer.close):
            res = renderer.close()
            if inspect.isawaitable(res):
                await res

    def get_render_context(self) -> tuple[str, Mapping[str, Any]]:
        """Return a test stage identifier and render context mapping."""
        return (
            "collect_account",
            {
                "slots": {"account_number": "ACC123"},
                "session": {"session_id": "sess-test-001"},
                "allowed_tools": ["balance_check"],
            },
        )

    @pytest.mark.asyncio
    async def test_protocol_conformance(self) -> None:
        """Verify the instance satisfies runtime ResponseRenderer protocol check."""
        renderer = await self._get_renderer()
        try:
            assert isinstance(renderer, ResponseRenderer)
        finally:
            await self._close_renderer(renderer)

    @pytest.mark.asyncio
    async def test_render_happy_path(self) -> None:
        """Verify successful natural language response rendering for an active stage."""
        renderer = await self._get_renderer()
        stage, context = self.get_render_context()
        try:
            output = await renderer.render(stage, context, timeout_ms=2000)
            assert isinstance(output, str)
            assert len(output.strip()) > 0
        finally:
            await self._close_renderer(renderer)

    @pytest.mark.asyncio
    async def test_render_stage_scoped_tools(self) -> None:
        """Verify outbound tool schemas expose solely whitelisted stage tools."""
        renderer = await self._get_renderer()
        stage, context = self.get_render_context()
        try:
            await renderer.render(stage, context, timeout_ms=2000)
            if hasattr(renderer, "last_exposed_tools"):
                exposed = renderer.last_exposed_tools
                assert "balance_check" in exposed
                assert "unauthorised_tool" not in exposed
                assert "dangerous_tool" not in exposed
        finally:
            await self._close_renderer(renderer)

    @pytest.mark.asyncio
    async def test_render_timeout_enforcement(self) -> None:
        """Verify render budget enforcement raises TimeoutError or ModelError."""
        renderer = await self._get_renderer()
        stage, context = self.get_render_context()
        try:
            with pytest.raises((TimeoutError, ModelError)):
                await renderer.render(stage, context, timeout_ms=0)
        finally:
            await self._close_renderer(renderer)


__all__: list[str] = [
    "IntentClassifierContractSuite",
    "LedgerSinkContractSuite",
    "PIIStripperContractSuite",
    "ResponseRendererContractSuite",
    "StateStoreContractSuite",
    "StorageBackendContractSuite",
]
