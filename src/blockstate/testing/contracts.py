"""Reusable contract test suites for verifying port protocol implementations.

Provides PIIStripperContractSuite for verifying that any PIIStripper protocol
adapter adheres strictly to zero-leakage boundaries, deterministic session
tokenisation, mathematical checksums, and edge-case invariants.
"""

import abc
from typing import Any

import pytest

from blockstate.ports.security import PIIStripper


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
