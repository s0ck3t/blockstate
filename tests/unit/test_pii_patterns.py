"""Unit tests for PII regex patterns and mathematical checksum detectors."""

from blockstate.security.pii_patterns import (
    PIIMatch,
    detect_card,
    detect_email,
    detect_nhs,
    detect_nino,
    detect_phone,
    detect_pii_spans,
    detect_postcode,
    detect_ssn,
    validate_luhn,
    validate_nhs_mod11,
    validate_ssn,
)


def test_validate_nhs_mod11() -> None:
    """Verify UK NHS number Modulus 11 validation."""
    # 9876543210 -> sum = 330, rem = 0, check = 11 - 0 = 11 -> 0 == d10 -> True
    assert validate_nhs_mod11("9876543210") is True
    assert validate_nhs_mod11("987 654 3210") is True
    assert validate_nhs_mod11("987-654-3210") is True

    # 9434765919 -> check digit 9 -> True
    assert validate_nhs_mod11("9434765919") is True

    # Invalid check digit
    assert validate_nhs_mod11("1234567890") is False

    # Invalid lengths
    assert validate_nhs_mod11("123") is False
    assert validate_nhs_mod11("12345678901234") is False

    # Check digit calculating to 10 (remainder 1 -> 11 - 1 = 10, strictly invalid in NHS)
    # Digits with total % 11 == 1: e.g. 000000001? 1 * 2 = 2.
    # Let's construct a sequence where sum % 11 == 1:
    # 0 0 0 0 0 0 0 4 0 -> 4 * 3 = 12 % 11 = 1.
    # Total is 12, remainder is 1, check = 10 -> False.
    assert validate_nhs_mod11("0000000405") is False


def test_validate_luhn() -> None:
    """Verify payment card Luhn (Mod 10) checksum algorithm."""
    # Valid 16-digit card
    assert validate_luhn("4532015012345671") is True
    assert validate_luhn("4532 0150 1234 5671") is True
    assert validate_luhn("4532-0150-1234-5671") is True

    # Invalid 16-digit card
    assert validate_luhn("4532015012345672") is False

    # Bounds check on length (13 to 19 digits)
    assert validate_luhn("123456") is False
    assert validate_luhn("1" * 20) is False


def test_validate_ssn() -> None:
    """Verify US Social Security Number validation rules."""
    assert validate_ssn("123-45-6789") is True
    assert validate_ssn("000-12-3456") is False  # Area 000
    assert validate_ssn("666-12-3456") is False  # Area 666
    assert validate_ssn("900-12-3456") is False  # Area 900+
    assert validate_ssn("950-12-3456") is False
    assert validate_ssn("123-00-4567") is False  # Group 00
    assert validate_ssn("123-45-0000") is False  # Serial 0000
    assert validate_ssn("123456789") is False    # Missing dashes
    assert validate_ssn("12-345-6789") is False
    assert validate_ssn("abc-de-fghi") is False


def test_detect_nino() -> None:
    """Verify UK National Insurance number detection."""
    text = "User NINo is QQ123456C and secondary is ab 12 34 56 d"
    matches = detect_nino(text)
    assert len(matches) == 2
    assert matches[0] == PIIMatch("NINO", "QQ123456C", 13, 22)
    assert matches[1].category == "NINO"
    assert matches[1].plaintext == "ab 12 34 56 d"


def test_detect_nhs() -> None:
    """Verify UK NHS number detection and Modulus 11 gating."""
    text = "Valid NHS 987 654 3210 and invalid NHS 123 456 7890"
    matches = detect_nhs(text)
    assert len(matches) == 1
    assert matches[0] == PIIMatch("NHS", "987 654 3210", 10, 22)


def test_detect_card() -> None:
    """Verify payment card detection and Luhn gating."""
    text = "Valid card 4532015012345671 and invalid card 4532015012345672"
    matches = detect_card(text)
    assert len(matches) == 1
    assert matches[0] == PIIMatch("CARD", "4532015012345671", 11, 27)


def test_detect_ssn() -> None:
    """Verify US SSN detection."""
    text = "Valid SSN 123-45-6789 and invalid SSN 000-12-3456"
    matches = detect_ssn(text)
    assert len(matches) == 1
    assert matches[0] == PIIMatch("SSN", "123-45-6789", 10, 21)


def test_detect_email() -> None:
    """Verify email address detection."""
    text = "Contact support@example.co.uk or admin.test+alert@sub.example.com"
    matches = detect_email(text)
    assert len(matches) == 2
    assert matches[0].plaintext == "support@example.co.uk"
    assert matches[1].plaintext == "admin.test+alert@sub.example.com"


def test_detect_phone() -> None:
    """Verify phone detection and date exclusion."""
    text = "Call +44 7911 123456 or 07911 123456 or (020) 7946 0999. Date: 2026-10-27"
    matches = detect_phone(text)
    assert len(matches) == 3
    assert matches[0].plaintext == "+44 7911 123456"
    assert matches[1].plaintext == "07911 123456"
    assert matches[2].plaintext == "(020) 7946 0999"


def test_detect_postcode() -> None:
    """Verify UK postcode detection."""
    text = "Postcodes: SW1A 1AA, EC1A 1BB, W1A 0AX, M1 1AE, B33 8TH, CR2 6XH, DN55 1PT"
    matches = detect_postcode(text)
    assert len(matches) == 7
    assert matches[0].plaintext == "SW1A 1AA"
    assert matches[1].plaintext == "EC1A 1BB"


def test_detect_pii_spans_empty_and_filtering() -> None:
    """Verify combined detection handles empty strings and category filtering."""
    assert detect_pii_spans("") == []

    text = "NINo QQ123456C and email test@example.com"
    nino_only = detect_pii_spans(text, categories=["NINO"])
    assert len(nino_only) == 1
    assert nino_only[0].category == "NINO"

    email_only = detect_pii_spans(text, categories=["EMAIL"])
    assert len(email_only) == 1
    assert email_only[0].category == "EMAIL"


def test_detect_pii_spans_pre_existing_vault_token_protection() -> None:
    """Verify pre-existing <VAULT:...> tokens are not matched or mutated."""
    text = "Already vaulted token <VAULT:POSTCODE_01> and NINo QQ123456C"
    matches = detect_pii_spans(text)
    assert len(matches) == 1
    assert matches[0].category == "NINO"
    assert matches[0].plaintext == "QQ123456C"


def test_detect_us_zip_codes() -> None:
    """Verify US 5-digit and ZIP+4 postal code detection."""
    text = "Beverly Hills 90210, White House 20500-0001, and NY 10001"
    matches = detect_postcode(text)
    assert len(matches) == 3
    assert matches[0] == PIIMatch("POSTCODE", "90210", 14, 19)
    assert matches[1] == PIIMatch("POSTCODE", "20500-0001", 33, 43)
    assert matches[2] == PIIMatch("POSTCODE", "10001", 52, 57)

    # In combined detect_pii_spans
    spans = detect_pii_spans(text)
    assert len(spans) == 3
    assert all(s.category == "POSTCODE" for s in spans)


def test_detect_us_unformatted_phone_numbers() -> None:
    """Verify unformatted 10-digit US phone numbers matching NANP rules."""
    text = "Call 2025550143 or 2125551234 for assistance"
    matches = detect_phone(text)
    assert len(matches) == 2
    assert matches[0] == PIIMatch("PHONE", "2025550143", 5, 15)
    assert matches[1] == PIIMatch("PHONE", "2125551234", 19, 29)

    # Should not match 16-digit payment cards or 10-digit numbers starting with 1
    non_phone = "Card 4532015012345671 and invalid 1234567890"
    matches_non = detect_phone(non_phone)
    assert len(matches_non) == 0
