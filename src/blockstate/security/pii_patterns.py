"""Pure regular expression patterns and checksum detectors for sensitive PII entities.

Provides zero-dependency UK and US pattern matching and mathematical checksum
validation for National Insurance numbers (NINo), NHS numbers (Modulus 11),
US Social Security numbers (SSN), payment cards (Luhn algorithm), email addresses,
telephone numbers, and postal codes.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

# Existing vault token pattern to prevent re-sanitising or matching inside tokens
VAULT_TOKEN_PATTERN = re.compile(r"<VAULT:[A-Z0-9_]+>")

# Category priorities for resolving overlapping spans (lower numerical value = higher priority)
CATEGORY_PRIORITY: dict[str, int] = {
    "EMAIL": 10,
    "CARD": 20,
    "NHS": 30,
    "NINO": 40,
    "SSN": 50,
    "PHONE": 60,
    "POSTCODE": 70,
}

# 1. UK National Insurance Number (NINo)
# Allows standard formats including HMRC test prefix QQ
NINO_PATTERN = re.compile(
    r"\b([A-Z]{2}\s?(?:\d{6}|\d{2}\s?\d{2}\s?\d{2})\s?[A-D])\b",
    re.IGNORECASE,
)

# 2. UK NHS Number (10 digits with optional spaces or hyphens)
NHS_PATTERN = re.compile(r"\b(\d{3}[\s-]?\d{3}[\s-]?\d{4})\b")

# 3. Payment Cards (13 to 19 digits starting and ending with digit)
CARD_PATTERN = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# 4. US Social Security Number (SSN) (Formatted 3-2-4 digits)
SSN_PATTERN = re.compile(r"\b(\d{3}-\d{2}-\d{4})\b")

# 5. Email addresses
EMAIL_PATTERN = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

# 6. Telephone numbers (UK, US, and international formats)
PHONE_PATTERN = re.compile(
    r"""
    (?<!\w)
    (?:
        # International format with +
        (?:\+\d{1,3}[\s.-]?(?:\(\d{1,5}\)|\d{1,5})[\s.-]?\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{1,4})?)
        |
        # UK format starting with 01, 02, 03, 07, 08, 09
        (?:0[123789]\d{1,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{1,4})?)
        |
        # US with 1- prefix
        (?:1[\s.-]?\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4})
        |
        # US or regional formatted with parentheses e.g. (020) or (555)
        (?:\([0-9]{2,5}\)[\s.-]?\d{3,4}[\s.-]?\d{3,4})
        |
        # US formatted e.g. 555-123-4567 or 555.123.4567
        (?:[2-9]\d{2}[-.\s]\d{3}[-.\s]\d{4})
        |
        # US unformatted 10-digit e.g. 2025550143
        (?:[2-9]\d{9})
    )
    (?!\w)
    """,
    re.VERBOSE,
)

# 7. UK Postal codes and US ZIP codes (5-digit / ZIP+4)
POSTCODE_PATTERN = re.compile(
    r"\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}|\d{5}(?:-\d{4})?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PIIMatch:
    """Detected personally identifiable information (PII) entity span."""

    category: str
    plaintext: str
    start: int
    end: int


def validate_nhs_mod11(candidate: str) -> bool:
    """Validate a 10-digit UK NHS number using the Modulus 11 algorithm.

    The first 9 digits are multiplied by descending weights from 10 to 2.
    The remainder modulo 11 is subtracted from 11 to yield the check digit.
    A calculated check digit of 11 represents 0; a check digit of 10 is invalid.
    """
    digits = [c for c in candidate if c.isdigit()]
    if len(digits) != 10:
        return False

    int_digits = [int(c) for c in digits]
    total = sum(int_digits[i] * (10 - i) for i in range(9))
    remainder = total % 11
    check_digit = 11 - remainder

    if check_digit == 11:
        check_digit = 0
    elif check_digit == 10:
        return False

    return check_digit == int_digits[9]


def validate_luhn(candidate: str) -> bool:
    """Validate payment card numbers using the standard Luhn (Mod 10) algorithm.

    Accepts digit strings of length 13 to 19. Doubles every second digit
    from right to left and validates the resulting checksum modulo 10.
    """
    digits = [c for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    int_digits = [int(c) for c in digits]
    total = 0
    reversed_digits = int_digits[::-1]

    for index, digit in enumerate(reversed_digits):
        if index % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit

    return total % 10 == 0


def validate_ssn(candidate: str) -> bool:
    """Validate US Social Security Number structural rules.

    Checks area number is not 000, 666, or 900-999, group number is not 00,
    and serial number is not 0000.
    """
    parts = candidate.split("-")
    if len(parts) != 3:
        return False

    area, group, serial = parts
    if not (len(area) == 3 and len(group) == 2 and len(serial) == 4):
        return False
    if not (area.isdigit() and group.isdigit() and serial.isdigit()):
        return False

    area_int = int(area)
    if area_int == 0 or area_int == 666 or (900 <= area_int <= 999):
        return False
    if int(group) == 0:
        return False
    return int(serial) != 0


def detect_nino(text: str) -> list[PIIMatch]:
    """Detect UK National Insurance numbers in text."""
    matches: list[PIIMatch] = []
    for match in NINO_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                category="NINO",
                plaintext=match.group(1),
                start=match.start(1),
                end=match.end(1),
            )
        )
    return matches


def detect_nhs(text: str) -> list[PIIMatch]:
    """Detect UK NHS numbers passing Modulus 11 validation in text."""
    matches: list[PIIMatch] = []
    for match in NHS_PATTERN.finditer(text):
        raw = match.group(1)
        if validate_nhs_mod11(raw):
            matches.append(
                PIIMatch(
                    category="NHS",
                    plaintext=raw,
                    start=match.start(1),
                    end=match.end(1),
                )
            )
    return matches


def detect_card(text: str) -> list[PIIMatch]:
    """Detect payment card numbers passing Luhn validation in text."""
    matches: list[PIIMatch] = []
    for match in CARD_PATTERN.finditer(text):
        raw = match.group(0).strip()
        if validate_luhn(raw):
            matches.append(
                PIIMatch(
                    category="CARD",
                    plaintext=raw,
                    start=match.start(),
                    end=match.end(),
                )
            )
    return matches


def detect_ssn(text: str) -> list[PIIMatch]:
    """Detect US Social Security Numbers matching format and group rules."""
    matches: list[PIIMatch] = []
    for match in SSN_PATTERN.finditer(text):
        raw = match.group(1)
        if validate_ssn(raw):
            matches.append(
                PIIMatch(
                    category="SSN",
                    plaintext=raw,
                    start=match.start(1),
                    end=match.end(1),
                )
            )
    return matches


def detect_email(text: str) -> list[PIIMatch]:
    """Detect email addresses in text."""
    matches: list[PIIMatch] = []
    for match in EMAIL_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                category="EMAIL",
                plaintext=match.group(1),
                start=match.start(1),
                end=match.end(1),
            )
        )
    return matches


def detect_phone(text: str) -> list[PIIMatch]:
    """Detect UK, US, and international telephone numbers in text."""
    matches: list[PIIMatch] = []
    for match in PHONE_PATTERN.finditer(text):
        raw = match.group(0).strip()
        digits_only = [c for c in raw if c.isdigit()]
        if 10 <= len(digits_only) <= 15:
            matches.append(
                PIIMatch(
                    category="PHONE",
                    plaintext=raw,
                    start=match.start(),
                    end=match.end(),
                )
            )
    return matches


def detect_postcode(text: str) -> list[PIIMatch]:
    """Detect UK postal codes and US ZIP codes in text."""
    matches: list[PIIMatch] = []
    for match in POSTCODE_PATTERN.finditer(text):
        matches.append(
            PIIMatch(
                category="POSTCODE",
                plaintext=match.group(1),
                start=match.start(1),
                end=match.end(1),
            )
        )
    return matches


def detect_pii_spans(
    text: str,
    categories: Sequence[str] | None = None,
) -> list[PIIMatch]:
    """Detect all non-overlapping PII spans in text across enabled categories.

    Resolves overlapping candidate spans by prioritising longer spans first,
    followed by category priority. Protects pre-existing vault tokens (<VAULT:...>)
    from mutation.
    """
    if not text:
        return []

    # Identify protected spans occupied by pre-existing vault tokens
    protected_spans: list[tuple[int, int]] = [
        (m.start(), m.end()) for m in VAULT_TOKEN_PATTERN.finditer(text)
    ]

    selected_categories = {c.upper() for c in categories} if categories is not None else None

    candidates: list[PIIMatch] = []

    if selected_categories is None or "EMAIL" in selected_categories:
        candidates.extend(detect_email(text))
    if selected_categories is None or "CARD" in selected_categories:
        candidates.extend(detect_card(text))
    if selected_categories is None or "NHS" in selected_categories:
        candidates.extend(detect_nhs(text))
    if selected_categories is None or "NINO" in selected_categories:
        candidates.extend(detect_nino(text))
    if selected_categories is None or "SSN" in selected_categories:
        candidates.extend(detect_ssn(text))
    if selected_categories is None or "PHONE" in selected_categories:
        candidates.extend(detect_phone(text))
    if selected_categories is None or "POSTCODE" in selected_categories:
        candidates.extend(detect_postcode(text))

    # Filter candidates that intersect with protected existing vault tokens
    valid_candidates: list[PIIMatch] = []
    for cand in candidates:
        intersects_protected = any(
            not (cand.end <= prot_start or cand.start >= prot_end)
            for prot_start, prot_end in protected_spans
        )
        if not intersects_protected:
            valid_candidates.append(cand)

    # Sort candidates to prioritise:
    # 1. Longer span length (descending)
    # 2. Category priority rank (ascending)
    # 3. Start position (ascending)
    valid_candidates.sort(
        key=lambda c: (
            -(c.end - c.start),
            CATEGORY_PRIORITY.get(c.category, 100),
            c.start,
        )
    )

    # Discard overlapping spans greedily
    accepted: list[PIIMatch] = []
    for cand in valid_candidates:
        overlaps = any(
            not (cand.end <= acc.start or cand.start >= acc.end)
            for acc in accepted
        )
        if not overlaps:
            accepted.append(cand)

    # Return accepted spans sorted in text appearance order
    accepted.sort(key=lambda c: c.start)
    return accepted
