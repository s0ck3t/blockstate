"""Pre-commit PII and credential security scanner.

Enforces zero-leakage security boundaries across git staging and pre-commit hooks,
blocking raw PII patterns (UK NINo, NHS, US SSN, credit cards) and secret tokens
(OpenAI keys, AWS keys, Bearer tokens) from entering the codebase.
"""

import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Violation:
    """Represents a detected security violation in text or file."""

    filename: str
    line_number: int
    rule: str
    snippet: str

    def __str__(self) -> str:
        loc = f"{self.filename}:{self.line_number}" if self.filename else f"line {self.line_number}"
        return f"[{self.rule}] {loc}: {self.snippet}"


# Blocked file extensions and path patterns
BLOCKED_EXTENSIONS = {".wal", ".db", ".sqlite", ".pem", ".key", ".db-wal", ".db-shm"}
ALLOWED_ENV_NAMES = {".env.example", ".env.template"}

# Regular expression patterns for PII and credential detection
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # UK National Insurance Number (NINo)
    (
        "UK NINo",
        re.compile(
            r"\b[A-Z]{2}\s?(?:\d{6}|\d{2}\s?\d{2}\s?\d{2})\s?[A-D]\b",
            re.IGNORECASE,
        ),
    ),
    # UK NHS Number (10 digits, formatted or unformatted)
    (
        "UK NHS Number",
        re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b"),
    ),
    # US Social Security Number (SSN)
    (
        "US SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    # Payment Cards (Visa, Mastercard, Amex)
    (
        "Credit Card",
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    ),
    # Bearer Token
    (
        "Bearer Token",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b"),
    ),
    # OpenAI API Key (supporting standard and sk-proj- project keys)
    (
        "OpenAI API Key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ),
    # AWS Access Key ID
    (
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    # AWS Secret Access Key
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
]


def is_blocked_filename(path: str | Path) -> bool:
    """Check whether a path or filename violates zero-leakage file rules."""
    p = Path(path)
    filename = p.name.lower()
    path_str = p.as_posix().lower()

    # Block files inside .blockstate/ directory or parts
    if ".blockstate" in p.parts or ".blockstate/" in path_str or path_str.startswith(".blockstate"):
        return True

    # Check blocked extensions
    if p.suffix.lower() in BLOCKED_EXTENSIONS or any(
        filename.endswith(ext) for ext in BLOCKED_EXTENSIONS
    ):
        return True

    # Check .env naming conventions
    return (
        filename.startswith(".env") or filename.endswith(".env") or ".env." in filename
    ) and filename not in ALLOWED_ENV_NAMES


def _is_safe_snippet(matched_str: str) -> bool:
    """Filter out known synthetic test placeholders, masks, or template values."""
    lower = matched_str.lower()
    return (
        "change_me" in lower
        or "**********" in lower
        or "<vault:" in lower
        or "placeholder" in lower
        or "dummy_token" in lower
    )


def scan_text(text: str, filename: str = "") -> list[Violation]:
    """Scan raw text for PII, credentials, or sensitive token patterns."""
    violations: list[Violation] = []
    lines = text.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for rule_name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                matched_val = match.group(0)
                if _is_safe_snippet(matched_val):
                    continue
                # Mask snippet in violation output
                if len(matched_val) > 8:
                    masked = matched_val[:4] + "..." + matched_val[-2:]
                else:
                    masked = matched_val[:2] + "..."  # pragma: no cover
                violations.append(
                    Violation(
                        filename=filename,
                        line_number=line_idx,
                        rule=rule_name,
                        snippet=f"Detected potential {rule_name} pattern ({masked})",
                    )
                )

    return violations


def scan_file(path: str | Path) -> list[Violation]:
    """Scan a file path and its contents for zero-leakage security violations."""
    p = Path(path)
    if not p.exists():
        return []

    file_str = p.as_posix()

    if is_blocked_filename(p):
        return [
            Violation(
                filename=file_str,
                line_number=1,
                rule="Blocked Sensitive File",
                snippet=f"File path '{file_str}' is forbidden by zero-leakage security policy",
            )
        ]

    if not p.is_file():
        return []

    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [
            Violation(
                filename=file_str,
                line_number=1,
                rule="File Read Error",
                snippet=f"Unable to read file: {exc}",
            )
        ]

    return scan_text(text, filename=file_str)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for blockstate-pii-guard pre-commit scanner."""
    args = list(argv if argv is not None else sys.argv[1:])
    all_violations: list[Violation] = []

    for target in args:
        violations = scan_file(target)
        all_violations.extend(violations)

    if all_violations:
        sys.stderr.write(
            f"[Zero-Leakage Security Gate] Found {len(all_violations)} violation(s):\n"
        )
        for v in all_violations:
            sys.stderr.write(f"  - {v}\n")
        sys.stderr.write(
            "\nPlease sanitise credentials or PII before committing to the repository.\n"
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
