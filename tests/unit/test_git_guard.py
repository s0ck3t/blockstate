"""Unit tests for blockstate-pii-guard git security scanner."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from blockstate.security.git_guard import (
    Violation,
    _is_safe_snippet,
    is_blocked_filename,
    main,
    scan_file,
    scan_text,
)


def test_scan_text_clean_returns_zero_violations() -> None:
    """Verify clean source code yields zero violations."""
    clean_code = """
    def compute_sum(a: int, b: int) -> int:
        \"\"\"Compute total sum of two integers.\"\"\"
        return a + b
    """
    assert scan_text(clean_code) == []


def test_scan_text_synthetic_and_masked_placeholders_ignored() -> None:
    """Verify synthetic test tokens, masked secrets, and CHANGE_ME tokens are bypassed."""
    text_with_safe_patterns = """
    VAULT_TOKEN = "<VAULT:NINO_01>"
    DEFAULT_KEY = "CHANGE_ME_GENERATE_32_BYTE_BASE64_KEY_FOR_AES256_GCM"
    MASKED = "**********"
    AUTH_HEADER = "Authorization: Bearer CHANGE_ME_JWT_TOKEN_12345678901234567890"
    """
    assert scan_text(text_with_safe_patterns) == []

    # Verify helper directly
    assert _is_safe_snippet("prefix_change_me_suffix") is True
    assert _is_safe_snippet("prefix_**********_suffix") is True
    assert _is_safe_snippet("prefix_<vault:nino_01>_suffix") is True
    assert _is_safe_snippet("placeholder_key_value") is True
    assert _is_safe_snippet("regular_token_value") is False


def test_scan_text_detects_uk_nino() -> None:
    """Verify raw UK National Insurance Number is detected and flagged."""
    text = "The applicant NINo is QQ123456C as verified."
    violations = scan_text(text, filename="applicant.txt")

    assert len(violations) == 1
    assert violations[0].rule == "UK NINo"
    assert violations[0].line_number == 1
    assert "UK NINo pattern" in violations[0].snippet


def test_scan_text_detects_uk_nhs_number() -> None:
    """Verify UK NHS Number is detected across formatted, hyphenated, and unformatted inputs."""
    text = """
    Formatted NHS: 987 654 3210
    Hyphenated NHS: 987-654-3210
    Unformatted NHS: 9876543210
    """
    violations = scan_text(text)

    assert len(violations) == 3
    assert all(v.rule == "UK NHS Number" for v in violations)


def test_scan_text_detects_us_ssn() -> None:
    """Verify raw US Social Security Number is detected and flagged."""
    text = "Customer SSN: 123-45-6789 provided on form."
    violations = scan_text(text)

    assert len(violations) == 1
    assert violations[0].rule == "US SSN"


def test_scan_text_detects_credit_cards() -> None:
    """Verify payment card patterns are detected across major card schemes."""
    cards_text = """
    Visa: 4111111111111111
    Mastercard: 5500000000000004
    Amex: 378282246310005
    """
    violations = scan_text(cards_text)
    assert len(violations) == 3
    assert all(v.rule == "Credit Card" for v in violations)


def test_scan_text_detects_api_tokens_and_credentials() -> None:
    """Verify OpenAI keys (including sk-proj-), Bearer tokens, and AWS credentials are flagged."""
    secrets_text = """
    Authorization: Bearer dXNlcl9zZXNzaW9uX3Rva2VuXzEyMzQ1Njc4OTA=
    OPENAI_API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    OPENAI_PROJ_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz_ABCD-1234"
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    """
    violations = scan_text(secrets_text)
    rules_detected = {v.rule for v in violations}

    assert "Bearer Token" in rules_detected
    assert "OpenAI API Key" in rules_detected
    assert "AWS Access Key ID" in rules_detected
    assert "AWS Secret Access Key" in rules_detected


@pytest.mark.parametrize(
    ("path", "expected_blocked"),
    [
        (".env", True),
        (".env.local", True),
        (".env.production", True),
        ("config/.env", True),
        (".env.example", False),
        (".env.template", False),
        (".blockstate/state.db", True),
        ("nested/.blockstate/session.json", True),
        ("data/audit.wal", True),
        ("data/state.db-wal", True),
        ("data/state.db-shm", True),
        ("sqlite/local.sqlite", True),
        ("certs/cert.pem", True),
        ("keys/private.key", True),
        ("src/blockstate/config.py", False),
        ("README.md", False),
    ],
)
def test_is_blocked_filename(path: str, expected_blocked: bool) -> None:
    """Verify blocked filename rules identify sensitive and storage files."""
    assert is_blocked_filename(path) == expected_blocked


def test_scan_file_blocked_filename(tmp_path: Path) -> None:
    """Verify scanning a forbidden file path immediately returns a violation."""
    forbidden_file = tmp_path / ".env.local"
    forbidden_file.write_text("SOME_SECRET=123", encoding="utf-8")

    violations = scan_file(forbidden_file)
    assert len(violations) == 1
    assert violations[0].rule == "Blocked Sensitive File"


def test_scan_file_clean_file(tmp_path: Path) -> None:
    """Verify scanning a clean file returns zero violations."""
    clean_file = tmp_path / "service.py"
    clean_file.write_text("x = 42\n", encoding="utf-8")

    assert scan_file(clean_file) == []


def test_scan_file_non_existent_file() -> None:
    """Verify scanning non-existent file path returns empty list without error."""
    assert scan_file(Path("non_existent_file_path.py")) == []


def test_scan_file_deleted_blocked_file_does_not_flag(tmp_path: Path) -> None:
    """Verify deleted blocked file (non-existent on disk) produces zero violations."""
    deleted_blocked = tmp_path / ".env"
    assert not deleted_blocked.exists()
    assert scan_file(deleted_blocked) == []


def test_scan_file_read_error(tmp_path: Path) -> None:
    """Verify file read failure returns diagnostic File Read Error violation."""
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("content", encoding="utf-8")

    with patch.object(Path, "read_text", side_effect=OSError("Disk failure")):
        violations = scan_file(broken_file)

    assert len(violations) == 1
    assert violations[0].rule == "File Read Error"


def test_main_cli_clean_files(tmp_path: Path) -> None:
    """Verify main returns exit code 0 when all targets are clean."""
    clean_file = tmp_path / "main.py"
    clean_file.write_text("print('clean')\n", encoding="utf-8")

    exit_code = main([str(clean_file)])
    assert exit_code == 0


def test_main_cli_violating_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify main returns exit code 1 and writes diagnostic warnings to stderr."""
    pii_file = tmp_path / "data.py"
    pii_file.write_text("nino = 'QQ123456C'\n", encoding="utf-8")

    exit_code = main([str(pii_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "[Zero-Leakage Security Gate]" in captured.err
    assert "UK NINo" in captured.err


def test_main_cli_empty_args() -> None:
    """Verify main returns 0 when no target arguments are supplied."""
    assert main([]) == 0


def test_main_cli_reads_sys_argv(tmp_path: Path) -> None:
    """Verify main defaults to sys.argv[1:] when argv is None."""
    clean_file = tmp_path / "sys_target.py"
    clean_file.write_text("clean = True\n", encoding="utf-8")

    with patch("sys.argv", ["blockstate-pii-guard", str(clean_file)]):
        exit_code = main()

    assert exit_code == 0


def test_violation_string_representation() -> None:
    """Verify Violation string formatting with and without filename."""
    v_with_file = Violation(
        filename="auth.py",
        line_number=10,
        rule="UK NINo",
        snippet="Detected NINo",
    )
    assert str(v_with_file) == "[UK NINo] auth.py:10: Detected NINo"

    v_without_file = Violation(filename="", line_number=5, rule="US SSN", snippet="Detected SSN")
    assert str(v_without_file) == "[US SSN] line 5: Detected SSN"


def test_pre_commit_config_syntax_valid() -> None:
    """Verify .pre-commit-config.yaml parses with PyYAML without syntax error."""
    config_file = Path(".pre-commit-config.yaml")
    assert config_file.is_file()
    data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "repos" in data
    assert len(data["repos"]) >= 5
