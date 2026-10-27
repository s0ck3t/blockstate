"""Blockstate security components and zero-leakage guards."""

from blockstate.security.annotations import (
    Detokenise,
    DetokeniseMarker,
    Vaulted,
    VaultedMarker,
    get_detokenise_inner_type,
    get_vaulted_inner_type,
    is_detokenise,
    is_vaulted,
)
from blockstate.security.git_guard import (
    Violation,
    is_blocked_filename,
    main,
    scan_file,
    scan_text,
)
from blockstate.security.pii_patterns import (
    PIIMatch,
    detect_pii_spans,
    validate_luhn,
    validate_nhs_mod11,
    validate_ssn,
)
from blockstate.security.vault import (
    PIIVault,
    VaultCipher,
)

__all__: list[str] = [
    "Detokenise",
    "DetokeniseMarker",
    "PIIMatch",
    "PIIVault",
    "VaultCipher",
    "Vaulted",
    "VaultedMarker",
    "Violation",
    "detect_pii_spans",
    "get_detokenise_inner_type",
    "get_vaulted_inner_type",
    "is_blocked_filename",
    "is_detokenise",
    "is_vaulted",
    "main",
    "scan_file",
    "scan_text",
    "validate_luhn",
    "validate_nhs_mod11",
    "validate_ssn",
]
