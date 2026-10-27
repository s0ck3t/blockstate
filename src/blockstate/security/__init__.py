"""Blockstate security components and zero-leakage guards."""

from blockstate.security.git_guard import (
    Violation,
    is_blocked_filename,
    main,
    scan_file,
    scan_text,
)

__all__ = [
    "Violation",
    "is_blocked_filename",
    "main",
    "scan_file",
    "scan_text",
]
