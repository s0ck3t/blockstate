"""Pytest configuration and shared fixtures for Blockstate Priority 1 (v1.1) E2E tests.

Provides path fixtures, subprocess CLI runners, sample agent sources,
cryptographic trace generators, and ephemeral network port finders.
Strict British English orthography is enforced throughout.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Return the absolute path to the repository root directory."""
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="session")
def brand_tokens_path(repo_root: Path) -> Path:
    """Return the path to marketing/brand/design-tokens.css."""
    return repo_root / "marketing" / "brand" / "design-tokens.css"


# ---------------------------------------------------------------------------
# Subprocess CLI Execution Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def cli_runner(repo_root: Path) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Return a callable that executes Blockstate CLI commands in the project environment."""

    def _run(
        *args: str, check: bool = False, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        src_path = str(repo_root / "src")
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{src_path};{repo_root};{existing_pythonpath}"
            if existing_pythonpath
            else f"{src_path};{repo_root}"
        )

        cmd = [sys.executable, "-m", "blockstate.cli.main", *args]
        return subprocess.run(
            cmd,
            cwd=str(cwd or repo_root),
            env=env,
            capture_output=True,
            text=True,
            check=check,
        )

    return _run


# ---------------------------------------------------------------------------
# Network Port Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def free_tcp_port() -> int:
    """Find and return an ephemeral free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return int(port)


# ---------------------------------------------------------------------------
# Canonical Agent Source Code Samples
# ---------------------------------------------------------------------------


@pytest.fixture
def banking_agent_source() -> str:
    """Return a canonical banking agent source adhering to Blockstate standards."""
    return '''"""Banking Transfer Agent with KYC Precursor Dominance."""

from typing import Annotated
from pydantic import BaseModel, Field
from blockstate import Agent, Stage, Transition
from blockstate.security import Vaulted

class TransferRequest(BaseModel):
    account_number: Annotated[str, Vaulted()]
    amount: float = Field(gt=0)
    recipient: str

class BankingAgent(Agent):
    """Enclave agent enforcing KYC verification dominance before transfer."""

    @Stage(initial=True, tools=["lookup_account"])
    def intake(self, user_msg: str) -> Transition["verify_kyc" | "reject"]:
        if "transfer" in user_msg.lower():
            return Transition.to("verify_kyc")
        return Transition.to("reject")

    @Stage(tools=["verify_identity_document", "check_sanctions"])
    def verify_kyc(self, user_msg: str) -> Transition["execute_transfer" | "reject"]:
        if "verified" in user_msg.lower():
            return Transition.to("execute_transfer")
        return Transition.to("reject")

    @Stage(tools=["settle_faster_payments"])
    def execute_transfer(self, user_msg: str) -> Transition["completed"]:
        return Transition.to("completed")

    @Stage(terminal=True)
    def reject(self, user_msg: str) -> Transition[None]:
        return Transition.end()

    @Stage(terminal=True)
    def completed(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''


@pytest.fixture
def insurance_pushdown_source() -> str:
    """Return an insurance claims agent source with a pushdown digression handler."""
    return '''"""Insurance Claims Agent with TaskStack Pushdown Digression."""

from blockstate import Agent, Stage, Transition

class InsuranceAgent(Agent):
    """Enclave agent handling claims and policy inquiries via TaskStack pushdown."""

    @Stage(initial=True, allow_digressions=True, tools=["lookup_policy"])
    def file_claim(self, user_msg: str) -> Transition["verify_policy" | "policy_faq"]:
        if "question" in user_msg.lower():
            return Transition.to("policy_faq")
        return Transition.to("verify_policy")

    @Stage(tools=["check_coverage"])
    def verify_policy(self, user_msg: str) -> Transition["assess_damage"]:
        return Transition.to("assess_damage")

    @Stage(tools=["estimate_cost"])
    def assess_damage(self, user_msg: str) -> Transition["settle_claim"]:
        return Transition.to("settle_claim")

    @Stage(terminal=True, tools=["issue_payout"])
    def settle_claim(self, user_msg: str) -> Transition[None]:
        return Transition.end()

    @Stage(tools=["answer_policy_question"])
    def policy_faq(self, user_msg: str) -> Transition[None]:
        return Transition.pop_frame()
'''


@pytest.fixture
def bypass_vulnerable_agent_source() -> str:
    """Return an agent with an unauthenticated bypass shortcut past the precursor."""
    return '''"""Vulnerable Agent with Unauthenticated Shortcut Past Precursor."""

from blockstate import Agent, Stage, Transition

class BypassAgent(Agent):
    """Agent containing a bypass path where target can be reached without precursor."""

    @Stage(initial=True)
    def intake(self, user_msg: str) -> Transition["verify_kyc" | "fast_track_transfer"]:
        if "vip" in user_msg.lower():
            return Transition.to("fast_track_transfer")
        return Transition.to("verify_kyc")

    @Stage
    def verify_kyc(self, user_msg: str) -> Transition["execute_transfer"]:
        return Transition.to("execute_transfer")

    @Stage
    def fast_track_transfer(self, user_msg: str) -> Transition["execute_transfer"]:
        return Transition.to("execute_transfer")

    @Stage(terminal=True)
    def execute_transfer(self, user_msg: str) -> Transition[None]:
        return Transition.end()
'''


# ---------------------------------------------------------------------------
# Trace Generation Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_trace_directory(tmp_path: Path) -> Path:
    """Create a temporary directory containing valid turn records in .blockstate/traces.jsonl."""
    trace_dir = tmp_path / ".blockstate"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_file = trace_dir / "traces.jsonl"

    session_id = "sess_e2e_test_001"
    genesis_hash = "0" * 64

    # Build turn 0
    t0_data = {
        "session_id": session_id,
        "turn_index": 0,
        "stage": "intake",
        "user_message": "I want to transfer funds",
        "exposed_tools": ["lookup_account"],
        "task_stack": ["intake"],
        "prev_record_hash": genesis_hash,
    }
    t0_bytes = json.dumps(t0_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    t0_hash = hashlib.sha256(t0_bytes).hexdigest()
    t0_data["record_hash"] = t0_hash

    # Build turn 1
    t1_data = {
        "session_id": session_id,
        "turn_index": 1,
        "stage": "verify_kyc",
        "user_message": "Here is my passport verification",
        "exposed_tools": ["verify_identity_document", "check_sanctions"],
        "task_stack": ["verify_kyc"],
        "prev_record_hash": t0_hash,
    }
    t1_bytes = json.dumps(t1_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    t1_hash = hashlib.sha256(t1_bytes).hexdigest()
    t1_data["record_hash"] = t1_hash

    # Build turn 2
    t2_data = {
        "session_id": session_id,
        "turn_index": 2,
        "stage": "execute_transfer",
        "user_message": "Confirm payment",
        "exposed_tools": ["settle_faster_payments"],
        "task_stack": ["execute_transfer"],
        "prev_record_hash": t1_hash,
    }
    t2_bytes = json.dumps(t2_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    t2_hash = hashlib.sha256(t2_bytes).hexdigest()
    t2_data["record_hash"] = t2_hash

    lines = [
        json.dumps(t0_data),
        json.dumps(t1_data),
        json.dumps(t2_data),
    ]
    trace_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path
