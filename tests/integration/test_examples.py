"""Integration tests executing and verifying all four reference agents in examples/."""

import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from blockstate.cli.main import app

runner = CliRunner()


@pytest.mark.parametrize(
    "example_script",
    [
        "examples/01_motor_insurance_claim.py",
        "examples/02_banking_kyc_dominator.py",
        "examples/03_healthcare_hipaa_vault.py",
        "examples/04_langchain_subflow_handoff.py",
        "examples/05_motor_insurance_claim_live.py",
    ],
)
def test_reference_agent_execution(example_script: str) -> None:
    """Verify that each domain reference agent runs to completion with exit code 0."""
    script_path = Path(example_script)
    assert script_path.exists(), f"Example script not found: {example_script}"

    proc = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, (
        f"Execution failed for {example_script}:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "Completed Successfully" in proc.stdout


@pytest.mark.parametrize(
    "example_script",
    [
        "examples/01_motor_insurance_claim.py",
        "examples/02_banking_kyc_dominator.py",
        "examples/03_healthcare_hipaa_vault.py",
        "examples/04_langchain_subflow_handoff.py",
        "examples/05_motor_insurance_claim_live.py",
    ],
)
def test_reference_agents_pass_blockstate_check(example_script: str) -> None:
    """Verify that all five reference agents pass static offline blockstate check."""
    result = runner.invoke(app, ["check", example_script])
    assert result.exit_code == 0
    assert "Declarative Control Grammar Verified" in result.output


def test_banking_kyc_dominator_verification_via_cli() -> None:
    """Verify that reference agent 2 passes Lengauer-Tarjan dominance proof via CLI."""
    result = runner.invoke(
        app,
        [
            "verify",
            "examples/02_banking_kyc_dominator.py",
            "--dominates",
            "VerifyKYC -> TransferFunds",
        ],
    )
    assert result.exit_code == 0
    assert "Lengauer-Tarjan Dominance Certified" in result.output


def test_motor_insurance_dominator_verification_via_cli() -> None:
    """Verify that reference agent 5 passes Lengauer-Tarjan dominance proof via CLI."""
    result = runner.invoke(
        app,
        [
            "verify",
            "examples/05_motor_insurance_claim_live.py",
            "--dominates",
            "verify_policy -> fast_track_settlement",
        ],
    )
    assert result.exit_code == 0
    assert "Lengauer-Tarjan Dominance Certified" in result.output


def test_motor_insurance_defensive_audit() -> None:
    """Verify that all 6 adversarial trials in reference agent 5 pass defensive audit."""
    script_path = Path("examples/05_defensive_audit.py")
    assert script_path.exists(), f"Audit script not found: {script_path}"

    proc = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, (
        f"Defensive audit failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "DEFENSIVE AUDIT SUMMARY: 6/6 TRIALS DEFENDED (100.0%)" in proc.stdout
