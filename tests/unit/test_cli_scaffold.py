"""Unit tests for Blockstate CLI project scaffolder and starter enclave templates.

Tests the scaffolding engine, directory collision protection (interactive and CI),
all four domain templates (banking, insurance, healthcare, minimal), zero-edit
verification guarantee under blockstate check, verify, and pytest execution.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from blockstate.cli.main import app
from blockstate.cli.scaffold import (
    TemplateType,
    scaffold_project,
)

runner = CliRunner()


# ===========================================================================
# Programmatic Scaffolder Tests
# ===========================================================================


@pytest.mark.parametrize("template_name", ["banking", "insurance", "healthcare", "minimal"])
def test_scaffold_project_programmatic_all_templates(
    tmp_path: Path,
    template_name: str,
) -> None:
    """Verify scaffold_project successfully writes all 5 required files for all templates."""
    dest = tmp_path / f"enclave_{template_name}"
    generated_files = scaffold_project(dest, template=template_name)

    assert len(generated_files) == 5
    for file_path in generated_files:
        assert file_path.is_file(), f"Expected generated file to exist: {file_path}"
        assert file_path.stat().st_size > 0, f"Generated file is empty: {file_path}"

    base_agent = dest / f"{template_name}_agent.py"
    assert base_agent.is_file()

    env_file = dest / ".env.example"
    assert env_file.is_file()
    assert "BLOCKSTATE_STORAGE_BACKEND" in env_file.read_text(encoding="utf-8")

    workflow_file = dest / ".github" / "workflows" / "blockstate-verify.yml"
    assert workflow_file.is_file()
    assert "Blockstate Enclave Verification" in workflow_file.read_text(encoding="utf-8")

    readme_file = dest / "README.md"
    assert readme_file.is_file()
    assert "Architectural Guarantees" in readme_file.read_text(encoding="utf-8")


def test_scaffold_project_custom_agent_name(tmp_path: Path) -> None:
    """Verify scaffold_project honours custom agent prefix for generated filenames."""
    dest = tmp_path / "custom_enclave"
    generated = scaffold_project(dest, template="banking", agent_name="treasury_flow")

    agent_file = dest / "treasury_flow_agent.py"
    test_file = dest / "test_treasury_flow_agent.py"

    assert agent_file.is_file()
    assert test_file.is_file()
    assert any(p == agent_file for p in generated)
    assert any(p == test_file for p in generated)


def test_scaffold_project_invalid_template(tmp_path: Path) -> None:
    """Verify scaffold_project raises ValueError when given an unrecognised template."""
    dest = tmp_path / "invalid_enclave"
    with pytest.raises(ValueError) as exc_info:
        scaffold_project(dest, template="unsupported_template_type")
    assert "Unknown template" in str(exc_info.value)


def test_scaffold_project_collision_file_exists_error(tmp_path: Path) -> None:
    """Verify scaffold_project raises FileExistsError on non-empty destination when force=False."""
    dest = tmp_path / "prepopulated"
    dest.mkdir(parents=True)
    (dest / "keep_me.txt").write_text("existing content", encoding="utf-8")

    with pytest.raises(FileExistsError) as exc_info:
        scaffold_project(dest, template="minimal", force=False)
    assert "is not empty" in str(exc_info.value)

    # With force=True, it succeeds
    files = scaffold_project(dest, template="minimal", force=True)
    assert len(files) == 5
    assert (dest / "minimal_agent.py").is_file()


# ===========================================================================
# CLI Runner Subcommand Tests
# ===========================================================================


@pytest.mark.parametrize("template_name", ["banking", "insurance", "healthcare", "minimal"])
def test_cli_init_subcommand_all_templates(tmp_path: Path, template_name: str) -> None:
    """Verify blockstate init command executes cleanly via CliRunner for all templates."""
    dest = tmp_path / f"cli_{template_name}"
    result = runner.invoke(app, ["init", str(dest), "--template", template_name])

    assert result.exit_code == 0, f"CLI init failed: {result.output}"
    assert "Blockstate Compliance Enclave Scaffolded" in result.output
    assert template_name in result.output.lower()
    assert (dest / f"{template_name}_agent.py").is_file()


def test_cli_init_non_interactive_collision_safeguard(tmp_path: Path) -> None:
    """Verify non-interactive CLI run into non-empty directory aborts with exit code 1."""
    dest = tmp_path / "occupied"
    dest.mkdir(parents=True)
    (dest / "data.csv").write_text("id,val\n1,2", encoding="utf-8")

    with patch("blockstate.cli.main._is_interactive", return_value=False):
        result = runner.invoke(app, ["init", str(dest), "--template", "minimal"])

    assert result.exit_code == 1
    assert "already exists and is not empty" in result.output


def test_cli_init_interactive_collision_declined(tmp_path: Path) -> None:
    """Verify interactive user declining overwrite cancels scaffolding with exit code 0."""
    dest = tmp_path / "occupied_interactive"
    dest.mkdir(parents=True)
    preexisting = dest / "sensitive.txt"
    preexisting.write_text("do not delete", encoding="utf-8")

    with patch("blockstate.cli.main._is_interactive", return_value=True):
        result = runner.invoke(app, ["init", str(dest), "--template", "minimal"], input="n\n")

    assert result.exit_code == 0
    assert "Scaffolding cancelled by user" in result.output
    assert preexisting.read_text(encoding="utf-8") == "do not delete"
    assert not (dest / "minimal_agent.py").exists()


def test_cli_init_interactive_collision_confirmed(tmp_path: Path) -> None:
    """Verify interactive user confirming overwrite proceeds with scaffolding."""
    dest = tmp_path / "occupied_confirmed"
    dest.mkdir(parents=True)
    (dest / "old.txt").write_text("old", encoding="utf-8")

    with patch("blockstate.cli.main._is_interactive", return_value=True):
        result = runner.invoke(app, ["init", str(dest), "--template", "minimal"], input="y\n")

    assert result.exit_code == 0
    assert "Blockstate Compliance Enclave Scaffolded" in result.output
    assert (dest / "minimal_agent.py").is_file()


def test_cli_init_force_flag_clean_overwrite(tmp_path: Path) -> None:
    """Verify --force flag allows overwriting non-empty directory without prompting."""
    dest = tmp_path / "force_dir"
    dest.mkdir(parents=True)
    (dest / "old.txt").write_text("old", encoding="utf-8")

    result = runner.invoke(app, ["init", str(dest), "--template", "minimal", "--force"])
    assert result.exit_code == 0
    assert "Blockstate Compliance Enclave Scaffolded" in result.output
    assert (dest / "minimal_agent.py").is_file()


# ===========================================================================
# Zero-Edit Verification Guarantees (check, verify, pytest)
# ===========================================================================


@pytest.mark.parametrize(
    "template_key,precursor,targets,assertion",
    [
        (
            TemplateType.BANKING,
            "verify_identity",
            ("execute_transfer",),
            "verify_identity -> execute_transfer",
        ),
        (
            TemplateType.INSURANCE,
            "verify_policy",
            ("fast_track_settlement",),
            "verify_policy -> fast_track_settlement",
        ),
        (
            TemplateType.HEALTHCARE,
            "patient_intake",
            ("emergency_dispatch", "schedule_clinic"),
            "patient_intake -> emergency_dispatch, schedule_clinic",
        ),
        (
            TemplateType.MINIMAL,
            "intake",
            ("complete",),
            "intake -> complete",
        ),
    ],
)
def test_zero_edit_check_and_verify(
    tmp_path: Path,
    template_key: TemplateType,
    precursor: str,
    targets: tuple[str, ...],
    assertion: str,
) -> None:
    """Ensure every template passes blockstate check and verify out-of-the-box."""
    dest = tmp_path / f"verify_{template_key.value}"
    scaffold_project(dest, template=template_key)
    agent_path = dest / f"{template_key.value}_agent.py"

    # 1. blockstate check
    check_result = runner.invoke(app, ["check", str(agent_path)])
    assert check_result.exit_code == 0, f"Check failed: {check_result.output}"
    assert "Declarative Control Grammar Verified" in check_result.output

    # 2. blockstate verify
    verify_result = runner.invoke(
        app,
        ["verify", str(agent_path), "--dominates", assertion],
    )
    assert verify_result.exit_code == 0, f"Verify failed: {verify_result.output}"
    assert "Lengauer-Tarjan Dominance Certified" in verify_result.output


@pytest.mark.parametrize("template_name", ["banking", "insurance", "healthcare", "minimal"])
def test_scaffolded_unit_tests_pass_pytest(tmp_path: Path, template_name: str) -> None:
    """Execute pytest directly against the scaffolded test files to verify green test suite."""
    dest = tmp_path / f"testrun_{template_name}"
    scaffold_project(dest, template=template_name)

    test_file = (
        dest / "test_minimal.py"
        if template_name == "minimal"
        else dest / f"test_{template_name}_agent.py"
    )
    assert test_file.is_file()

    # Run pytest directly against the scaffolded test file
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_file), "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Scaffolded test failed:\n{proc.stdout}\n{proc.stderr}"
    assert "passed" in proc.stdout


@pytest.mark.parametrize("template_name", ["banking", "insurance", "healthcare", "minimal"])
def test_scaffolded_agent_simulation_runs(tmp_path: Path, template_name: str) -> None:
    """Execute python <name>_agent.py directly to verify standalone simulation passes."""
    dest = tmp_path / f"simrun_{template_name}"
    scaffold_project(dest, template=template_name)

    agent_file = dest / f"{template_name}_agent.py"
    proc = subprocess.run(
        [sys.executable, str(agent_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Simulation runner failed:\n{proc.stdout}\n{proc.stderr}"
    assert "Simulation" in proc.stdout
