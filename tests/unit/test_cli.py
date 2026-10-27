"""Unit tests for the Typer/Rich blockstate CLI surface."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from blockstate.cli.main import app, main

runner = CliRunner()


@pytest.fixture
def temp_agent_files(tmp_path: Path) -> dict[str, Path]:
    """Create temporary agent source files covering various DCG scenarios."""
    valid_agent = tmp_path / "valid_agent.py"
    valid_agent.write_text(
        """from blockstate.core.agent import Agent, Stage, Transition, Guard

class SimpleTestAgent(Agent):
    @Stage(name="start")
    @Transition("finish")
    def start_stage(self) -> Transition[str]:
        return Transition.to("finish")

    @Stage(name="finish", terminal=True)
    def finish_stage(self) -> Transition[None]:
        return Transition.end()
""",
        encoding="utf-8",
    )

    dynamic_reflection_agent = tmp_path / "dynamic_reflection_agent.py"
    dynamic_reflection_agent.write_text(
        """from blockstate.core.agent import Agent, Stage, Transition

class DynamicAgent(Agent):
    @Stage(name="root")
    def root(self) -> None:
        target = "somewhere"
        getattr(self, target)()
""",
        encoding="utf-8",
    )

    dynamic_transition_agent = tmp_path / "dynamic_transition_agent.py"
    dynamic_transition_agent.write_text(
        """from blockstate.core.agent import Agent, Stage, Transition

class DynamicTargetAgent(Agent):
    @Stage(name="root")
    def root(self) -> Transition[str]:
        target = "stage_" + "two"
        return Transition.to(target)
""",
        encoding="utf-8",
    )

    dead_stage_agent = tmp_path / "dead_stage_agent.py"
    dead_stage_agent.write_text(
        """from blockstate.core.agent import Agent, Stage, Transition

class DeadStageAgent(Agent):
    @Stage(name="start")
    def start(self) -> Transition[str]:
        return Transition.to("end")

    @Stage(name="end", terminal=True)
    def end(self) -> Transition[None]:
        return Transition.end()

    @Stage(name="unreachable_stage")
    def dead(self) -> None:
        pass
""",
        encoding="utf-8",
    )

    syntax_error_agent = tmp_path / "syntax_error.py"
    syntax_error_agent.write_text(
        """def broken(
""",
        encoding="utf-8",
    )

    return {
        "valid": valid_agent,
        "dynamic_reflection": dynamic_reflection_agent,
        "dynamic_transition": dynamic_transition_agent,
        "dead_stage": dead_stage_agent,
        "syntax_error": syntax_error_agent,
    }


def test_cli_check_valid_agent(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate check succeeds and outputs stages table for valid agent."""
    result = runner.invoke(app, ["check", str(temp_agent_files["valid"])])
    assert result.exit_code == 0
    assert "Declarative Control Grammar Verified" in result.output
    assert "SimpleTestAgent" in result.output
    assert "start" in result.output
    assert "finish" in result.output


def test_cli_check_missing_file() -> None:
    """Verify blockstate check fails with code 1 for non-existent file."""
    result = runner.invoke(app, ["check", "non_existent_agent_file.py"])
    assert result.exit_code == 1
    assert "Agent source file not found" in result.output


def test_cli_check_dynamic_reflection(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate check flags dynamic reflection with [Blockstate E014]."""
    result = runner.invoke(app, ["check", str(temp_agent_files["dynamic_reflection"])])
    assert result.exit_code == 1
    assert "[Blockstate E014]" in result.output
    assert "Dynamic transition destination detected" in result.output


def test_cli_check_dynamic_transition_target(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate check flags dynamic Transition.to targets with [Blockstate E014]."""
    result = runner.invoke(app, ["check", str(temp_agent_files["dynamic_transition"])])
    assert result.exit_code == 1
    assert "[Blockstate E014]" in result.output


def test_cli_check_dead_stage(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate check flags unreachable stages with BLK-AST-002."""
    result = runner.invoke(app, ["check", str(temp_agent_files["dead_stage"])])
    assert result.exit_code == 1
    assert "BLK-AST-002" in result.output
    assert "Unreachable dead stages detected" in result.output


def test_cli_check_syntax_error(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate check handles Python syntax errors with BLK-AST-001."""
    result = runner.invoke(app, ["check", str(temp_agent_files["syntax_error"])])
    assert result.exit_code == 1
    assert "BLK-AST-001" in result.output


def test_cli_verify_dominance_satisfied() -> None:
    """Verify blockstate verify certifies dominance and exits with code 0."""
    target_file = "examples/02_banking_kyc_dominator.py"
    result = runner.invoke(
        app,
        ["verify", target_file, "--dominates", "VerifyKYC -> TransferFunds"],
    )
    assert result.exit_code == 0
    assert "Lengauer-Tarjan Dominance Certified" in result.output
    assert "Precursor: VerifyKYC" in result.output
    assert "TransferFunds" in result.output


def test_cli_verify_dominance_violation() -> None:
    """Verify blockstate verify prints violating path and exits with code 1 on bypass."""
    target_file = "examples/02_banking_kyc_dominator.py"
    result = runner.invoke(
        app,
        ["verify", target_file, "--dominates", "ManualComplianceReview -> TransferFunds"],
    )
    assert result.exit_code == 1
    assert "Dominance Proof Failure" in result.output
    assert "Violating bypass route" in result.output


def test_cli_verify_invalid_syntax(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate verify validates --dominates syntax."""
    result = runner.invoke(
        app,
        ["verify", str(temp_agent_files["valid"]), "--dominates", "InvalidSyntaxNoArrow"],
    )
    assert result.exit_code == 1
    assert "Invalid --dominates syntax" in result.output


def test_cli_verify_missing_path() -> None:
    """Verify blockstate verify requires path or --file."""
    result = runner.invoke(app, ["verify", "--dominates", "A -> B"])
    assert result.exit_code == 1
    assert "Path to agent source file must be specified" in result.output


def test_cli_trace_table_and_json(tmp_path: Path) -> None:
    """Verify blockstate trace renders table and JSON formats with chain status."""
    trace_file = tmp_path / "traces.jsonl"
    record1 = {
        "session_id": "sess_unit_test",
        "turn_index": 1,
        "stage_from": "stage_a",
        "stage_to": "stage_b",
        "exposed_tools": ["tool1"],
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
        "slot_deltas": ["slot1"],
        "guard_outcome": "transition",
        "record_hash": "hash_turn_1",
        "prev_record_hash": "0" * 64,
        "timestamp_utc": "2026-10-27T12:00:00Z",
        "chain_valid": True,
    }
    record2 = {
        "session_id": "sess_unit_test",
        "turn_index": 2,
        "stage_from": "stage_b",
        "stage_to": "stage_c",
        "exposed_tools": [],
        "input_hash": "c" * 64,
        "output_hash": "d" * 64,
        "slot_deltas": [],
        "guard_outcome": "end",
        "record_hash": "hash_turn_2",
        "prev_record_hash": "hash_turn_1",
        "timestamp_utc": "2026-10-27T12:01:00Z",
        "chain_valid": True,
    }
    trace_file.write_text(
        json.dumps(record1) + "\n" + json.dumps(record2) + "\n",
        encoding="utf-8",
    )

    # 1. Table format
    res_table = runner.invoke(
        app,
        ["trace", "--session", "sess_unit_test", "--file", str(trace_file), "--format", "table"],
    )
    assert res_table.exit_code == 0
    assert "Turn Trace Timeline: Session sess_unit_test" in res_table.output
    assert "stage_a" in res_table.output
    assert "stage_b" in res_table.output
    assert "VALID" in res_table.output

    # 2. JSON format
    res_json = runner.invoke(
        app,
        ["trace", "--session", "sess_unit_test", "--file", str(trace_file), "--format", "json"],
    )
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["session_id"] == "sess_unit_test"
    assert data[1]["turn_index"] == 2


def test_cli_trace_session_not_found(tmp_path: Path) -> None:
    """Verify blockstate trace exits with code 1 if session does not exist."""
    trace_file = tmp_path / "traces.jsonl"
    trace_file.write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        ["trace", "--session", "unknown_session", "--file", str(trace_file)],
    )
    assert result.exit_code == 1
    assert "Diagnostic: Session 'unknown_session' not found" in result.output


def test_cli_export_mermaid_and_json(temp_agent_files: dict[str, Path]) -> None:
    """Verify blockstate export outputs valid Mermaid flowchart and JSON schema."""
    valid_file = str(temp_agent_files["valid"])

    # 1. Mermaid
    res_mermaid = runner.invoke(app, ["export", valid_file, "--format", "mermaid"])
    assert res_mermaid.exit_code == 0
    assert "flowchart TD" in res_mermaid.output
    assert "start" in res_mermaid.output
    assert "finish" in res_mermaid.output

    # 2. Mermaid with markdown fence
    res_fenced = runner.invoke(
        app,
        ["export", valid_file, "--format", "mermaid", "--markdown-fence"],
    )
    assert res_fenced.exit_code == 0
    assert "```mermaid" in res_fenced.output

    # 3. JSON
    res_json = runner.invoke(app, ["export", valid_file, "--format", "json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["agent_name"] == "SimpleTestAgent"
    assert "start" in data["stages"]
    assert "finish" in data["stages"]

    # 4. Invalid format
    res_invalid = runner.invoke(app, ["export", valid_file, "--format", "unsupported_fmt"])
    assert res_invalid.exit_code == 1
    assert "Unsupported export format" in res_invalid.output


def test_cli_export_missing_file() -> None:
    """Verify blockstate export exits with code 1 if source file not found."""
    result = runner.invoke(app, ["export", "missing.py"])
    assert result.exit_code == 1
    assert "Agent source file not found" in result.output


def test_cli_verify_with_file_option() -> None:
    """Verify blockstate verify works with --file option."""
    result = runner.invoke(
        app,
        [
            "verify",
            "--file",
            "examples/02_banking_kyc_dominator.py",
            "--dominates",
            "VerifyKYC -> TransferFunds",
        ],
    )
    assert result.exit_code == 0


def test_cli_verify_missing_source_file() -> None:
    """Verify blockstate verify exits with code 1 if source file missing."""
    result = runner.invoke(
        app,
        ["verify", "non_existent.py", "--dominates", "A -> B"],
    )
    assert result.exit_code == 1
    assert "Agent source file not found" in result.output


def test_cli_main_callable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify main() entrypoint is callable and exits cleanly on --help."""
    import sys

    assert callable(main)
    monkeypatch.setattr(sys, "argv", ["blockstate", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_compiler_ast_reexports() -> None:
    """Verify blockstate.compiler.ast re-exports compiler classes."""
    import blockstate.compiler.ast as ast_mod

    assert hasattr(ast_mod, "StaticGraphCompiler")
    assert hasattr(ast_mod, "StatechartGraph")
