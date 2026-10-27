"""Blockstate command-line interface (CLI) for statechart inspection and verification.

Provides offline AST checking, Lengauer-Tarjan mathematical dominator proofs,
chronological trace replay, and Mermaid/JSON topology exporters.
"""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blockstate.adapters.telemetry.otel import DEFAULT_TRACES_PATH, TraceReplayer
from blockstate.compiler.ast_extractor import StaticGraphCompiler
from blockstate.compiler.dominators import verify_dominance
from blockstate.compiler.exporters import export_json, export_mermaid
from blockstate.errors import BlockstateError

app = typer.Typer(
    name="blockstate",
    help="Blockstate deterministic statechart governance CLI and verification toolkit.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


@app.command()
def check(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to Python source file containing Declarative Control Grammar agent.",
            exists=False,
            readable=False,
        ),
    ],
) -> None:
    """Statically inspect an agent source file offline to verify topology and detect defects."""
    if not path.exists():
        err_console.print(f"[red]Error: Agent source file not found: {path}[/red]")
        raise typer.Exit(code=1)

    try:
        source_code = path.read_text(encoding="utf-8")
        graph = StaticGraphCompiler.compile_source(source_code, filename=str(path))
    except BlockstateError as err:
        # Preserve verbatim error format, e.g. [Blockstate E014] or [BLK-AST-002]
        err_console.print(f"[red]{err}[/red]")
        raise typer.Exit(code=1) from None
    except Exception as exc:
        err_console.print(f"[red]Error checking agent '{path}': {exc}[/red]")
        raise typer.Exit(code=1) from None

    # Render clean Rich verification report
    console.print(
        Panel.fit(
            f"[bold green]Declarative Control Grammar Verified[/bold green]\n"
            f"Agent: [cyan]{graph.agent_name}[/cyan]\n"
            f"Initial Stage: [yellow]{graph.initial_stage}[/yellow]\n"
            f"Total Stages: {len(graph.stages)} | Total Transitions: {len(graph.transitions)}",
            title="Blockstate Check",
            border_style="green",
        )
    )

    stages_table = Table(title=f"Declared Stages ({graph.agent_name})", border_style="cyan")
    stages_table.add_column("Stage Name", style="bold")
    stages_table.add_column("Type", style="italic")
    stages_table.add_column("Max Turns", justify="right")
    stages_table.add_column("Allowed Tools")
    stages_table.add_column("Permitted Digressions")
    stages_table.add_column("Target Fallback")

    for name, s in sorted(graph.stages.items()):
        stage_type = (
            "Initial"
            if s.is_initial or name == graph.initial_stage
            else ("Terminal" if s.terminal else "Standard")
        )
        tools_str = ", ".join(s.tools) if s.tools else "[dim]none[/dim]"
        dig_str = ", ".join(s.allow_digressions) if s.allow_digressions else "[dim]none[/dim]"
        fallbacks: list[str] = []
        if s.on_refusal:
            fallbacks.append(f"refusal->{s.on_refusal}")
        if s.on_max_turns_exceeded:
            fallbacks.append(f"turns->{s.on_max_turns_exceeded}")
        if s.on_breach:
            fallbacks.append(f"breach->{s.on_breach}")
        if s.on_security_violation:
            fallbacks.append(f"security->{s.on_security_violation}")
        fallback_str = ", ".join(fallbacks) if fallbacks else "[dim]none[/dim]"

        stages_table.add_row(
            name,
            stage_type,
            str(s.max_turns) if s.max_turns is not None else "unlimited",
            tools_str,
            dig_str,
            fallback_str,
        )

    console.print(stages_table)


@app.command()
def verify(
    dominates: Annotated[
        str,
        typer.Option(
            "--dominates",
            "-d",
            help="Precursor dominance assertion, e.g. 'VerifyKYC -> TransferFunds'.",
        ),
    ],
    path: Annotated[
        Path | None,
        typer.Argument(
            help="Path to Python source file containing Declarative Control Grammar agent.",
        ),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-f",
            help="Alternative path to Python source file.",
        ),
    ] = None,
) -> None:
    """Mathematically verify precursor dominance using Lengauer-Tarjan algorithm."""
    target_path = path or file
    if target_path is None:
        err_console.print("[red]Error: Path to agent source file must be specified.[/red]")
        raise typer.Exit(code=1)

    if not target_path.exists():
        err_console.print(f"[red]Error: Agent source file not found: {target_path}[/red]")
        raise typer.Exit(code=1)

    if "->" not in dominates:
        err_console.print(
            "[red]Error: Invalid --dominates syntax. Expected '<Precursor> -> <Targets>'.[/red]"
        )
        raise typer.Exit(code=1)

    precursor_raw, targets_raw = dominates.split("->", 1)
    precursor = precursor_raw.strip()
    targets = tuple(t.strip() for t in targets_raw.split(",") if t.strip())

    if not precursor or not targets:
        err_console.print(
            "[red]Error: Both precursor and at least one target stage must be specified.[/red]"
        )
        raise typer.Exit(code=1)

    try:
        source_code = target_path.read_text(encoding="utf-8")
        graph = StaticGraphCompiler.compile_source(source_code, filename=str(target_path))
    except BlockstateError as err:
        err_console.print(f"[red]{err}[/red]")
        raise typer.Exit(code=1) from None
    except Exception as exc:
        err_console.print(f"[red]Error compiling agent '{target_path}': {exc}[/red]")
        raise typer.Exit(code=1) from None

    root = graph.initial_stage
    if not root:
        err_console.print("[red]Error: Agent has no declared initial stage.[/red]")
        raise typer.Exit(code=1)

    adj = graph.adjacency_list(include_fallbacks=True)
    proof = verify_dominance(root=root, graph=adj, precursor=precursor, targets=targets)

    if proof.satisfied:
        cert_panel = Panel.fit(
            f"[bold green]Lengauer-Tarjan Dominance Certified[/bold green]\n\n"
            f"[bold]Precursor:[/bold] [cyan]{precursor}[/cyan]\n"
            f"[bold]Protected Targets:[/bold] [yellow]{', '.join(targets)}[/yellow]\n"
            f"[bold]Root Stage:[/bold] {root}\n"
            f"[bold]Proof Status:[/bold] [green]100% of paths dominated[/green]\n"
            f"[bold]Bypass Risk:[/bold] 0.00% (Mathematical Invariant)",
            title="Verification Certificate",
            border_style="green",
        )
        console.print(cert_panel)
        raise typer.Exit(code=0)
    else:
        path_str = " -> ".join(proof.violating_path or ())
        err_console.print(
            f"[bold red]Dominance Proof Failure[/bold red]\n"
            f"{proof.summary()}\n"
            f"[red]Violating bypass route:[/red] [bold yellow]{path_str}[/bold yellow]"
        )
        raise typer.Exit(code=1)


@app.command()
def trace(
    session: Annotated[
        str,
        typer.Option(
            "--session",
            "-s",
            help="Session identifier to inspect and replay.",
        ),
    ],
    file: Annotated[
        Path,
        typer.Option(
            "--file",
            "-f",
            help="Path to .blockstate/traces.jsonl trace log file.",
        ),
    ] = DEFAULT_TRACES_PATH,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Output display format (table or json).",
        ),
    ] = "table",
) -> None:
    """Replay conversational turn timeline from local traces with SHA-256 chain verification."""
    replayer = TraceReplayer(trace_file=file)
    records = replayer.load_session_traces(session_id=session)

    if not records:
        err_console.print(
            f"[red]Diagnostic: Session '{session}' not found in traces file '{file}'.[/red]"
        )
        raise typer.Exit(code=1)

    if format.lower() == "json":
        dict_records = [r.to_dict() for r in records]
        console.print(json.dumps(dict_records, indent=2, ensure_ascii=False))
        return

    # Render Rich timeline table
    table = Table(
        title=f"Turn Trace Timeline: Session {session}",
        border_style="blue",
        show_lines=True,
    )
    table.add_column("Turn", justify="right", style="bold")
    table.add_column("Stage From", style="cyan")
    table.add_column("Stage To", style="green")
    table.add_column("Guard Outcome", style="italic")
    table.add_column("Slot Deltas")
    table.add_column("Exposed Tools")
    table.add_column("Input Digest (SHA-256)", style="dim")
    table.add_column("Chain Status", justify="center")

    for rec in records:
        chain_status = (
            "[bold green]VALID[/bold green]"
            if rec.chain_valid
            else "[bold red]BROKEN[/bold red]"
        )
        deltas_str = ", ".join(rec.slot_deltas) if rec.slot_deltas else "[dim]none[/dim]"
        tools_str = ", ".join(rec.exposed_tools) if rec.exposed_tools else "[dim]none[/dim]"
        input_digest = f"{rec.input_hash[:12]}..." if rec.input_hash else "[dim]none[/dim]"

        table.add_row(
            str(rec.turn_index),
            rec.stage_from,
            rec.stage_to,
            rec.guard_outcome,
            deltas_str,
            tools_str,
            input_digest,
            chain_status,
        )

    console.print(table)


@app.command(name="export")
def export_cmd(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to Python source file containing Declarative Control Grammar agent.",
        ),
    ],
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export topology format (mermaid or json).",
        ),
    ] = "mermaid",
    markdown_fence: Annotated[
        bool,
        typer.Option(
            "--markdown-fence",
            help="Wrap Mermaid diagram inside GitHub-flavoured markdown code fence.",
        ),
    ] = False,
) -> None:
    """Export verified agent statechart topology as visual Mermaid diagram or JSON schema."""
    if not path.exists():
        err_console.print(f"[red]Error: Agent source file not found: {path}[/red]")
        raise typer.Exit(code=1)

    try:
        source_code = path.read_text(encoding="utf-8")
        graph = StaticGraphCompiler.compile_source(source_code, filename=str(path))
    except BlockstateError as err:
        err_console.print(f"[red]{err}[/red]")
        raise typer.Exit(code=1) from None
    except Exception as exc:
        err_console.print(f"[red]Error compiling agent '{path}': {exc}[/red]")
        raise typer.Exit(code=1) from None

    fmt = format.lower().strip()
    if fmt == "mermaid":
        mermaid_text = export_mermaid(graph, markdown_fence=markdown_fence)
        console.print(mermaid_text)
    elif fmt == "json":
        json_text = export_json(graph)
        console.print(json_text)
    else:
        msg = f"Error: Unsupported export format '{format}'. Supported formats: mermaid, json."
        err_console.print(f"[red]{msg}[/red]")
        raise typer.Exit(code=1)


def main() -> None:
    """Entrypoint function for blockstate CLI executable."""
    app()


if __name__ == "__main__":
    main()
