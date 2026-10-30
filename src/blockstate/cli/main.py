"""Blockstate command-line interface (CLI) for statechart inspection and verification.

Provides offline AST checking, Lengauer-Tarjan mathematical dominator proofs,
chronological trace replay, and Mermaid/JSON topology exporters.
"""

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from blockstate.adapters.telemetry.otel import DEFAULT_TRACES_PATH, TraceReplayer
from blockstate.cli.scaffold import TEMPLATES, TemplateType, scaffold_project
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


def _is_interactive() -> bool:
    """Return whether standard input is attached to an interactive terminal."""
    return sys.stdin.isatty()


@app.command(name="init")
def init_cmd(
    directory: Annotated[
        Path,
        typer.Argument(
            help="Target directory to scaffold the enclave into. Defaults to current directory.",
            show_default=".",
        ),
    ] = Path("."),
    template: Annotated[
        TemplateType,
        typer.Option(
            "--template",
            "-t",
            help="Starter enclave template (banking, insurance, healthcare, minimal).",
            case_sensitive=False,
        ),
    ] = TemplateType.MINIMAL,
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            "-n",
            help="Custom identifier for the agent and filenames (defaults to template name).",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing files in target directory if it is not empty.",
        ),
    ] = False,
) -> None:
    """Scaffold a ready-to-verify Blockstate compliance enclave directory."""
    is_non_empty = directory.exists() and any(directory.iterdir())
    if is_non_empty and not force:
        if _is_interactive():
            confirm = typer.confirm(
                f"Target directory '{directory}' already exists and contains files. Overwrite?",
                default=False,
            )
            if not confirm:
                console.print("[yellow]Scaffolding cancelled by user.[/yellow]")
                raise typer.Exit(code=0)
        else:
            err_console.print(
                f"[red]Error: Target directory '{directory}' already exists and is not empty. "
                f"Use --force to overwrite existing files.[/red]"
            )
            raise typer.Exit(code=1)

    try:
        generated_files = scaffold_project(
            target_dir=directory,
            template=template,
            force=True,
            agent_name=name,
        )
    except Exception as exc:
        err_console.print(f"[red]Error scaffolding enclave: {exc}[/red]")
        raise typer.Exit(code=1) from None

    template_meta = TEMPLATES[template]
    base_name = name.strip() if name else template.value
    agent_filename = f"{base_name}_agent.py"
    test_filename = (
        f"test_{base_name}.py" if template == TemplateType.MINIMAL else f"test_{base_name}_agent.py"
    )

    console.print(
        Panel.fit(
            f"[bold green]Blockstate Compliance Enclave Scaffolded[/bold green]\n"
            f"Template: [cyan]{template.value}[/cyan] ({template_meta.agent_class_name})\n"
            f"Precursor Invariant: [yellow]{template_meta.dominance_assertion}[/yellow]\n"
            f"Target Directory: [bold]{directory.resolve()}[/bold]\n"
            f"Total Files Generated: {len(generated_files)}",
            title="Blockstate Init",
            border_style="green",
        )
    )

    files_table = Table(title="Generated Enclave Files", border_style="cyan")
    files_table.add_column("File", style="bold")
    files_table.add_column("Purpose", style="italic")

    files_table.add_row(
        agent_filename,
        "Declarative Control Grammar statechart with stage-scoped tools and simulation runner",
    )
    files_table.add_row(
        test_filename,
        "Automated pytest suite verifying AST extraction, dominator proof, and turns",
    )
    files_table.add_row(".env.example", "Baseline runtime environment configuration")
    files_table.add_row(
        ".github/workflows/blockstate-verify.yml",
        "Automated pull-request verification gate",
    )
    files_table.add_row("README.md", "Quickstart verification and execution instructions")
    console.print(files_table)

    console.print("\n[bold]Next Steps:[/bold]")
    console.print(
        f"  1. Verify topology:   [cyan]blockstate check {directory / agent_filename}[/cyan]"
    )
    console.print(
        f"  2. Certify dominance: [cyan]blockstate verify {directory / agent_filename} "
        f'--dominates "{template_meta.dominance_assertion}"[/cyan]'
    )
    console.print(f"  3. Run test suite:    [cyan]pytest {directory / test_filename} -v[/cyan]")
    console.print(
        f"  4. Visual canvas:     [cyan]blockstate studio {directory / agent_filename}[/cyan]"
    )


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
            "[bold green]VALID[/bold green]" if rec.chain_valid else "[bold red]BROKEN[/bold red]"
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


@app.command(name="studio")
def studio_cmd(
    path: Annotated[
        Path | None,
        typer.Argument(
            help="Path to Python agent file or directory to inspect in Blockstate Studio.",
        ),
    ] = None,
    port: Annotated[
        int,
        typer.Option(
            "--port",
            "-p",
            help="Local port number to bind the Studio HTTP server.",
        ),
    ] = 8420,
    host: Annotated[
        str,
        typer.Option(
            "--host",
            "-h",
            help="Host address to bind the Studio HTTP server.",
        ),
    ] = "127.0.0.1",
    no_browser: Annotated[
        bool,
        typer.Option(
            "--no-browser",
            help="Do not automatically launch the system web browser upon startup.",
        ),
    ] = False,
) -> None:
    """Launch the interactive visual statechart canvas and trace replay studio."""
    from blockstate.cli.studio import run_studio

    run_studio(path=path, host=host, port=port, open_browser=not no_browser)


def main() -> None:
    """Entrypoint function for blockstate CLI executable."""
    app()


if __name__ == "__main__":
    main()
