"""Mermaid flowchart and JSON schema exporters for compiled StatechartGraphs.

Generates valid GitHub-flavoured Mermaid diagrams (flowchart TD) displaying stage
nodes, whitelisted tools, and guard annotations, alongside machine-readable JSON
topology schemas for compliance audits.
"""

import json
from typing import Any

from blockstate.compiler.ast_extractor import StatechartGraph


def export_mermaid(graph: StatechartGraph, *, markdown_fence: bool = False) -> str:
    """Export a StatechartGraph to a valid Mermaid flowchart TD definition."""
    lines: list[str] = ["flowchart TD"]

    # 1. Declare stage nodes with descriptive labels and tool badges
    for name, stage in sorted(graph.stages.items()):
        badges: list[str] = []
        if stage.is_initial or name == graph.initial_stage:
            badges.append("[INITIAL]")
        if stage.terminal:
            badges.append("[TERMINAL]")
        if stage.tools:
            badges.append(f"tools: {', '.join(stage.tools)}")
        if stage.max_turns is not None:
            badges.append(f"max_turns: {stage.max_turns}")

        badge_str = f"\\n({'; '.join(badges)})" if badges else ""
        label = f'"{name}{badge_str}"'

        # Use rounded rectangle for standard, stadium for terminal/initial
        if stage.terminal:
            lines.append(f"    {name}([{label}])")
        else:
            lines.append(f"    {name}[{label}]")

    # 2. Declare transition edges with annotations
    for edge in graph.transitions:
        src = edge.source
        tgt = edge.target

        # Handle special target markers
        if tgt == "[END]":
            tgt_node = f"{src}_end"
            lines.append(f"    {tgt_node}((End))")
            lines.append(f"    {src} --> {tgt_node}")
            continue
        if tgt == "[POP]":
            tgt_node = f"{src}_pop"
            lines.append(f"    {tgt_node}((Pop Frame))")
            lines.append(f"    {src} --> {tgt_node}")
            continue
        if tgt == "[STAY]":
            lines.append(f"    {src} -->|stay| {src}")
            continue

        label_part = f"|{edge.guard}| " if edge.guard else ""
        if edge.kind == "fallback":
            lines.append(f"    {src} -.->|fallback| {tgt}")
        elif edge.kind == "stay":
            lines.append(f"    {src} -->|stay| {tgt}")
        else:
            lines.append(f"    {src} -->{label_part}{tgt}")

    content = "\n".join(lines)
    if markdown_fence:
        return f"```mermaid\n{content}\n```"
    return content


def export_json(graph: StatechartGraph, *, indent: int = 2) -> str:
    """Export a StatechartGraph to a machine-readable JSON topology schema."""
    stages_payload: dict[str, Any] = {}
    for name, stage in sorted(graph.stages.items()):
        stages_payload[name] = {
            "name": stage.name,
            "is_initial": stage.is_initial or name == graph.initial_stage,
            "terminal": stage.terminal,
            "tools": list(stage.tools),
            "allow_digressions": list(stage.allow_digressions),
            "on_refusal": stage.on_refusal,
            "on_max_turns_exceeded": stage.on_max_turns_exceeded,
            "on_breach": stage.on_breach,
            "on_security_violation": stage.on_security_violation,
            "max_turns": stage.max_turns,
            "collect_model": stage.collect_model,
            "canned_response": stage.canned_response,
            "choice_options": list(stage.choice_options),
            "lineno": stage.lineno,
            "guards": graph.guards.get(name, []),
        }

    transitions_payload: list[dict[str, Any]] = [
        {
            "source": edge.source,
            "target": edge.target,
            "kind": edge.kind,
            "guard": edge.guard,
            "lineno": edge.lineno,
        }
        for edge in graph.transitions
    ]

    payload: dict[str, Any] = {
        "agent_name": graph.agent_name,
        "initial_stage": graph.initial_stage,
        "stages": stages_payload,
        "transitions": transitions_payload,
    }
    return json.dumps(payload, indent=indent, sort_keys=True)


__all__: list[str] = [
    "export_json",
    "export_mermaid",
]
