"""Blockstate Declarative Control Grammar (DCG) static AST compiler and dominator proofs.

Provides offline static analysis over agent source code, Lengauer-Tarjan dominator
tree solving, and Mermaid/JSON topology exporters.
"""

from blockstate.compiler.ast_extractor import (
    StageNode,
    StatechartGraph,
    StaticGraphCompiler,
    TransitionEdge,
    extract_statechart_from_ast,
    extract_statechart_from_file,
    extract_statechart_from_source,
)
from blockstate.compiler.dominators import (
    DominanceProofResult,
    LengauerTarjanSolver,
    find_counterexample_path,
    verify_dominance,
)
from blockstate.compiler.exporters import (
    export_json,
    export_mermaid,
)

__all__: list[str] = [
    "DominanceProofResult",
    "LengauerTarjanSolver",
    "StageNode",
    "StatechartGraph",
    "StaticGraphCompiler",
    "TransitionEdge",
    "export_json",
    "export_mermaid",
    "extract_statechart_from_ast",
    "extract_statechart_from_file",
    "extract_statechart_from_source",
    "find_counterexample_path",
    "verify_dominance",
]
