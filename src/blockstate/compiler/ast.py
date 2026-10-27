"""Declarative Control Grammar (DCG) static AST graph extractor and compiler.

Alias module providing backward compatibility and direct access to AST extraction
and compiler routines.
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

__all__: list[str] = [
    "StageNode",
    "StatechartGraph",
    "StaticGraphCompiler",
    "TransitionEdge",
    "extract_statechart_from_ast",
    "extract_statechart_from_file",
    "extract_statechart_from_source",
]
