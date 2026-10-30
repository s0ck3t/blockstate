"""Comprehensive unit and Hypothesis property tests for Lengauer-Tarjan dominator solver."""

from collections import deque
from collections.abc import Iterable, Mapping

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blockstate.compiler.dominators import (
    LengauerTarjanSolver,
    find_counterexample_path,
    verify_dominance,
)


def _brute_force_dominators(root: str, graph: Mapping[str, Iterable[str]]) -> dict[str, set[str]]:
    """Reference brute-force dominator solver for verification and property fuzzing.

    Node D dominates N if every simple path from root to N contains D.
    """
    # 1. Determine all reachable nodes from root via BFS
    reachable: set[str] = set()
    queue: deque[str] = deque([root])
    while queue:
        curr = queue.popleft()
        if curr in reachable:
            continue
        reachable.add(curr)
        for nxt in graph.get(curr, ()):
            if nxt not in reachable:
                queue.append(nxt)

    all_nodes = sorted(reachable)
    doms: dict[str, set[str]] = {node: set() for node in all_nodes}

    for node in all_nodes:
        # Check every candidate dominator D
        for candidate in all_nodes:
            if candidate == node:
                doms[node].add(candidate)
                continue
            if candidate == root:
                doms[node].add(root)
                continue

            # Does there exist a path from root to node without passing through candidate?
            has_bypass_path = False
            visited_bfs: set[str] = {root, candidate}
            q_bfs: deque[str] = deque([root])

            while q_bfs:
                curr = q_bfs.popleft()
                if curr == node:
                    has_bypass_path = True
                    break
                for nxt in graph.get(curr, ()):
                    if nxt not in visited_bfs:
                        visited_bfs.add(nxt)
                        q_bfs.append(nxt)

            if not has_bypass_path:
                doms[node].add(candidate)

    return doms


@pytest.mark.patent_invariant
def test_lengauer_tarjan_linear_chain() -> None:
    """Verify dominator computation on a linear chain: A -> B -> C -> D."""
    graph = {
        "A": ["B"],
        "B": ["C"],
        "C": ["D"],
        "D": [],
    }
    solver = LengauerTarjanSolver("A", graph)
    idoms = solver.solve()

    assert idoms == {"B": "A", "C": "B", "D": "C"}
    tree = solver.compute_dominator_tree()
    assert tree["A"] == ("B",)
    assert tree["B"] == ("C",)
    assert tree["C"] == ("D",)


@pytest.mark.patent_invariant
def test_lengauer_tarjan_diamond_graph() -> None:
    """Verify dominator computation on a diamond graph:
    A -> B, A -> C
    B -> D, C -> D
    """
    graph = {
        "A": ["B", "C"],
        "B": ["D"],
        "C": ["D"],
        "D": [],
    }
    solver = LengauerTarjanSolver("A", graph)
    idoms = solver.solve()

    # D is reached via B and C, so immediate dominator of D is A
    assert idoms["B"] == "A"
    assert idoms["C"] == "A"
    assert idoms["D"] == "A"


@pytest.mark.patent_invariant
def test_lengauer_tarjan_complex_control_flow_with_cycle() -> None:
    """Verify Lengauer-Tarjan on complex control flow graph with back-edges / loops."""
    # Lengauer & Tarjan (1979) classic paper example
    graph = {
        "r": ["a", "b", "c"],
        "a": ["d"],
        "b": ["a", "d", "e"],
        "c": ["f", "g"],
        "d": ["l"],
        "e": ["h"],
        "f": ["i"],
        "g": ["i", "j"],
        "h": ["e", "k"],
        "i": ["k"],
        "j": ["i"],
        "k": ["r", "l"],
        "l": [],
    }
    solver = LengauerTarjanSolver("r", graph)
    lt_doms = solver.compute_all_dominators()
    bf_doms = _brute_force_dominators("r", graph)

    assert lt_doms == bf_doms


@pytest.mark.patent_invariant
def test_verify_dominance_holds_and_fails() -> None:
    """Verify verify_dominance correctly validates invariants and provides counterexamples."""
    graph = {
        "start": ["disclosure"],
        "disclosure": ["kyc_check"],
        "kyc_check": ["payout"],
        "payout": [],
    }

    # 1. kyc_check dominates payout
    res = verify_dominance("start", graph, precursor="kyc_check", targets=["payout"])
    assert res.satisfied is True
    assert "Dominance Verified" in res.summary()

    # 2. Add bypass transition bypassing kyc_check
    graph_bypass = {
        "start": ["disclosure", "fast_bypass"],
        "disclosure": ["kyc_check"],
        "kyc_check": ["payout"],
        "fast_bypass": ["payout"],
        "payout": [],
    }
    res_bypass = verify_dominance("start", graph_bypass, precursor="kyc_check", targets=["payout"])
    assert res_bypass.satisfied is False
    assert res_bypass.violating_target == "payout"
    assert res_bypass.violating_path == ("start", "fast_bypass", "payout")
    assert "Violating bypass path: start -> fast_bypass -> payout" in res_bypass.summary()


@pytest.mark.patent_invariant
def test_find_counterexample_path_edge_cases() -> None:
    """Verify counterexample path tracer handles root and direct edges."""
    graph = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
    # Precursor is root: cannot bypass root
    assert find_counterexample_path("A", graph, precursor="A", target="D") is None

    # Precursor is B: path A -> C -> D bypasses B
    path = find_counterexample_path("A", graph, precursor="B", target="D")
    assert path == ["A", "C", "D"]


def test_dominator_additional_coverage_branches() -> None:
    """Verify auxiliary dominator solver branches and unreachable target dominance."""
    # 1. Root not in graph
    empty_solver = LengauerTarjanSolver("missing_root", {})
    assert empty_solver.solve() == {}

    # 2. Target unreachable from root in verify_dominance
    disconnected_graph = {
        "start": ["step_a"],
        "step_a": [],
        "isolated": [],
    }
    res_unreachable = verify_dominance(
        "start", disconnected_graph, precursor="step_a", targets=["isolated"]
    )
    assert res_unreachable.satisfied is False
    assert res_unreachable.violating_target == "isolated"

    # 3. Precursor with predecessor unreachable from root
    unreachable_pred_graph = {
        "root": ["target"],
        "unreachable_node": ["target"],  # unreachable predecessor
        "target": [],
    }
    solver = LengauerTarjanSolver("root", unreachable_pred_graph)
    idoms = solver.solve()
    assert idoms["target"] == "root"



# =============================================================================
# Hypothesis Property-Based Dominator Equivalence Fuzzing (CAP-23)
# =============================================================================


@st.composite
def random_directed_graphs(draw: st.DrawFn) -> tuple[str, dict[str, list[str]]]:
    """Hypothesis strategy generating synthetic directed flowgraphs with 3 to 12 nodes."""
    node_count = draw(st.integers(min_value=3, max_value=12))
    nodes = [f"N{i}" for i in range(node_count)]
    root = nodes[0]

    graph: dict[str, list[str]] = {n: [] for n in nodes}

    # Ensure a basic spanning tree so several nodes are reachable
    for i in range(1, node_count):
        parent = draw(st.sampled_from(nodes[:i]))
        graph[parent].append(nodes[i])

    # Add random cross and back edges
    extra_edges = draw(st.integers(min_value=0, max_value=node_count * 2))
    for _ in range(extra_edges):
        u = draw(st.sampled_from(nodes))
        v = draw(st.sampled_from(nodes))
        if v not in graph[u]:
            graph[u].append(v)

    return root, graph


@settings(max_examples=500, deadline=None)
@given(random_directed_graphs())
def test_lengauer_tarjan_equivalence_to_brute_force(
    graph_tuple: tuple[str, dict[str, list[str]]],
) -> None:
    """Verify Lengauer-Tarjan dominators match brute-force path reachability (>=500 examples)."""
    root, graph = graph_tuple

    solver = LengauerTarjanSolver(root, graph)
    lt_dominators = solver.compute_all_dominators()
    bf_dominators = _brute_force_dominators(root, graph)

    assert lt_dominators == bf_dominators
