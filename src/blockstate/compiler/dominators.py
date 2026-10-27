"""Lengauer-Tarjan dominator tree solver, proofs, and counter-example tracer.

Computes immediate dominators, dominator trees, and verifies precursor dominance
in compliance-governed conversational statecharts. Emits counter-example paths
demonstrating the exact route bypassing required precursor stages upon proof failure.
"""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DominanceProofResult:
    """Outcome of a formal precursor dominance verification query."""

    satisfied: bool
    root: str
    precursor: str
    targets: tuple[str, ...]
    violating_target: str | None = None
    violating_path: tuple[str, ...] | None = None
    dominator_tree: dict[str, tuple[str, ...]] = field(default_factory=dict)
    immediate_dominators: dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        """Render a human-readable British English audit proof summary."""
        if self.satisfied:
            targets_str = ", ".join(self.targets)
            return (
                f"Dominance Verified: Precursor '{self.precursor}' dominates all paths "
                f"from root '{self.root}' to target(s) [{targets_str}]."
            )
        path_str = " -> ".join(self.violating_path or ())
        return (
            f"Dominance Violation: Precursor '{self.precursor}' does not dominate "
            f"target '{self.violating_target}'. Violating bypass path: {path_str}"
        )


class LengauerTarjanSolver:
    """Lengauer-Tarjan dominator tree solver for directed flowgraphs."""

    def __init__(self, root: str, graph: Mapping[str, Iterable[str]]) -> None:
        self.root = root
        # Normalise graph to adjacency dictionary
        self.adj: dict[str, list[str]] = {u: list(vs) for u, vs in graph.items()}
        # Ensure all referenced target nodes exist in adj
        for vs in list(self.adj.values()):
            for v in vs:
                if v not in self.adj:
                    self.adj[v] = []

        self.pred: dict[str, list[str]] = {u: [] for u in self.adj}
        for u, vs in self.adj.items():
            for v in vs:
                self.pred[v].append(u)

        # Algorithm state
        self.dfnum: dict[str, int] = {}
        self.vertex: list[str] = [""]  # 1-indexed
        self.parent: dict[str, str] = {}
        self.semi: dict[str, int] = {}
        self.idom: dict[str, str] = {}
        self.ancestor: dict[str, str] = {}
        self.best: dict[str, str] = {}
        self.bucket: dict[str, list[str]] = {u: [] for u in self.adj}
        self._solved: bool = False

    def solve(self) -> dict[str, str]:
        """Execute Lengauer-Tarjan algorithm and return immediate dominators mapping.

        Returns a dictionary mapping each reachable node (excluding root) to its
        immediate dominator.
        """
        if self._solved:
            return self.idom

        if self.root not in self.adj:
            return {}

        # 1. Depth-First Search numbering
        self._dfs(self.root)
        n = len(self.vertex) - 1

        # 2. Compute semi-dominators and initial dominators in reverse DFS order
        for i in range(n, 1, -1):
            w = self.vertex[i]
            p = self.parent[w]

            # Calculate semi(w)
            for v in self.pred[w]:
                if v not in self.dfnum:
                    continue  # v is not reachable from root
                u = self._eval(v)
                if self.semi[u] < self.semi[w]:
                    self.semi[w] = self.semi[u]

            s_node = self.vertex[self.semi[w]]
            self.bucket[s_node].append(w)
            self._link(p, w)

            # Process bucket of parent
            for v in list(self.bucket[p]):
                u = self._eval(v)
                self.idom[v] = p if self.semi[u] >= self.semi[v] else u
            self.bucket[p].clear()

        # 3. Finalise immediate dominators in forward DFS order
        for i in range(2, n + 1):
            w = self.vertex[i]
            s_node = self.vertex[self.semi[w]]
            if self.idom[w] != s_node:
                self.idom[w] = self.idom[self.idom[w]]

        self._solved = True
        return self.idom

    def compute_dominator_tree(self) -> dict[str, tuple[str, ...]]:
        """Construct the dominator tree mapping each dominator to immediately dominated children."""
        idoms = self.solve()
        tree: dict[str, list[str]] = {self.root: []}
        for u in idoms:
            tree.setdefault(u, [])
        for node, dom in idoms.items():
            tree.setdefault(dom, []).append(node)
        return {k: tuple(sorted(vs)) for k, vs in tree.items()}

    def compute_all_dominators(self) -> dict[str, set[str]]:
        """Compute the complete set of strict and non-strict dominators for each reachable node."""
        idoms = self.solve()
        all_doms: dict[str, set[str]] = {self.root: {self.root}}
        # Process in topological / DFS order
        for i in range(2, len(self.vertex)):
            w = self.vertex[i]
            p_idom = idoms.get(w)
            if p_idom and p_idom in all_doms:
                all_doms[w] = all_doms[p_idom] | {w}
            else:
                all_doms[w] = {w}
        return all_doms

    def _dfs(self, root: str) -> None:
        """Perform iterative or recursive DFS to compute pre-order numbers."""
        count = 0
        stack: list[tuple[str, int]] = [(root, 0)]
        visited: set[str] = {root}

        count += 1
        self.dfnum[root] = count
        self.vertex.append(root)
        self.semi[root] = count
        self.best[root] = root

        while stack:
            u, idx = stack[-1]
            children = self.adj.get(u, [])

            if idx < len(children):
                stack[-1] = (u, idx + 1)
                v = children[idx]
                if v not in visited:
                    visited.add(v)
                    count += 1
                    self.dfnum[v] = count
                    self.vertex.append(v)
                    self.parent[v] = u
                    self.semi[v] = count
                    self.best[v] = v
                    stack.append((v, 0))
            else:
                stack.pop()

    def _eval(self, v: str) -> str:
        """Find the vertex with minimum semi-dominator along ancestor path with compression."""
        if v not in self.ancestor:
            return self.best[v]
        self._compress(v)
        return self.best[v]

    def _compress(self, v: str) -> None:
        """Path compression helper."""
        a = self.ancestor.get(v)
        if a and a in self.ancestor:
            self._compress(a)
            if self.semi[self.best[a]] < self.semi[self.best[v]]:
                self.best[v] = self.best[a]
            self.ancestor[v] = self.ancestor[a]

    def _link(self, v: str, w: str) -> None:
        """Link tree helper."""
        self.ancestor[w] = v


def find_counterexample_path(
    root: str,
    graph: Mapping[str, Iterable[str]],
    precursor: str,
    target: str,
) -> list[str] | None:
    """Find a concrete directed path from root to target that bypasses precursor."""
    if root == precursor:
        # Precursor is root; cannot be bypassed if target is reached from root
        return None

    visited: set[str] = {root, precursor}
    queue: deque[list[str]] = deque([[root]])

    while queue:
        path = queue.popleft()
        curr = path[-1]
        if curr == target:
            return path

        for nxt in graph.get(curr, ()):
            if nxt not in visited:
                visited.add(nxt)
                queue.append([*path, nxt])

    return None


def verify_dominance(
    root: str,
    graph: Mapping[str, Iterable[str]],
    precursor: str,
    targets: Iterable[str],
) -> DominanceProofResult:
    """Verify whether precursor dominates every path from root to all specified target stages.

    Returns DominanceProofResult containing formal certification or the exact
    counter-example path bypassing the precursor.
    """
    target_tuple = tuple(sorted(set(targets)))
    solver = LengauerTarjanSolver(root, graph)
    idoms = solver.solve()
    dom_tree = solver.compute_dominator_tree()
    all_doms = solver.compute_all_dominators()

    for target in target_tuple:
        # Check if precursor dominates target
        target_doms = all_doms.get(target)
        if target_doms is None:
            # Target is unreachable from root
            return DominanceProofResult(
                satisfied=False,
                root=root,
                precursor=precursor,
                targets=target_tuple,
                violating_target=target,
                violating_path=(),
                dominator_tree=dom_tree,
                immediate_dominators=idoms,
            )

        if precursor not in target_doms:
            # Precursor does NOT dominate target; find violating bypass path
            violating_path = find_counterexample_path(root, graph, precursor, target)
            return DominanceProofResult(
                satisfied=False,
                root=root,
                precursor=precursor,
                targets=target_tuple,
                violating_target=target,
                violating_path=tuple(violating_path) if violating_path else (root, target),
                dominator_tree=dom_tree,
                immediate_dominators=idoms,
            )

    return DominanceProofResult(
        satisfied=True,
        root=root,
        precursor=precursor,
        targets=target_tuple,
        violating_target=None,
        violating_path=None,
        dominator_tree=dom_tree,
        immediate_dominators=idoms,
    )


__all__: list[str] = [
    "DominanceProofResult",
    "LengauerTarjanSolver",
    "find_counterexample_path",
    "verify_dominance",
]
