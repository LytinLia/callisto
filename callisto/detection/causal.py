"""CRS — Causal Responsibility Scoring.

Core contribution #1: Applies Shapley-value causal attribution on
tool-call dependency DAGs to identify which invocations are causally
responsible for driving a session toward a dangerous state.

This solves the STAC problem: individually benign calls that form
dangerous chains are identified by their causal contribution.
"""

from __future__ import annotations

import random
import time
import numpy as np
import networkx as nx
from dataclasses import dataclass
from typing import Callable

from callisto.collector.models import CallEvent, Alert, RiskLevel, AttackType


@dataclass
class CRSResult:
    """Per-node causal responsibility scores."""

    scores: dict[str, float]  # event_id -> CRS score in [0, 1]
    critical_path: list[str]  # event_ids on the highest-responsibility path
    max_score: float = 0.0


# ---------------------------------------------------------------------------
# Safety evaluation functions φ(S) — score how "dangerous" a subset of
# calls is.  Pluggable; we provide a default composite scorer.
# ---------------------------------------------------------------------------

def default_safety_scorer(
    graph: nx.DiGraph,
    active_nodes: set[str],
    tool_risk: dict[str, float] | None = None,
) -> float:
    """Composite safety score φ(S) ∈ [0, 1].

    Factors:
    1. Sensitive tool presence (file write, exec, network)
    2. Chain length of active subgraph
    3. Data-flow connectivity (how much information flows end-to-end)

    Operates directly on the original graph filtered by active_nodes,
    avoiding nx.subgraph() overhead in the inner Shapley loop.
    """
    if not active_nodes:
        return 0.0

    if tool_risk is None:
        tool_risk = _DEFAULT_TOOL_RISK

    # Factor 1: max risk of any active tool
    max_risk = 0.0
    for n in active_nodes:
        tool = graph.nodes[n].get("tool", "")
        r = tool_risk.get(tool, 0.1)
        if r > max_risk:
            max_risk = r

    # Factor 2: longest path among active nodes (Kahn's DP, no subgraph)
    in_deg: dict[str, int] = {n: 0 for n in active_nodes}
    adj: dict[str, list[str]] = {n: [] for n in active_nodes}
    for n in active_nodes:
        for succ in graph.successors(n):
            if succ in active_nodes:
                adj[n].append(succ)
                in_deg[succ] += 1

    queue = [n for n in active_nodes if in_deg[n] == 0]
    dist: dict[str, int] = {n: 0 for n in active_nodes}
    chain_len = 0
    while queue:
        node = queue.pop()
        for succ in adj[node]:
            d = dist[node] + 1
            if d > dist[succ]:
                dist[succ] = d
            if d > chain_len:
                chain_len = d
            in_deg[succ] -= 1
            if in_deg[succ] == 0:
                queue.append(succ)
    chain_score = min(chain_len / 10.0, 1.0)

    # Factor 3: dataflow edge ratio among active nodes
    df_edges = 0
    for n in active_nodes:
        for succ in adj[n]:
            if graph.edges[n, succ].get("kind") == "dataflow":
                df_edges += 1
    df_score = min(df_edges / max(len(active_nodes), 1), 1.0)

    return 0.5 * max_risk + 0.3 * chain_score + 0.2 * df_score


_DEFAULT_TOOL_RISK: dict[str, float] = {
    "exec": 0.95, "shell": 0.95, "run_command": 0.95,
    "write_file": 0.7, "delete_file": 0.8,
    "send_email": 0.6, "http_request": 0.6, "curl": 0.7,
    "read_file": 0.3, "search": 0.2, "list_files": 0.1,
}


# ---------------------------------------------------------------------------
# Core CRS Algorithm — Shapley-based causal responsibility scoring
# ---------------------------------------------------------------------------

class CausalResponsibilityScorer:
    """Compute Shapley-value causal responsibility for each node in a call DAG.

    Algorithm:
        For each node vᵢ, approximate its Shapley value by sampling k random
        permutations and computing the marginal contribution of vᵢ to the
        safety score φ when added to the coalition of nodes preceding it.

    Complexity: O(k · |V| · cost(φ))  where k = num_samples
    """

    def __init__(
        self,
        num_samples: int = 30,
        threshold: float = 0.7,
        safety_fn: Callable[..., float] | None = None,
        seed: int = 42,
    ):
        self.num_samples = num_samples
        self.threshold = threshold
        self.safety_fn = safety_fn or default_safety_scorer
        self.rng = random.Random(seed)

    def _cached_safety(
        self,
        graph: nx.DiGraph,
        coalition: set[str],
        cache: dict[frozenset[str], float],
    ) -> float:
        """Evaluate safety_fn with coalition caching."""
        key = frozenset(coalition)
        if key not in cache:
            cache[key] = self.safety_fn(graph, coalition)
        return cache[key]

    def _process_permutation(
        self,
        perm: list[str],
        graph: nx.DiGraph,
        shapley: dict[str, float],
        cache: dict[frozenset[str], float],
        weight: float,
    ) -> None:
        """Accumulate marginal contributions for a single permutation."""
        prev_score = 0.0
        coalition: set[str] = set()
        for nid in perm:
            coalition.add(nid)
            curr_score = self._cached_safety(graph, coalition, cache)
            shapley[nid] += (curr_score - prev_score) * weight
            prev_score = curr_score

    def score(self, graph: nx.DiGraph) -> CRSResult:
        """Compute CRS for all nodes in the graph."""
        nodes = list(graph.nodes())
        n = len(nodes)
        if n == 0:
            return CRSResult(scores={}, critical_path=[], max_score=0.0)

        # Gate: if the full graph's safety score is low, skip expensive Shapley
        full_safety = self.safety_fn(graph, set(nodes))
        if full_safety < 0.68:
            return CRSResult(
                scores={nid: 0.0 for nid in nodes},
                critical_path=[],
                max_score=0.0,
            )

        shapley = {nid: 0.0 for nid in nodes}
        cache: dict[frozenset[str], float] = {}
        prev_shapley = {nid: 0.0 for nid in nodes}

        # Each iteration produces 2 samples (forward + antithetic reverse)
        sample_count = 0
        total_samples = self.num_samples

        for i in range(total_samples // 2 + total_samples % 2):
            perm = nodes[:]
            self.rng.shuffle(perm)

            # Forward permutation
            self._process_permutation(
                perm, graph, shapley, cache, 1.0 / total_samples,
            )
            sample_count += 1

            # Antithetic (reverse) permutation — skip if we've hit the cap
            if sample_count < total_samples:
                self._process_permutation(
                    perm[::-1], graph, shapley, cache, 1.0 / total_samples,
                )
                sample_count += 1

            # Early termination: check every 10 samples
            if sample_count % 10 == 0 and sample_count >= 10:
                max_delta = max(
                    abs(shapley[nid] - prev_shapley[nid]) for nid in nodes
                )
                if max_delta < 0.01:
                    break
                prev_shapley = {nid: shapley[nid] for nid in nodes}

        # Normalize to [0, 1]
        max_val = max(shapley.values()) if shapley else 1.0
        if max_val > 1e-9:
            scores = {k: v / max_val for k, v in shapley.items()}
        else:
            scores = {k: 0.0 for k in shapley}

        # Extract critical path: nodes with score above threshold, in topo order
        critical = {nid for nid, s in scores.items() if s >= self.threshold}
        if critical and nx.is_directed_acyclic_graph(graph):
            topo = list(nx.topological_sort(graph))
            critical_path = [n for n in topo if n in critical]
        else:
            critical_path = sorted(critical, key=lambda x: scores[x], reverse=True)

        return CRSResult(
            scores=scores,
            critical_path=critical_path,
            max_score=max(scores.values()) if scores else 0.0,
        )

    def detect(self, graph: nx.DiGraph) -> Alert | None:
        """Run CRS and return an Alert if the max score exceeds threshold."""
        result = self.score(graph)
        if result.max_score < self.threshold:
            return None

        return Alert(
            timestamp=time.time(),
            risk_level=RiskLevel.HIGH if result.max_score > 0.85 else RiskLevel.MEDIUM,
            attack_type=AttackType.A2_PRIV_ESCALATION,
            source_module="CRS",
            trigger_events=result.critical_path,
            score=result.max_score,
            explanation=(
                f"Causal analysis identified {len(result.critical_path)} critical "
                f"nodes forming a dangerous tool chain (max CRS={result.max_score:.3f})"
            ),
        )
