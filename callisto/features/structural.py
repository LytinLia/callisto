"""Structural feature extraction — tool-call dependency DAG construction.

Builds a directed acyclic graph from tool call sequences based on
data-flow and control-flow dependencies, then extracts graph-level features.
"""

from __future__ import annotations

import numpy as np
import networkx as nx
from dataclasses import dataclass

from callisto.collector.models import CallEvent, EventType


@dataclass
class StructuralFeatures:
    """Graph-level features from the call dependency DAG."""

    num_nodes: int = 0
    num_edges: int = 0
    density: float = 0.0
    max_depth: int = 0
    max_fan_out: int = 0
    avg_fan_out: float = 0.0
    num_connected_components: int = 0
    has_cycle: bool = False
    longest_path_len: int = 0
    unique_tools: int = 0

    def to_vector(self) -> np.ndarray:
        return np.array([
            self.num_nodes, self.num_edges, self.density,
            self.max_depth, self.max_fan_out, self.avg_fan_out,
            self.num_connected_components, float(self.has_cycle),
            self.longest_path_len, self.unique_tools,
        ])


def _extract_strings(obj: object) -> list[str]:
    """Recursively extract all string-typed values from nested dicts/lists."""
    results: list[str] = []
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_strings(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            results.extend(_extract_strings(item))
    return results


class DAGBuilder:
    """Builds a tool-call dependency DAG from a sequence of CallEvents."""

    def __init__(
        self,
        min_snippet_len: int = 16,
        trivial_values: set[str] | None = None,
    ):
        self.min_snippet_len = min_snippet_len
        self.trivial_values: set[str] = (
            trivial_values if trivial_values is not None
            else {"true", "false", "null", "0", "1", "none", "ok", ""}
        )

    def build(self, events: list[CallEvent]) -> nx.DiGraph:
        """Construct dependency DAG using data-flow heuristics.

        Edges are added when:
        1. A tool_result feeds into the next tool_call (sequential data flow)
        2. Parameter values reference prior result identifiers (explicit data flow)
        """
        g = nx.DiGraph()
        call_events = [e for e in events if e.event_type == EventType.TOOL_CALL]

        for e in call_events:
            g.add_node(e.event_id, tool=e.tool_name, ts=e.timestamp, params=e.parameters)

        # Sequential dependency: each call depends on the previous call
        for i in range(1, len(call_events)):
            g.add_edge(call_events[i - 1].event_id, call_events[i].event_id, kind="sequential")

        # Data-flow dependency: if a parameter value matches a prior result
        result_map: dict[str, str] = {}  # result_snippet -> event_id
        for e in events:
            if e.event_type == EventType.TOOL_RESULT and e.result is not None:
                snippet = str(e.result)[:128]
                if len(snippet) < self.min_snippet_len:
                    continue
                if snippet.strip().lower() in self.trivial_values:
                    continue
                result_map[snippet] = e.event_id

        for e in call_events:
            param_strings = _extract_strings(e.parameters)
            for snippet, source_id in result_map.items():
                if source_id == e.event_id:
                    continue
                if any(snippet in pval for pval in param_strings):
                    if not g.has_edge(source_id, e.event_id):
                        g.add_edge(source_id, e.event_id, kind="dataflow")

        return g


class StructuralExtractor:
    """Extract graph-level features from a call dependency DAG."""

    def __init__(
        self,
        min_snippet_len: int = 16,
        trivial_values: set[str] | None = None,
    ):
        self.builder = DAGBuilder(
            min_snippet_len=min_snippet_len,
            trivial_values=trivial_values,
        )

    def extract(self, events: list[CallEvent]) -> tuple[nx.DiGraph, StructuralFeatures]:
        g = self.builder.build(events)

        if g.number_of_nodes() == 0:
            return g, StructuralFeatures()

        fan_outs = [g.out_degree(n) for n in g.nodes()]
        has_cycle = not nx.is_directed_acyclic_graph(g)

        longest_path = 0
        if not has_cycle:
            try:
                longest_path = nx.dag_longest_path_length(g)
            except nx.NetworkXError:
                longest_path = 0

        tools = set(nx.get_node_attributes(g, "tool").values())

        feats = StructuralFeatures(
            num_nodes=g.number_of_nodes(),
            num_edges=g.number_of_edges(),
            density=nx.density(g),
            max_depth=longest_path,
            max_fan_out=max(fan_outs) if fan_outs else 0,
            avg_fan_out=float(np.mean(fan_outs)) if fan_outs else 0.0,
            num_connected_components=nx.number_weakly_connected_components(g),
            has_cycle=has_cycle,
            longest_path_len=longest_path,
            unique_tools=len(tools),
        )
        return g, feats
