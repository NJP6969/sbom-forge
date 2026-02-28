from typing import Dict, List, Set, Tuple
import networkx as nx
from sbom_forge.graph.models import PackageNode


class GraphAnalyzer:
    def __init__(self, graph: nx.DiGraph, nodes: Dict[str, PackageNode]):
        self.graph = graph
        self.nodes = nodes

    def calculate_betweenness_centrality(self) -> Dict[str, float]:
        if len(self.graph) == 0:
            return {}
        try:
            centrality = nx.betweenness_centrality(self.graph)
        except Exception:
            centrality = {node: 0.0 for node in self.graph.nodes}

        for node_id, score in centrality.items():
            if node_id in self.nodes:
                self.nodes[node_id].betweenness_centrality = round(score, 4)

        return centrality

    def calculate_transitive_reach(self) -> Dict[str, int]:
        # Reversed graph to find how many nodes depend on a target node
        reversed_graph = self.graph.reverse()
        reach_map = {}

        for node_id in self.graph.nodes:
            # Nodes reachable in reversed graph = nodes that depend on node_id
            ancestors = nx.descendants(reversed_graph, node_id)
            reach_count = len(ancestors)
            reach_map[node_id] = reach_count
            if node_id in self.nodes:
                self.nodes[node_id].transitive_reach = reach_count

        return reach_map

    def calculate_depths(self) -> Dict[str, int]:
        depth_map = {}
        roots = [node for node, in_deg in self.graph.in_degree() if in_deg == 0]

        for node_id in self.graph.nodes:
            max_depth = 0
            for root in roots:
                try:
                    paths = nx.all_simple_paths(self.graph, root, node_id)
                    for path in paths:
                        max_depth = max(max_depth, len(path) - 1)
                except Exception:
                    pass
            depth_map[node_id] = max_depth
            if node_id in self.nodes:
                self.nodes[node_id].depth = max_depth

        return depth_map

    def analyze(self) -> Dict[str, PackageNode]:
        self.calculate_betweenness_centrality()
        self.calculate_transitive_reach()
        self.calculate_depths()
        return self.nodes
