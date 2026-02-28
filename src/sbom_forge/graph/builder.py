from typing import Dict, List, Tuple
import networkx as nx
from sbom_forge.graph.models import PackageNode


class DependencyGraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, PackageNode] = {}

    def add_package(self, package: PackageNode) -> None:
        key = package.identifier
        self.nodes[key] = package
        self.graph.add_node(
            key,
            name=package.name,
            version=package.version,
            ecosystem=package.ecosystem.value,
            is_direct=package.is_direct,
            is_dev=package.is_dev,
        )

    def add_dependency(self, parent_id: str, child_id: str) -> None:
        if parent_id in self.graph and child_id in self.graph:
            self.graph.add_edge(parent_id, child_id)

    def build_from_packages(self, packages: List[PackageNode]) -> nx.DiGraph:
        for pkg in packages:
            self.add_package(pkg)

        for pkg in packages:
            parent_id = pkg.identifier
            for dep_id in pkg.dependencies:
                if dep_id in self.nodes:
                    self.add_dependency(parent_id, dep_id)

        return self.graph

    def get_root_nodes(self) -> List[str]:
        return [node for node, in_degree in self.graph.in_degree() if in_degree == 0]

    def get_leaf_nodes(self) -> List[str]:
        return [node for node, out_degree in self.graph.out_degree() if out_degree == 0]
