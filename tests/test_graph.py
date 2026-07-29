from sbom_forge.graph.models import PackageNode, Ecosystem
from sbom_forge.graph.builder import DependencyGraphBuilder
from sbom_forge.graph.analyzer import GraphAnalyzer


def test_dependency_graph_analysis():
    p1 = PackageNode(name="app", version="1.0.0", is_direct=True, dependencies=["liba@1.0.0", "libb@1.0.0"])
    p2 = PackageNode(name="liba", version="1.0.0", is_direct=False, dependencies=["core@2.0.0"])
    p3 = PackageNode(name="libb", version="1.0.0", is_direct=False, dependencies=["core@2.0.0"])
    p4 = PackageNode(name="core", version="2.0.0", is_direct=False, dependencies=[])

    packages = [p1, p2, p3, p4]

    builder = DependencyGraphBuilder()
    builder.build_from_packages(packages)

    analyzer = GraphAnalyzer(builder.graph, builder.nodes)
    nodes = analyzer.analyze()

    core_node = nodes["core@2.0.0"]
    # Both liba and libb depend on core, so core has high reach
    assert core_node.transitive_reach == 3  # app, liba, libb all depend on core
    assert core_node.betweenness_centrality >= 0.0
