import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from sbom_forge.parsers import detect_and_parse
from sbom_forge.graph import DependencyGraphBuilder, GraphAnalyzer, ScanResult, Ecosystem
from sbom_forge.enrichment import OSVClient, RiskScorer
from sbom_forge.ai import OllamaClient, AttackSimulator
from sbom_forge.output import (
    print_terminal_report,
    generate_sarif_report,
    generate_cyclonedx_sbom,
    generate_spdx_sbom,
    generate_hardened_npmrc,
    generate_pip_constraints,
)

app = typer.Typer(
    name="sbom-forge",
    help="AI-Powered Supply Chain Attack Surface Analyzer and Hardener",
    add_completion=False,
)
console = Console()


def _run_core_scan(target_dir: Path, ollama_model: str = "llama3.1", run_ai: bool = True) -> ScanResult:
    packages, parser = detect_and_parse(target_dir)

    if not packages:
        console.print(f"[bold red]Error:[/bold red] No supported dependency manifest found in {target_dir}")
        console.print("Supported files: package-lock.json, requirements.txt, go.sum")
        sys.exit(1)

    # 1. Build & Analyze Graph
    builder = DependencyGraphBuilder()
    builder.build_from_packages(packages)
    analyzer = GraphAnalyzer(builder.graph, builder.nodes)
    analyzed_nodes = analyzer.analyze()

    # 2. Query OSV.dev for CVE Vulnerabilities
    osv_client = OSVClient()
    all_vulns = []
    for node in analyzed_nodes.values():
        vulns = osv_client.fetch_vulnerabilities(node)
        node.vulnerabilities = vulns
        all_vulns.extend(vulns)

    # 3. Calculate Composite Risk Scores
    scorer = RiskScorer()
    overall_score = scorer.score_scan_result(analyzed_nodes)

    # 4. Rank High Risk Packages
    sorted_packages = sorted(analyzed_nodes.values(), key=lambda p: p.risk_score, reverse=True)
    high_risk = [p for p in sorted_packages if p.risk_score >= 4.0]

    # 5. Run AI Attack Path Simulation
    attack_paths = []
    if run_ai and high_risk:
        ollama_client = OllamaClient(model=ollama_model)
        simulator = AttackSimulator(ollama_client)
        for top_pkg in high_risk[:3]:
            path = simulator.simulate_attack_path(top_pkg, len(analyzed_nodes))
            attack_paths.append(path)

    direct_count = sum(1 for p in analyzed_nodes.values() if p.is_direct)
    transitive_count = len(analyzed_nodes) - direct_count
    root_eco = packages[0].ecosystem if packages else Ecosystem.UNKNOWN

    return ScanResult(
        project_name=target_dir.resolve().name,
        root_ecosystem=root_eco,
        total_dependencies=len(analyzed_nodes),
        direct_dependencies_count=direct_count,
        transitive_dependencies_count=transitive_count,
        overall_risk_score=overall_score,
        high_risk_packages=high_risk,
        vulnerabilities=all_vulns,
        attack_paths=attack_paths,
        nodes=analyzed_nodes,
    )


@app.command(name="scan")
def scan_cmd(
    target_path: Path = typer.Argument(Path("."), help="Path to project directory or lockfile"),
    ollama_model: str = typer.Option("llama3.1", "--model", "-m", help="Ollama LLM model to use"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable Ollama AI attack path simulation"),
    sarif_out: Optional[Path] = typer.Option(None, "--sarif", help="Export SARIF report file"),
):
    """Scan a project for supply chain risk, blast radius, and AI attack paths."""
    result = _run_core_scan(target_path, ollama_model=ollama_model, run_ai=not no_ai)
    print_terminal_report(result)

    if sarif_out:
        sarif_content = generate_sarif_report(result)
        with open(sarif_out, "w", encoding="utf-8") as f:
            f.write(sarif_content)
        console.print(f"[bold green]✓ SARIF report saved to {sarif_out}[/bold green]")


@app.command(name="sbom")
def sbom_cmd(
    target_path: Path = typer.Argument(Path("."), help="Path to project directory or lockfile"),
    format_type: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format: cyclonedx or spdx"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Generate a CycloneDX or SPDX compliant SBOM."""
    result = _run_core_scan(target_path, run_ai=False)
    if format_type.lower() == "spdx":
        sbom_str = generate_spdx_sbom(result)
    else:
        sbom_str = generate_cyclonedx_sbom(result)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(sbom_str)
        console.print(f"[bold green]✓ {format_type.upper()} SBOM exported to {output_file}[/bold green]")
    else:
        console.print(sbom_str)


@app.command(name="harden")
def harden_cmd(
    target_path: Path = typer.Argument(Path("."), help="Path to project directory"),
):
    """Generate hardened lockfiles, .npmrc, and security constraints."""
    result = _run_core_scan(target_path, run_ai=False)
    target_dir = target_path if target_path.is_dir() else target_path.parent

    if result.root_ecosystem == Ecosystem.NPM:
        out_npm = generate_hardened_npmrc(target_dir)
        console.print(f"[bold green]✓ Generated hardened .npmrc at {out_npm}[/bold green]")
    elif result.root_ecosystem == Ecosystem.PYPI:
        out_pip = generate_pip_constraints(result, target_dir)
        console.print(f"[bold green]✓ Generated pinned constraints.txt at {out_pip}[/bold green]")
    else:
        console.print("[bold yellow]No specific hardener for ecosystem, policy check complete.[/bold yellow]")


@app.command(name="ci")
def ci_cmd(
    target_path: Path = typer.Argument(Path("."), help="Path to project directory"),
    threshold: float = typer.Option(7.0, "--threshold", "-t", help="Risk score threshold to fail CI build"),
    no_ai: bool = typer.Option(True, "--no-ai", help="Disable AI layer in CI for speed"),
):
    """CI/CD mode: Fails with exit code 1 if risk score exceeds threshold."""
    result = _run_core_scan(target_path, run_ai=not no_ai)
    print_terminal_report(result)

    if result.overall_risk_score >= threshold:
        console.print(
            f"\n[bold red]❌ CI BUILD FAILED: Risk score {result.overall_risk_score} exceeds threshold {threshold}[/bold red]"
        )
        sys.exit(1)
    else:
        console.print(
            f"\n[bold green]✅ CI BUILD PASSED: Risk score {result.overall_risk_score} below threshold {threshold}[/bold green]"
        )


if __name__ == "__main__":
    app()
