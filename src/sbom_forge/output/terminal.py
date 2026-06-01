from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from sbom_forge.graph.models import ScanResult

console = Console()


def print_terminal_report(result: ScanResult) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]sbom-forge[/bold cyan] [bold white]Supply Chain Security Analysis[/bold white]\n"
            f"Project: [bold yellow]{result.project_name}[/bold yellow] | Ecosystem: [bold green]{result.root_ecosystem.value}[/bold green] | "
            f"Overall Risk Score: [bold red]{result.overall_risk_score}/10.0[/bold red]",
            border_style="cyan",
        )
    )

    # 1. Summary Statistics Table
    stats_table = Table(title="Dependency Tree Summary", show_header=True, header_style="bold magenta")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="bold white")

    stats_table.add_row("Total Packages in DAG", str(result.total_dependencies))
    stats_table.add_row("Direct Dependencies", str(result.direct_dependencies_count))
    stats_table.add_row("Transitive Dependencies", str(result.transitive_dependencies_count))
    stats_table.add_row("Known Vulnerabilities (CVEs)", str(len(result.vulnerabilities)))
    stats_table.add_row("Simulated Attack Paths", str(len(result.attack_paths)))

    console.print(stats_table)
    console.print()

    # 2. Top High Risk / Dependency Centrality Packages Table
    display_pkgs = result.high_risk_packages if result.high_risk_packages else list(result.nodes.values())
    if display_pkgs:
        risk_table = Table(title="Dependency Risk & Blast Radius Matrix", show_header=True, header_style="bold red")
        risk_table.add_column("Package Identifier", style="bold yellow")
        risk_table.add_column("Type", style="cyan")
        risk_table.add_column("Centrality", style="bold green")
        risk_table.add_column("Transitive Reach", style="bold blue")
        risk_table.add_column("CVEs", style="bold red")
        risk_table.add_column("Risk Score", style="bold magenta")

        sorted_display = sorted(display_pkgs, key=lambda p: p.risk_score, reverse=True)
        for pkg in sorted_display[:10]:
            dep_type = "Direct" if pkg.is_direct else "Transitive"
            cve_count = str(len(pkg.vulnerabilities))
            risk_table.add_row(
                pkg.identifier,
                dep_type,
                f"{pkg.betweenness_centrality:.4f}",
                str(pkg.transitive_reach),
                cve_count,
                f"{pkg.risk_score:.1f} / 10",
            )

        console.print(risk_table)
        console.print()

    # 3. AI Attack Path Simulation Results
    if result.attack_paths:
        console.print("[bold yellow]🤖 AI Supply Chain Attack Path Simulations[/bold yellow]")
        for path in result.attack_paths[:3]:
            content = (
                f"[bold red]Target Package:[/bold red] {path.target_package}\n"
                f"[bold yellow]Blast Radius:[/bold yellow] {path.blast_radius_percentage}% of total dependency tree\n"
                f"[bold cyan]MITRE ATT&CK:[/bold cyan] {', '.join(path.mitre_attack_techniques)}\n"
                f"[bold white]Data Exposure Risk:[/bold white] {path.data_exposure_risk}\n\n"
                f"[bold green]Recommended Mitigation:[/bold green] {path.recommended_mitigation}\n\n"
                f"[italic text-dim]{path.compromise_scenario}[/italic text-dim]"
            )
            console.print(Panel(content, title=f"Attack Simulation: {path.target_package}", border_style="red"))
            console.print()
