from typing import List
from sbom_forge.graph.models import AttackPath, PackageNode
from sbom_forge.ai.ollama_client import OllamaClient
from sbom_forge.ai.prompts import SYSTEM_SECURITY_ANALYZER_PROMPT, ATTACK_SIMULATION_TEMPLATE


class AttackSimulator:
    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client

    def simulate_attack_path(self, package: PackageNode, total_deps: int) -> AttackPath:
        has_ollama = self.client.is_available()

        if has_ollama:
            vuln_summary = ", ".join([v.id for v in package.vulnerabilities]) if package.vulnerabilities else "None"
            prompt = ATTACK_SIMULATION_TEMPLATE.format(
                package_name=package.name,
                package_version=package.version,
                ecosystem=package.ecosystem.value,
                centrality=package.betweenness_centrality,
                reach=package.transitive_reach,
                is_direct="Yes" if package.is_direct else "No",
                is_dev="Yes" if package.is_dev else "No",
                vulnerability_count=len(package.vulnerabilities),
                vulnerability_summary=vuln_summary,
                has_hash="Yes" if package.integrity_hash else "No (High Risk)",
            )

            response_text = self.client.generate_reasoning(prompt, SYSTEM_SECURITY_ANALYZER_PROMPT)
            if response_text:
                return self._parse_llm_response(package, response_text, total_deps)

        # Fallback heuristic generator if Ollama is offline
        return self._heuristic_fallback(package, total_deps)

    def _parse_llm_response(self, package: PackageNode, llm_text: str, total_deps: int) -> AttackPath:
        blast_pct = round((package.transitive_reach / max(1, total_deps)) * 100, 2)
        
        # Extract MITRE techniques mentioned or default
        techniques = []
        if "T1195" in llm_text:
            techniques.append("T1195.001 (Supply Chain Compromise)")
        if "T1059" in llm_text:
            techniques.append("T1059 (Command and Scripting Interpreter)")
        if not techniques:
            techniques = ["T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)"]

        return AttackPath(
            target_package=package.identifier,
            compromise_scenario=llm_text[:300] + "...",
            blast_radius_percentage=blast_pct,
            affected_packages=[f"Transitively affects {package.transitive_reach} downstream modules"],
            mitre_attack_techniques=techniques,
            data_exposure_risk="HIGH: Malicious lifecycle scripts (postinstall) can access process environment & tokens",
            recommended_mitigation="Enforce sha512 hash-pinning in lockfile, set ignore-scripts=true, and audit maintainer provenance.",
        )

    def _heuristic_fallback(self, package: PackageNode, total_deps: int) -> AttackPath:
        blast_pct = round((package.transitive_reach / max(1, total_deps)) * 100, 2)
        return AttackPath(
            target_package=package.identifier,
            compromise_scenario=f"Hypothetical compromise of {package.name} via maintainer account takeover or malicious publish.",
            blast_radius_percentage=blast_pct,
            affected_packages=[f"{package.transitive_reach} downstream dependent packages"],
            mitre_attack_techniques=["T1195.001 (Supply Chain Compromise)", "T1059 (Execution)"],
            data_exposure_risk="CRITICAL: Full process environment variable access & token exfiltration risk",
            recommended_mitigation=f"Pin exact integrity hash for {package.identifier} and restrict build-time script execution.",
        )
