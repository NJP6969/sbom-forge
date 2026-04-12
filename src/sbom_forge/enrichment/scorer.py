from typing import Dict, List
from sbom_forge.graph.models import PackageNode, ScanResult
from sbom_forge.enrichment.registry import detect_typosquatting


class RiskScorer:
    def calculate_package_risk(self, package: PackageNode) -> float:
        score = 0.0

        # 1. Centrality & Blast Radius (Up to 3.5 points)
        score += package.betweenness_centrality * 3.5
        if package.transitive_reach > 10:
            score += 1.0

        # 2. Known Vulnerabilities (Up to 4.0 points)
        for vuln in package.vulnerabilities:
            if vuln.severity == "CRITICAL":
                score += 3.0
            elif vuln.severity == "HIGH":
                score += 2.0
            elif vuln.severity == "MEDIUM":
                score += 1.0
            elif vuln.severity == "LOW":
                score += 0.5

        # 3. Missing Integrity Hash (+1.5 points)
        if not package.integrity_hash and package.is_direct:
            score += 1.5

        # 4. Typosquatting Candidate Flag (+3.0 points)
        if detect_typosquatting(package.name):
            score += 3.0

        # Cap score at 10.0
        final_score = min(10.0, round(score, 2))
        package.risk_score = final_score
        return final_score

    def score_scan_result(self, nodes: Dict[str, PackageNode]) -> float:
        if not nodes:
            return 0.0

        scores = [self.calculate_package_risk(node) for node in nodes.values()]
        avg_score = sum(scores) / len(scores)
        max_score = max(scores) if scores else 0.0

        # Weighted score emphasizing top high-risk packages
        overall = (0.7 * max_score) + (0.3 * avg_score)
        return round(overall, 2)
