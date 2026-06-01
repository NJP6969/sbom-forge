import json
from typing import Dict
from sbom_forge.graph.models import ScanResult


def generate_sarif_report(result: ScanResult) -> str:
    rules = [
        {
            "id": "SBOM-FORGE-HIGH-RISK-DEP",
            "name": "HighRiskSupplyChainDependency",
            "shortDescription": {"text": "High risk supply chain dependency detected"},
            "fullDescription": {"text": "Package has high centrality or known vulnerability blast radius"},
            "properties": {"security-severity": "8.0"},
        },
        {
            "id": "SBOM-FORGE-MISSING-INTEGRITY",
            "name": "MissingIntegrityHash",
            "shortDescription": {"text": "Dependency missing cryptographic integrity hash"},
            "properties": {"security-severity": "6.5"},
        },
    ]

    results = []
    for pkg in result.high_risk_packages:
        if pkg.risk_score >= 6.0:
            results.append({
                "ruleId": "SBOM-FORGE-HIGH-RISK-DEP",
                "level": "error" if pkg.risk_score >= 8.0 else "warning",
                "message": {
                    "text": f"Package '{pkg.identifier}' has risk score {pkg.risk_score}/10. Centrality: {pkg.betweenness_centrality}, Transitive reach: {pkg.transitive_reach} packages."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "package-lock.json"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sbom-forge",
                        "semanticVersion": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
