from sbom_forge.graph.models import PackageNode, VulnerabilityFinding
from sbom_forge.enrichment.scorer import RiskScorer
from sbom_forge.enrichment.registry import detect_typosquatting


def test_typosquatting_detection():
    assert detect_typosquatting("expresss") is True  # Typo candidate for express
    assert detect_typosquatting("express") is False   # Legitimate
    assert detect_typosquatting("my-custom-pkg-xyz") is False


def test_risk_scorer():
    scorer = RiskScorer()
    clean_pkg = PackageNode(name="express", version="4.18.2", integrity_hash="sha512-xxx")
    clean_score = scorer.calculate_package_risk(clean_pkg)
    assert clean_score < 4.0

    vuln_pkg = PackageNode(
        name="expresss",
        version="1.0.0",
        betweenness_centrality=0.8,
        transitive_reach=15,
        vulnerabilities=[VulnerabilityFinding(id="CVE-2021-0001", summary="RCE", severity="CRITICAL")],
    )
    vuln_score = scorer.calculate_package_risk(vuln_pkg)
    assert vuln_score >= 8.0
