import httpx
from typing import Dict, List, Optional
from sbom_forge.graph.models import Ecosystem, PackageNode, VulnerabilityFinding

OSV_API_URL = "https://api.osv.dev/v1/query"

# Map our Ecosystem enum to OSV API ecosystem names
ECOSYSTEM_MAP = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.GO: "Go",
    Ecosystem.MAVEN: "Maven",
}


class OSVClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.cache: Dict[str, List[VulnerabilityFinding]] = {}

    def fetch_vulnerabilities(self, package: PackageNode) -> List[VulnerabilityFinding]:
        cache_key = f"{package.ecosystem.value}:{package.name}:{package.version}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        osv_ecosystem = ECOSYSTEM_MAP.get(package.ecosystem)
        if not osv_ecosystem:
            return []

        payload = {
            "package": {
                "name": package.name,
                "ecosystem": osv_ecosystem,
            },
            "version": package.version,
        }

        findings: List[VulnerabilityFinding] = []

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(OSV_API_URL, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulns", [])
                    for vuln in vulns:
                        finding = self._parse_osv_vuln(vuln)
                        if finding:
                            findings.append(finding)
        except Exception:
            # Graceful offline fallback on connection/timeout error
            pass

        self.cache[cache_key] = findings
        return findings

    def _parse_osv_vuln(self, vuln_data: dict) -> Optional[VulnerabilityFinding]:
        vuln_id = vuln_data.get("id", "UNKNOWN-CVE")
        summary = vuln_data.get("summary") or vuln_data.get("details", "No description available")
        if len(summary) > 120:
            summary = summary[:117] + "..."

        severity = "MEDIUM"
        cvss_score = None

        # Extract CVSS score if available in database metrics
        severities = vuln_data.get("severity", [])
        for s in severities:
            if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                score_str = s.get("score")
                try:
                    # Basic heuristic parsing if string contains score
                    if "/" in score_str:
                        cvss_score = float(score_str.split("/")[1])
                    else:
                        cvss_score = float(score_str)
                except Exception:
                    pass

        if cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Determine fixed version if reported
        fixed_ver = None
        affected_list = vuln_data.get("affected", [])
        for aff in affected_list:
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for ev in events:
                    if "fixed" in ev:
                        fixed_ver = ev["fixed"]
                        break

        refs = [ref.get("url") for ref in vuln_data.get("references", []) if "url" in ref]

        return VulnerabilityFinding(
            id=vuln_id,
            summary=summary,
            severity=severity,
            cvss_score=cvss_score,
            fixed_version=fixed_ver,
            references=refs[:3],
        )
