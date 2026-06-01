import json
from typing import Dict
from sbom_forge.graph.models import ScanResult, Ecosystem


def generate_cyclonedx_sbom(result: ScanResult) -> str:
    components = []
    for pkg in result.nodes.values():
        comp = {
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": f"pkg:{pkg.ecosystem.value}/{pkg.name}@{pkg.version}",
        }
        if pkg.integrity_hash:
            comp["hashes"] = [{"alg": "SHA-512", "content": pkg.integrity_hash}]
        components.append(comp)

    cyclonedx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": result.project_name,
                "version": "1.0.0",
            },
            "tools": [{"name": "sbom-forge", "version": "0.1.0"}],
        },
        "components": components,
    }

    return json.dumps(cyclonedx_doc, indent=2)


def generate_spdx_sbom(result: ScanResult) -> str:
    packages = []
    for pkg in result.nodes.values():
        spdx_pkg = {
            "name": pkg.name,
            "SPDXID": f"SPDXRef-Package-{pkg.name}-{pkg.version}",
            "versionInfo": pkg.version,
            "downloadLocation": pkg.resolved_url or "NOASSERTION",
            "filesAnalyzed": False,
        }
        packages.append(spdx_pkg)

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{result.project_name}",
        "documentNamespace": f"http://spdx.org/spdxdocs/sbom-forge-{result.project_name}-1.0.0",
        "creationInfo": {
            "creators": ["Tool: sbom-forge-0.1.0"],
        },
        "packages": packages,
    }

    return json.dumps(spdx_doc, indent=2)
