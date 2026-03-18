from pathlib import Path
from typing import Dict, List
from sbom_forge.graph.models import PackageNode, Ecosystem
from sbom_forge.parsers.base import BaseParser


class GoParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "go.sum"

    def parse(self, file_path: Path) -> List[PackageNode]:
        packages: Dict[str, PackageNode] = {}
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 3:
                continue

            mod_path = parts[0]
            raw_version = parts[1].replace("/go.mod", "")
            hash_val = parts[2]

            # Clean version string (e.g. v1.2.3 -> 1.2.3)
            version = raw_version.lstrip("v")
            identifier = f"{mod_path}@{version}"

            if identifier not in packages:
                pkg_node = PackageNode(
                    name=mod_path,
                    version=version,
                    ecosystem=Ecosystem.GO,
                    integrity_hash=hash_val,
                    is_direct=True,
                )
                packages[identifier] = pkg_node

        return list(packages.values())
