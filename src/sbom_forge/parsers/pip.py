import re
from pathlib import Path
from typing import List
from sbom_forge.graph.models import PackageNode, Ecosystem
from sbom_forge.parsers.base import BaseParser


class PipParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name in ("requirements.txt", "Pipfile.lock", "poetry.lock") or file_path.name.endswith(".txt")

    def parse(self, file_path: Path) -> List[PackageNode]:
        if file_path.name == "requirements.txt" or file_path.name.endswith(".txt"):
            return self._parse_requirements_txt(file_path)
        return []

    def _parse_requirements_txt(self, file_path: Path) -> List[PackageNode]:
        packages: List[PackageNode] = []
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        current_hash = None
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-e"):
                continue

            extracted_hash = current_hash
            if "--hash=" in line:
                parts = line.split("--hash=")
                line_without_hash = parts[0].strip()
                extracted_hash = parts[1].split()[0].strip()
            else:
                line_without_hash = line

            clean_line = line_without_hash.split("#")[0].split(";")[0].strip()
            if not clean_line:
                continue

            # Match package==version or package>=version
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=><~]=?([a-zA-Z0-9_\-\.]+))?", clean_line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(2) or "latest"
                
                pkg_node = PackageNode(
                    name=pkg_name,
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    integrity_hash=extracted_hash,
                    is_direct=True,
                    is_dev=False,
                )
                packages.append(pkg_node)
                current_hash = None

        return packages
