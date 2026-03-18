import json
from pathlib import Path
from typing import Dict, List
from sbom_forge.graph.models import PackageNode, Ecosystem
from sbom_forge.parsers.base import BaseParser


class NpmParser(BaseParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "package-lock.json"

    def parse(self, file_path: Path) -> List[PackageNode]:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        lockfile_version = data.get("lockfileVersion", 1)
        packages: Dict[str, PackageNode] = {}

        if lockfile_version >= 2 and "packages" in data:
            self._parse_v2_v3(data["packages"], packages)
        elif "dependencies" in data:
            self._parse_v1(data["dependencies"], packages)

        return list(packages.values())

    def _parse_v2_v3(self, packages_dict: dict, out_map: Dict[str, PackageNode]) -> None:
        root_package = packages_dict.get("", {})
        root_deps = set(root_package.get("dependencies", {}).keys())
        root_dev_deps = set(root_package.get("devDependencies", {}).keys())

        for pkg_path, info in packages_dict.items():
            if pkg_path == "":
                continue  # Skip root package itself

            # Extract clean package name from node_modules path
            clean_name = pkg_path.replace("node_modules/", "").split("node_modules/")[-1]
            version = info.get("version", "0.0.0")
            integrity = info.get("integrity")
            resolved = info.get("resolved")
            is_dev = info.get("dev", False) or clean_name in root_dev_deps
            is_direct = clean_name in root_deps or clean_name in root_dev_deps

            # Collect dependency names
            dep_names = []
            deps = info.get("dependencies", {})
            for dep_name in deps.keys():
                # Store placeholder child reference
                dep_names.append(dep_name)

            identifier = f"{clean_name}@{version}"
            
            pkg_node = PackageNode(
                name=clean_name,
                version=version,
                ecosystem=Ecosystem.NPM,
                integrity_hash=integrity,
                resolved_url=resolved,
                is_direct=is_direct,
                is_dev=is_dev,
                dependencies=[],  # Will resolve exact child versions below
            )
            out_map[clean_name] = pkg_node

        # Resolve child dependency identifiers
        for clean_name, node in out_map.items():
            pkg_path = f"node_modules/{clean_name}"
            info = packages_dict.get(pkg_path, {})
            deps = info.get("dependencies", {})
            resolved_child_ids = []
            for child_name in deps.keys():
                if child_name in out_map:
                    resolved_child_ids.append(out_map[child_name].identifier)
            node.dependencies = resolved_child_ids

    def _parse_v1(self, deps_dict: dict, out_map: Dict[str, PackageNode]) -> None:
        for name, info in deps_dict.items():
            version = info.get("version", "0.0.0")
            integrity = info.get("integrity")
            resolved = info.get("resolved")
            is_dev = info.get("dev", False)

            node = PackageNode(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                integrity_hash=integrity,
                resolved_url=resolved,
                is_direct=True,
                is_dev=is_dev,
            )
            out_map[name] = node
