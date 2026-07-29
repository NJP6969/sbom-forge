from pathlib import Path
from typing import List, Optional, Tuple
from sbom_forge.graph.models import PackageNode
from sbom_forge.parsers.base import BaseParser
from sbom_forge.parsers.npm import NpmParser
from sbom_forge.parsers.pip import PipParser
from sbom_forge.parsers.go import GoParser

ALL_PARSERS: List[BaseParser] = [
    NpmParser(),
    PipParser(),
    GoParser(),
]


def detect_and_parse(target_path: Path) -> Tuple[List[PackageNode], Optional[BaseParser]]:
    if target_path.is_file():
        for parser in ALL_PARSERS:
            if parser.can_parse(target_path):
                return parser.parse(target_path), parser
    elif target_path.is_dir():
        for manifest_name in ["package-lock.json", "requirements.txt", "go.sum"]:
            candidate = target_path / manifest_name
            if candidate.exists():
                for parser in ALL_PARSERS:
                    if parser.can_parse(candidate):
                        return parser.parse(candidate), parser

    return [], None
