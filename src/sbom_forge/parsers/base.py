from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Tuple
from sbom_forge.graph.models import PackageNode, Ecosystem


class BaseParser(ABC):
    @abstractmethod
    def parse(self, file_path: Path) -> List[PackageNode]:
        """Parse a manifest file and return a list of PackageNode objects."""
        pass

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Return True if this parser can handle the target file."""
        pass
