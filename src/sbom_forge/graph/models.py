from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    MAVEN = "maven"
    UNKNOWN = "unknown"


class VulnerabilityFinding(BaseModel):
    id: str  # CVE-2021-23337 or GHSA-xxx
    summary: str
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class PackageNode(BaseModel):
    name: str
    version: str
    ecosystem: Ecosystem = Ecosystem.NPM
    integrity_hash: Optional[str] = None
    resolved_url: Optional[str] = None
    is_direct: bool = False
    is_dev: bool = False
    dependencies: List[str] = Field(default_factory=list)  # Child package identifiers ("name@version")

    # Calculated metrics
    betweenness_centrality: float = 0.0
    transitive_reach: int = 0
    depth: int = 0
    risk_score: float = 0.0
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)

    @property
    def identifier(self) -> str:
        return f"{self.name}@{self.version}"


class DependencyEdge(BaseModel):
    source: str  # Parent identifier
    target: str  # Child identifier
    relationship_type: str = "requires"  # requires, devDepends, optional


class AttackPath(BaseModel):
    target_package: str
    compromise_scenario: str
    blast_radius_percentage: float
    affected_packages: List[str]
    mitre_attack_techniques: List[str]
    data_exposure_risk: str
    recommended_mitigation: str


class ScanResult(BaseModel):
    project_name: str
    root_ecosystem: Ecosystem
    total_dependencies: int
    direct_dependencies_count: int
    transitive_dependencies_count: int
    overall_risk_score: float
    high_risk_packages: List[PackageNode] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    nodes: Dict[str, PackageNode] = Field(default_factory=dict)
