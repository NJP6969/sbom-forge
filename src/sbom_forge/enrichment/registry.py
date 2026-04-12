from typing import List, Set
from sbom_forge.graph.models import PackageNode

# Known high-target popular packages for typosquatting checks
POPULAR_PACKAGES: Set[str] = {
    "express", "lodash", "react", "vue", "axios", "webpack", "typescript",
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "pytest",
    "gin", "gorm", "cobra", "logrus", "zap"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(package_name: str) -> bool:
    pkg = package_name.lower()
    if pkg in POPULAR_PACKAGES:
        return False  # Legitimate popular package

    for popular in POPULAR_PACKAGES:
        distance = levenshtein_distance(pkg, popular)
        if 1 <= distance <= 2:
            return True  # 1 or 2 character edit distance = suspicious typosquat candidate

    return False
