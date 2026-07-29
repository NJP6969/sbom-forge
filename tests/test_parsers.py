from pathlib import Path
from sbom_forge.parsers.npm import NpmParser
from sbom_forge.parsers.pip import PipParser
from sbom_forge.parsers import detect_and_parse


def test_npm_parser(sample_package_lock_json: Path):
    parser = NpmParser()
    assert parser.can_parse(sample_package_lock_json) is True

    packages = parser.parse(sample_package_lock_json)
    assert len(packages) == 4

    names = {pkg.name for pkg in packages}
    assert "express" in names
    assert "body-parser" in names
    assert "qs" in names
    assert "jest" in names

    express_pkg = next(p for p in packages if p.name == "express")
    assert express_pkg.is_direct is True
    assert express_pkg.is_dev is False
    assert len(express_pkg.dependencies) == 2


def test_pip_parser(sample_requirements_txt: Path):
    parser = PipParser()
    assert parser.can_parse(sample_requirements_txt) is True

    packages = parser.parse(sample_requirements_txt)
    assert len(packages) == 3

    names = {pkg.name for pkg in packages}
    assert "flask" in names
    assert "requests" in names
    assert "pytest" in names


def test_detect_and_parse(sample_package_lock_json: Path):
    packages, parser = detect_and_parse(sample_package_lock_json)
    assert parser is not None
    assert len(packages) == 4
