from pathlib import Path
from typer.testing import CliRunner
from sbom_forge.cli import app

runner = CliRunner()


def test_cli_scan(sample_package_lock_json: Path):
    result = runner.invoke(app, ["scan", str(sample_package_lock_json), "--no-ai"])
    assert result.exit_code == 0
    assert "Supply Chain Security Analysis" in result.output
    assert "express" in result.output


def test_cli_sbom(sample_package_lock_json: Path):
    result = runner.invoke(app, ["sbom", str(sample_package_lock_json), "--format", "cyclonedx"])
    assert result.exit_code == 0
    assert "CycloneDX" in result.output


def test_cli_harden(sample_package_lock_json: Path):
    result = runner.invoke(app, ["harden", str(sample_package_lock_json.parent)])
    assert result.exit_code == 0
    assert ".npmrc" in result.output
