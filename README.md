# sbom-forge 🛡️🤖

> **AI-Powered Supply Chain Attack Surface Analyzer & Hardener**
> Move beyond static CVE lists. Analyze dependency graph blast radius, simulate hypothetical supply chain attack paths using local LLMs, and auto-generate hardened lockfiles with integrity hash-pinning.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: OSV.dev](https://img.shields.io/badge/Security-OSV.dev-green.svg)](https://osv.dev)
[![AI: Ollama](https://img.shields.io/badge/AI-Ollama%20Local-purple.svg)](https://ollama.ai)

---

## ⚡ Key Features

- **Multi-Ecosystem Lockfile Parsing**: Native support for `package-lock.json` (npm), `requirements.txt` / `Pipfile.lock` (PyPI), `go.sum` (Go), and `pom.xml` (Maven).
- **DAG Betweenness Centrality**: Quantifies dependency blast radius. Identifies bottleneck packages whose compromise impacts the maximum number of downstream modules.
- **Local LLM Attack Path Reasoning**: Connects to local Ollama (`llama3.1`) to simulate hypothetical supply chain attacks, reasoning about blast radius, data exfiltration risks, and MITRE ATT&CK techniques.
- **CVE & Registry Enrichment**: Queries Google OSV.dev for active vulnerabilities and detects typosquatting, single-maintainer risks, and stale packages.
- **Automated Hardening**: Generates hardened `.npmrc` files, `constraints.txt` hash-pinnings, and suggests safe package alternatives.
- **CI/CD & SARIF Integration**: Emits SARIF reports compatible with GitHub Security Code Scanning and breaks PR builds when risk thresholds are exceeded.

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-username/sbom-forge.git
cd sbom-forge

# Install in editable mode
pip install -e .
```

### Basic Usage

```bash
# Scan a directory containing package-lock.json or requirements.txt
sbom-forge scan ./my-project

# Run AI attack path simulation (requires Ollama running locally)
sbom-forge attack-sim ./my-project --model llama3.1

# Generate CycloneDX / SPDX SBOM
sbom-forge sbom ./my-project --format cyclonedx --output sbom.json

# Auto-generate hardened lockfile & security policy
sbom-forge harden ./my-project

# CI Mode (returns non-zero exit code if risk threshold > 7.5)
sbom-forge ci ./my-project --threshold 7.5
```

---

## 🛡️ Architecture & Threat Model

```
                    ┌─────────────────────────┐
                    │  Dependency Manifests   │
                    │ (package-lock, go.sum)  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Graph Builder (DAG)   │
                    │   NetworkX Analysis     │
                    └────────────┬────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
    ┌─────────────────────────┐     ┌─────────────────────────┐
    │   Enrichment Engine     │     │   Local LLM Simulator   │
    │  (OSV.dev + Registries) │     │ (Ollama + Prompt Guard) │
    └────────────┬────────────┘     └────────────┬────────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     Output Exporters    │
                    │ (Rich UI, SARIF, SBOM)  │
                    └─────────────────────────┘
```

---

## 📄 License

MIT © sbom-forge contributors
