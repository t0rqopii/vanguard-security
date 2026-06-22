# Vanguard: Advanced Supply Chain Security Toolkit

**Production-grade supply chain security analyzer** for detecting homograph attacks, pipeline tampering, and malicious package patterns.

## Features

### 🎯 Homograph Attack Detection
- **AST-based import scanning**: Parses all Python source files and analyzes import statements
- **Unicode character-set analysis**: Detects mixing of Latin, Cyrillic, and Greek characters indicative of homoglyph attacks
- **Typosquatting prevention**: Identifies suspicious module names that attempt character spoofing

### 🔍 Pipeline Taint Analysis
- **GitHub Actions inspection**: Scans `.github/workflows/*.yml` for risky patterns
- **Unpinned action detection**: Flags actions using `@main`, `@master`, or semantic versions instead of pinned SHA hashes
- **Remote code execution patterns**: Detects `curl | sh`, `wget | bash` and similar execution pipes
- **Environment exfiltration**: Identifies `env`/`printenv` usage combined with outbound network requests
- **Makefile scanning**: Analyzes Makefile rules for shell injection and taint signatures

### 📦 Registry Forensics & Slopsquatting Detection
- **AI hallucination trap detection**: Flags packages exhibiting multiple suspicious indicators
- **Metadata analysis**: Evaluates version history, description boilerplate, and repository links
- **Name similarity scoring**: Detects packages with names highly similar to legitimate libraries (typosquatting)
- **Adoption signal validation**: Flags packages with insufficient downstream usage

## Installation

### From Source
```bash
git clone <repository-url>
cd vanguard
pip install -e ".[dev]"
```

### As a Package
```bash
pip install vanguard-security
```

## Quick Start

```bash
# Basic scan
vanguard scan /path/to/project

# JSON output for integration
vanguard scan . --json

# Strict mode: exit non-zero on findings
vanguard scan . --strict

# Verbose logging
vanguard scan . --verbose
```

## Architecture

```
vanguard/
├── __init__.py                 # Package initialization
├── exceptions.py               # Custom security exceptions
├── ast_scanner.py              # ImportHomographDetector class
├── pipeline_analyzer.py        # WorkflowTaintAnalyzer class
├── registry_vetter.py          # RegistryForensics class
└── cli.py                      # CLI coordinator & entry point
```

### Component Details

#### `ImportHomographDetector`
Scans Python source files for homograph-based imports:
- Parses `.py` files via `ast` module
- Tracks character ranges (Latin, Cyrillic, Greek)
- Flags imports mixing multiple character sets
- Autoexcludes common directories (venv, .git, etc.)

#### `WorkflowTaintAnalyzer`
Inspects CI/CD pipelines for supply chain risks:
- Parses YAML workflow files with error recovery
- Regex-based pattern detection for known RCE signatures
- Step-level analysis within jobs
- Makefile support for legacy builds

#### `RegistryForensics`
Detects slopsquatting and AI-generated fake packages:
- Analyzes package metadata (version, description, links)
- Applies multiple indicator checks (≥3 triggers alert)
- Implements string similarity matching against known packages
- Flags packages with generic boilerplate descriptions

#### CLI Coordinator
Aggregates findings across all scanners:
- Subcommand-based interface (currently: `scan`)
- Structured error handling with graceful degradation
- JSON and human-readable output formats
- Exit codes reflect severity (0=pass, 1=findings, 2=error)

## Configuration

Vanguard uses sensible defaults. Scanner behavior can be customized by modifying class constants:

```python
# Registry forensics example
registry = RegistryForensics(cache_dir=Path("/custom/cache"))

# Homograph detector with custom root
detector = ImportHomographDetector(Path("/target/project"))
```

## Usage Examples

### Detect Homograph Imports
```python
from vanguard.ast_scanner import ImportHomographDetector
from pathlib import Path

detector = ImportHomographDetector(Path("."))
detector.scan()
findings = detector.get_findings()
```

### Analyze CI/CD Pipelines
```python
from vanguard.pipeline_analyzer import WorkflowTaintAnalyzer
from pathlib import Path

analyzer = WorkflowTaintAnalyzer(Path("."))
analyzer.scan()
for finding in analyzer.get_findings():
    print(f"Risk in {finding['file']}: {finding['message']}")
```

### Evaluate Package Safety
```python
from vanguard.registry_vetter import RegistryForensics, PackageMetadata

registry = RegistryForensics()
metadata = PackageMetadata(
    name="requests",
    version="2.31.0",
    description="HTTP library for humans",
    repository_url="https://github.com/psf/requests",
    download_count=500_000_000,
)

try:
    registry.evaluate_package(metadata)
    print("Package appears safe")
except GhostPackageWarning:
    print("Package flagged as suspicious")
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed; no security findings |
| 1    | Scan completed; findings detected (warnings/alerts) |
| 2    | Scan failed; error or critical exception |

## Security Considerations

Vanguard is a **defensive analysis tool** intended for:
- ✅ Security auditing of internal projects
- ✅ Supply chain risk assessment
- ✅ CI/CD pipeline hardening
- ✅ Package selection vetting
- ✅ CTF security challenges

It is **not** intended for:
- ❌ Bypassing security controls
- ❌ Automated exploitation
- ❌ Targeting third-party systems without authorization

## Logging

Vanguard uses Python's native `logging` module. Configure via environment or code:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

CLI verbose mode automatically sets DEBUG level:
```bash
vanguard scan . --verbose
```

## Development

### Type Checking
```bash
mypy vanguard/
```

### Code Quality
```bash
black vanguard/
ruff check vanguard/
```

### Testing
```bash
pytest tests/ -v --cov=vanguard
```

## Contributing

Contributions welcome. Please:
1. Maintain Python 3.11+ compatibility
2. Add type hints to all functions
3. Include tests for new features
4. Follow Black/Ruff formatting

## License

MIT License - See LICENSE file for details

## Support & Feedback

For issues or suggestions, open a GitHub issue or contact the AppSec team.

---

**Built with production-grade Python standards**: strict type hints, structured error handling, defensive coding, and self-documenting APIs.
