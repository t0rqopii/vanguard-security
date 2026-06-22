# Vanguard Quick Reference

## Installation & Setup

```bash
# Install for development
cd vanguard
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Type check
mypy vanguard/

# Format & lint
black vanguard/ && ruff check --fix vanguard/
```

## Basic Usage

### CLI: Scan a Project
```bash
vanguard scan /path/to/project
vanguard scan . --json > report.json
vanguard scan . --strict --verbose
```

### Programmatic: Detect Homographs
```python
from vanguard.ast_scanner import ImportHomographDetector
from pathlib import Path

detector = ImportHomographDetector(Path("."))
detector.scan()

for file, module, msg in detector.get_findings():
    print(f"{file}: {msg}")
```

### Programmatic: Analyze Pipelines
```python
from vanguard.pipeline_analyzer import WorkflowTaintAnalyzer

analyzer = WorkflowTaintAnalyzer(Path("."))
analyzer.scan()

for finding in analyzer.get_findings():
    print(f"Risk: {finding['message']}")
```

### Programmatic: Evaluate Packages
```python
from vanguard.registry_vetter import RegistryForensics, PackageMetadata
from vanguard.exceptions import GhostPackageWarning

registry = RegistryForensics()
pkg = PackageMetadata(
    name="suspicious-lib",
    version="0.0.1",
    description="A python package",
    repository_url=None,
    download_count=1,
)

try:
    registry.evaluate_package(pkg)
except GhostPackageWarning as e:
    print(f"Dangerous package: {e}")
```

## Key Classes

| Class | Purpose |
|-------|---------|
| `ImportHomographDetector` | Detects Unicode spoofing in imports |
| `WorkflowTaintAnalyzer` | Detects risky CI/CD patterns |
| `RegistryForensics` | Detects AI hallucination traps |

## Exception Handling

```python
from vanguard.exceptions import (
    HomographAttackDetected,
    SuspiciousPipelineHook,
    GhostPackageWarning,
)

try:
    detector.scan()
except HomographAttackDetected as e:
    # Handle homograph detection
    pass
```

## CLI Exit Codes

- `0`: Pass (no findings)
- `1`: Findings detected
- `2`: Error during execution

## Configuration

All scanners use sensible defaults. Customize by modifying class attributes:

```python
# Custom character sets for homograph detection
detector.SUSPICIOUS_CHAR_SETS["emoji"] = range(0x1F300, 0x1F9FF)

# Custom legitimate packages list
registry.LEGITIMATE_PACKAGES.add("my-package")
```

## Logging

Enable verbose logging:

```bash
vanguard scan . --verbose  # CLI

# Or in code
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Performance Tips

- Exclude large directories: Modify exclusion patterns in scanner classes
- Parallel processing: For future versions supporting multiprocessing
- Incremental scanning: Run against only changed files in CI/CD

## Troubleshooting

**Import Error**: Ensure package installed with `pip install -e .`

**Type Errors**: Run `mypy vanguard/` to verify type hints

**Test Failures**: Check Python version (requires 3.11+)

**YAML Parse Errors**: Malformed workflow files are logged and skipped

## Integration Examples

### GitHub Actions
```yaml
- name: Run Vanguard
  run: vanguard scan . --strict --json > report.json

- name: Parse Report
  run: python scripts/parse_vanguard.py report.json
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: vanguard-scan
        name: Vanguard Supply Chain Check
        entry: vanguard scan
        language: system
        stages: [commit]
```

### CI/CD Pipeline
```bash
#!/bin/bash
vanguard scan . --strict || exit 1
```

## Support

- **Documentation**: See README.md, ARCHITECTURE.md, DEVELOP.md
- **Issues**: GitHub Issues
- **Contributing**: Pull requests welcome

---

**Vanguard: Production-grade supply chain security**
