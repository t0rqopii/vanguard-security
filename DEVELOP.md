# Development Guide for Vanguard

## Setup

```bash
# Clone repository
git clone <url>
cd vanguard

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=vanguard --cov-report=html

# Run specific test file
pytest tests/test_ast_scanner.py -v

# Run specific test
pytest tests/test_ast_scanner.py::test_homograph_detector_clean_file -v
```

## Code Quality

```bash
# Type checking
mypy vanguard/

# Code formatting
black vanguard/ tests/

# Linting
ruff check vanguard/ tests/
ruff check --fix vanguard/ tests/  # Auto-fix

# All together
black vanguard/ tests/ && ruff check --fix vanguard/ tests/ && mypy vanguard/
```

## Quick Test

```bash
# Test the CLI on the vanguard project itself
python -m vanguard.cli scan .

# Or use the installed command
vanguard scan .

# With JSON output
vanguard scan . --json

# Verbose mode
vanguard scan . --verbose
```

## Code Style

- **Type hints**: All functions must have parameter and return type hints
- **Docstrings**: Module and class docstrings only; brief, not verbose
- **Comments**: Only when the WHY is non-obvious; no obvious statements
- **Naming**: Self-documenting names preferred over comments
- **Error handling**: Custom exceptions for security findings; defensive checks at boundaries

## Project Structure

```
vanguard/
├── __init__.py           # Public API
├── exceptions.py         # Custom exceptions
├── ast_scanner.py        # ImportHomographDetector
├── pipeline_analyzer.py  # WorkflowTaintAnalyzer
├── registry_vetter.py    # RegistryForensics
└── cli.py                # CLI entry point

tests/
├── conftest.py           # Pytest fixtures
├── test_ast_scanner.py
├── test_pipeline_analyzer.py
└── test_registry_vetter.py

examples/
└── audit.py              # Example usage
```

## Adding Features

1. Write test first (TDD)
2. Implement with type hints
3. Update docstrings/examples
4. Run full test suite and checks
5. Update README if API changed

## Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Or via CLI:
```bash
vanguard scan . --verbose
```

## Performance

- AST scanning: O(n) files
- Pipeline analysis: O(m) workflows
- Registry forensics: O(1) per-package

For large projects (>10k files), consider incremental scanning.
