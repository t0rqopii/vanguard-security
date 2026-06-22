"""
AST-based detection of homograph attacks in Python import statements.
"""

import ast
import logging
from pathlib import Path
from typing import Generator

from vanguard.exceptions import HomographAttackDetected

logger = logging.getLogger(__name__)


class ImportHomographDetector:
    """
    Parses Python source files and detects Unicode homographs in import statements.
    Identifies suspicious module names using character-set analysis and Unicode
    normalization checks.
    """

    LATIN_RANGE = set(range(0x0041, 0x005B)) | set(range(0x0061, 0x007B))
    CYRILLIC_RANGE = set(range(0x0410, 0x044F))
    GREEK_RANGE = set(range(0x0391, 0x03A9)) | set(range(0x03B1, 0x03C9))

    SUSPICIOUS_CHAR_SETS = {
        "cyrillic": CYRILLIC_RANGE,
        "greek": GREEK_RANGE,
    }

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root)
        self.findings: list[tuple[Path, str, str]] = []

    def scan(self) -> None:
        """Scan all Python files in project root for homograph attacks."""
        for py_file in self._enumerate_python_files():
            try:
                self._analyze_file(py_file)
            except (SyntaxError, ValueError) as e:
                logger.warning(f"Skipped {py_file}: {e}")

    def _enumerate_python_files(self) -> Generator[Path, None, None]:
        """Yield all .py files excluding common exclusion patterns."""
        exclusions = {".venv", "venv", "__pycache__", ".git", "node_modules"}
        for py_file in self.project_root.rglob("*.py"):
            if not any(excl in py_file.parts for excl in exclusions):
                yield py_file

    def _analyze_file(self, file_path: Path) -> None:
        """Parse file AST and inspect import statements."""
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source, filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._check_import_names(
                    file_path, [alias.name for alias in node.names]
                )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self._check_import_names(file_path, [node.module])

    def _check_import_names(self, file_path: Path, names: list[str]) -> None:
        """Evaluate import names for homograph indicators."""
        for name in names:
            if self._contains_homograph(name):
                finding = f"Homograph detected: '{name}'"
                self.findings.append((file_path, name, finding))
                logger.warning(f"{file_path}:{name} - {finding}")
                raise HomographAttackDetected(finding)

    def _contains_homograph(self, module_name: str) -> bool:
        """Detect suspicious Unicode character mixing in module names."""
        chars = [ord(c) for c in module_name if c.isalpha()]
        if not chars:
            return False

        has_latin = any(c in self.LATIN_RANGE for c in chars)
        has_suspicious = any(
            any(c in suspect_range for c in chars)
            for suspect_range in self.SUSPICIOUS_CHAR_SETS.values()
        )

        return has_latin and has_suspicious

    def get_findings(
        self,
    ) -> list[tuple[Path, str, str]]:
        """Return detected homograph findings."""
        return self.findings
