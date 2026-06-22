"""
Tests for homograph attack detection.
"""

import pytest
from pathlib import Path

from vanguard.ast_scanner import ImportHomographDetector
from vanguard.exceptions import HomographAttackDetected


def test_homograph_detector_clean_file(tmp_project: Path) -> None:
    """Verify clean Python files pass without findings."""
    py_file = tmp_project / "clean.py"
    py_file.write_text("import os\nimport sys\nfrom pathlib import Path")

    detector = ImportHomographDetector(tmp_project)
    detector.scan()

    assert len(detector.get_findings()) == 0


def test_homograph_detector_mixed_characters(tmp_project: Path) -> None:
    """Detect imports with mixed character sets."""
    py_file = tmp_project / "suspicious.py"
    py_file.write_text("import rеquests")  # 'е' is Cyrillic, looks like 'e'

    detector = ImportHomographDetector(tmp_project)

    with pytest.raises(HomographAttackDetected):
        detector.scan()

    assert len(detector.get_findings()) > 0


def test_homograph_detector_excludes_venv(tmp_project: Path) -> None:
    """Verify venv directories are excluded."""
    venv_dir = tmp_project / "venv"
    venv_dir.mkdir()
    suspicious_file = venv_dir / "package.py"
    suspicious_file.write_text("import rеquests")

    detector = ImportHomographDetector(tmp_project)
    detector.scan()

    assert len(detector.get_findings()) == 0


def test_homograph_detector_syntax_error_handling(tmp_project: Path) -> None:
    """Verify graceful handling of syntax errors."""
    bad_file = tmp_project / "broken.py"
    bad_file.write_text("def broken(:\n  pass")

    detector = ImportHomographDetector(tmp_project)
    detector.scan()

    assert len(detector.get_findings()) == 0
