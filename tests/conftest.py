"""
Pytest configuration and fixtures.
"""

import pytest
from pathlib import Path
from typing import Generator


@pytest.fixture
def tmp_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Provide a temporary project directory."""
    yield tmp_path


@pytest.fixture
def sample_workflow(tmp_path: Path) -> Path:
    """Create a sample GitHub Actions workflow file."""
    workflows_dir = tmp_path / ".github" / "workflows"
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
      - uses: actions/checkout@v4
      - uses: actions/setup-python@main
        with:
          python-version: '3.11'
"""
    )
    return workflow_file
