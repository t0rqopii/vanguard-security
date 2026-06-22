"""
CI/CD pipeline taint analysis for GitHub Actions and Makefiles.
"""

import logging
import re
from pathlib import Path
from typing import Generator

import yaml

from vanguard.exceptions import SuspiciousPipelineHook

logger = logging.getLogger(__name__)


class WorkflowTaintAnalyzer:
    """
    Inspects GitHub Actions workflows and shell scripts for supply chain risks.
    Detects unpinned actions, remote code execution patterns, and environment
    variable taint flows.
    """

    UNPINNED_ACTION_PATTERN = re.compile(r"uses:\s*[\w\-./]+@(?:main|master|v\d+(?:\.\d+)*)(?:\s|$)")
    RCE_PIPE_PATTERN = re.compile(r"(?:curl|wget)\s+.*\|\s*(?:sh|bash)")
    ENV_EXFIL_PATTERN = re.compile(
        r"(?:env|printenv)\s*(?:\||>)\s*.*(?:http|curl|wget|nc|telnet)"
    )
    SHELL_CMD_PATTERN = re.compile(r"run:\s*(.+?)(?=\n|$)", re.MULTILINE)

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root)
        self.findings: list[dict] = []

    def scan(self) -> None:
        """Scan workflow files and shell scripts for taint signatures."""
        self._scan_workflows()
        self._scan_makefiles()

    def _scan_workflows(self) -> None:
        """Inspect .github/workflows YAML files."""
        workflows_dir = self.project_root / ".github" / "workflows"
        if not workflows_dir.exists():
            logger.debug(f"No workflows directory at {workflows_dir}")
            return

        for yaml_file in workflows_dir.glob("*.yml"):
            try:
                self._analyze_workflow(yaml_file)
            except yaml.YAMLError as e:
                logger.warning(f"Failed to parse {yaml_file}: {e}")
            except Exception as e:
                logger.error(f"Error scanning {yaml_file}: {e}")

    def _analyze_workflow(self, file_path: Path) -> None:
        """Parse workflow YAML and detect taint patterns."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            return

        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue
            self._inspect_job_steps(file_path, job_name, job_config)

    def _inspect_job_steps(self, file_path: Path, job_name: str, job_config: dict) -> None:
        """Analyze steps within a job for suspicious patterns."""
        steps = job_config.get("steps", [])
        if not isinstance(steps, list):
            return

        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses_action = step.get("uses", "")
            if isinstance(uses_action, str) and self.UNPINNED_ACTION_PATTERN.search(
                uses_action
            ):
                finding = f"Unpinned action detected: {uses_action}"
                self._record_finding(file_path, job_name, step_idx, finding)
                raise SuspiciousPipelineHook(finding)

            run_cmd = step.get("run", "")
            if isinstance(run_cmd, str):
                self._inspect_shell_commands(
                    file_path, job_name, step_idx, run_cmd
                )

    def _inspect_shell_commands(
        self, file_path: Path, job_name: str, step_idx: int, cmd: str
    ) -> None:
        """Detect RCE and data exfiltration patterns in shell commands."""
        if self.RCE_PIPE_PATTERN.search(cmd):
            finding = f"Remote execution pipe detected: {cmd[:80]}"
            self._record_finding(file_path, job_name, step_idx, finding)
            raise SuspiciousPipelineHook(finding)

        if self.ENV_EXFIL_PATTERN.search(cmd):
            finding = f"Potential environment exfiltration: {cmd[:80]}"
            self._record_finding(file_path, job_name, step_idx, finding)
            raise SuspiciousPipelineHook(finding)

    def _scan_makefiles(self) -> None:
        """Inspect Makefile for taint signatures."""
        makefile_candidates = ["Makefile", "makefile", "GNUmakefile"]
        for candidate in makefile_candidates:
            makefile_path = self.project_root / candidate
            if makefile_path.exists():
                try:
                    self._analyze_makefile(makefile_path)
                except Exception as e:
                    logger.error(f"Error scanning {makefile_path}: {e}")

    def _analyze_makefile(self, file_path: Path) -> None:
        """Parse Makefile for suspicious shell patterns."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        for match in self.SHELL_CMD_PATTERN.finditer(content):
            cmd = match.group(1).strip()
            if self.RCE_PIPE_PATTERN.search(cmd):
                finding = f"Remote execution pipe in Makefile: {cmd[:80]}"
                self._record_finding(file_path, "makefile", 0, finding)
                raise SuspiciousPipelineHook(finding)

    def _record_finding(
        self, file_path: Path, context: str, index: int, finding: str
    ) -> None:
        """Record a taint finding."""
        self.findings.append(
            {
                "file": str(file_path),
                "context": context,
                "index": index,
                "message": finding,
            }
        )
        logger.warning(f"{file_path}:{context}[{index}] - {finding}")

    def get_findings(self) -> list[dict]:
        """Return detected taint findings."""
        return self.findings
