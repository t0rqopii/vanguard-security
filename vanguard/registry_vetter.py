"""
Registry forensics and slopsquatting detection via package metadata analysis.
"""

import logging
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Optional

from vanguard.exceptions import GhostPackageWarning

logger = logging.getLogger(__name__)


@dataclass
class PackageMetadata:
    """Immutable package metadata snapshot."""

    name: str
    version: str
    description: str
    repository_url: Optional[str]
    download_count: int


class RegistryForensics:
    """
    Detects slopsquatting and AI hallucination traps via package metadata analysis.
    Flags packages exhibiting suspicious patterns indicative of spoofing or fake
    community adoption.
    """

    LEGITIMATE_PACKAGES = {
        "requests",
        "numpy",
        "pandas",
        "django",
        "flask",
        "sqlalchemy",
        "pytest",
        "black",
        "mypy",
        "pydantic",
        "fastapi",
        "asyncio",
        "aiohttp",
    }

    GENERIC_DESCRIPTIONS = {
        "a python package",
        "python utility",
        "helper library",
        "useful tool",
        "common functions",
        "utility functions",
        "basic utilities",
    }

    HALLUCINATION_INDICATORS = {
        "suspicious_version",
        "low_adoption",
        "generic_metadata",
        "name_spoofing",
        "missing_repository",
    }

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.cache_dir = cache_dir or Path.cwd()
        self.findings: list[dict] = []

    def evaluate_package(self, metadata: PackageMetadata) -> bool:
        """
        Assess package for AI hallucination indicators.
        Returns True if package exhibits suspicious patterns.
        """
        indicators = set()

        if self._is_suspicious_version(metadata.version):
            indicators.add("suspicious_version")

        if self._is_low_adoption(metadata.download_count):
            indicators.add("low_adoption")

        if self._is_generic_description(metadata.description):
            indicators.add("generic_metadata")

        if self._is_name_spoofing(metadata.name):
            indicators.add("name_spoofing")

        if self._has_missing_repository(metadata.repository_url):
            indicators.add("missing_repository")

        is_suspicious = len(indicators) >= 3
        if is_suspicious:
            finding = {
                "package": metadata.name,
                "version": metadata.version,
                "indicators": list(indicators),
                "description": metadata.description[:100],
            }
            self.findings.append(finding)
            logger.warning(
                f"Ghost package trap detected: {metadata.name} "
                f"(indicators: {', '.join(indicators)})"
            )
            raise GhostPackageWarning(
                f"AI hallucination trap: {metadata.name} "
                f"exhibits {len(indicators)} suspicious indicators"
            )

        return is_suspicious

    def _is_suspicious_version(self, version: str) -> bool:
        """Flag initial/hallucination-typical versions."""
        return version in {"0.0.1", "1.0.0", "0.1.0"}

    def _is_low_adoption(self, download_count: int) -> bool:
        """Flag packages with insufficient adoption signals."""
        return download_count < 2

    def _is_generic_description(self, description: str) -> bool:
        """Detect boilerplate/auto-generated descriptions."""
        normalized = description.lower().strip()
        return any(
            generic in normalized for generic in self.GENERIC_DESCRIPTIONS
        )

    def _is_name_spoofing(self, package_name: str) -> bool:
        """Detect names highly similar to legitimate packages."""
        for legit in self.LEGITIMATE_PACKAGES:
            similarity = SequenceMatcher(None, package_name.lower(), legit).ratio()
            if 0.75 <= similarity < 1.0:
                logger.debug(
                    f"Name similarity: {package_name} vs {legit} ({similarity:.2f})"
                )
                return True
        return False

    def _has_missing_repository(self, repository_url: Optional[str]) -> bool:
        """Flag packages with no repository link."""
        if not repository_url:
            return True
        if not repository_url.startswith(("http://", "https://")):
            return True
        return False

    def get_findings(self) -> list[dict]:
        """Return detected hallucination trap findings."""
        return self.findings
