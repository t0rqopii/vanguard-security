"""
Tests for registry forensics and slopsquatting detection.
"""

import pytest
from pathlib import Path

from vanguard.registry_vetter import RegistryForensics, PackageMetadata
from vanguard.exceptions import GhostPackageWarning


def test_registry_forensics_legitimate_package() -> None:
    """Verify legitimate packages pass validation."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="requests",
        version="2.31.0",
        description="HTTP library for humans",
        repository_url="https://github.com/psf/requests",
        download_count=500_000_000,
    )

    is_suspicious = registry.evaluate_package(metadata)
    assert not is_suspicious
    assert len(registry.get_findings()) == 0


def test_registry_forensics_suspicious_version() -> None:
    """Flag packages with hallucination-typical versions."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="legit-package",
        version="0.0.1",
        description="A legitimate tool",
        repository_url="https://github.com/owner/repo",
        download_count=100,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)


def test_registry_forensics_low_adoption() -> None:
    """Flag packages with insufficient adoption signals."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="mystery-lib",
        version="1.2.3",
        description="Useful utility",
        repository_url="https://github.com/owner/repo",
        download_count=1,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)


def test_registry_forensics_generic_description() -> None:
    """Detect boilerplate descriptions."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="helper-lib",
        version="1.0.0",
        description="A Python package",
        repository_url="https://github.com/owner/repo",
        download_count=10,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)


def test_registry_forensics_name_spoofing() -> None:
    """Detect names similar to legitimate packages."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="requets",  # Typo of 'requests'
        version="1.0.0",
        description="HTTP library",
        repository_url="https://github.com/fake/requests",
        download_count=1,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)


def test_registry_forensics_missing_repository() -> None:
    """Flag packages with no repository link."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="orphan-package",
        version="1.0.0",
        description="A package with description",
        repository_url=None,
        download_count=1,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)


def test_registry_forensics_hallucination_trap() -> None:
    """Flag packages matching multiple hallucination indicators."""
    registry = RegistryForensics()

    metadata = PackageMetadata(
        name="numpi",  # Similar to numpy
        version="0.0.1",
        description="A python package",
        repository_url=None,
        download_count=1,
    )

    with pytest.raises(GhostPackageWarning):
        registry.evaluate_package(metadata)

    assert len(registry.get_findings()) > 0
