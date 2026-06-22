#!/usr/bin/env python3
"""
Example usage of Vanguard components for supply chain security auditing.
"""

import sys
from pathlib import Path

from vanguard.ast_scanner import ImportHomographDetector
from vanguard.pipeline_analyzer import WorkflowTaintAnalyzer
from vanguard.registry_vetter import RegistryForensics, PackageMetadata


def audit_project(project_root: Path) -> None:
    """
    Comprehensive security audit of a project.
    Demonstrates usage of all Vanguard components.
    """
    print(f"Auditing project: {project_root}\n")

    print("[1/3] Scanning for homograph imports...")
    try:
        detector = ImportHomographDetector(project_root)
        detector.scan()
        findings = detector.get_findings()
        if findings:
            print(f"  ⚠ Found {len(findings)} suspicious imports")
            for file, module, msg in findings:
                print(f"    • {file}: {msg}")
        else:
            print("  ✓ No homograph attacks detected")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    print("\n[2/3] Analyzing pipeline security...")
    try:
        analyzer = WorkflowTaintAnalyzer(project_root)
        analyzer.scan()
        findings = analyzer.get_findings()
        if findings:
            print(f"  ⚠ Found {len(findings)} taint signatures")
            for finding in findings[:3]:
                print(f"    • {finding['message']}")
        else:
            print("  ✓ No pipeline tampering patterns detected")
    except Exception as e:
        print(f"  ✗ Error: {e}")

    print("\n[3/3] Evaluating package safety...")
    test_packages = [
        PackageMetadata(
            name="numpy",
            version="1.24.0",
            description="NumPy: array processing for numbers, strings, records and objects.",
            repository_url="https://github.com/numpy/numpy",
            download_count=500_000_000,
        ),
        PackageMetadata(
            name="numpi",
            version="0.0.1",
            description="A python package",
            repository_url=None,
            download_count=0,
        ),
    ]

    registry = RegistryForensics(project_root)
    for pkg in test_packages:
        try:
            registry.evaluate_package(pkg)
            print(f"  ✓ {pkg.name} appears safe")
        except Exception as e:
            print(f"  ⚠ {pkg.name}: {e}")

    findings = registry.get_findings()
    if findings:
        print(f"\n  Detected {len(findings)} suspicious packages")

    print("\n" + "=" * 70)
    print("Audit complete")


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    audit_project(target)
