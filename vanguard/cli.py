"""
Command-line interface and main execution coordinator for Vanguard.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from vanguard.ast_scanner import ImportHomographDetector
from vanguard.exceptions import (
    HomographAttackDetected,
    SuspiciousPipelineHook,
    GhostPackageWarning,
    VanguardSecurityError,
)
from vanguard.pipeline_analyzer import WorkflowTaintAnalyzer
from vanguard.registry_vetter import PackageMetadata, RegistryForensics


def setup_logging(level: int) -> None:
    """Configure logging to stderr with structured output."""
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


def execute_scan(project_root: Path, strict: bool = False) -> dict:
    """
    Execute all security scanners across project.
    Returns aggregated findings dict.
    """
    results = {
        "timestamp": "",
        "project_root": str(project_root),
        "scanners": {
            "homograph_detection": None,
            "pipeline_taint": None,
            "registry_forensics": None,
        },
        "summary": {"total_findings": 0, "severity": "PASS"},
        "errors": [],
    }

    try:
        detector = ImportHomographDetector(project_root)
        detector.scan()
        results["scanners"]["homograph_detection"] = {
            "status": "completed",
            "findings": len(detector.get_findings()),
            "details": [
                {
                    "file": str(file),
                    "module": module,
                    "message": msg,
                }
                for file, module, msg in detector.get_findings()
            ],
        }
    except HomographAttackDetected as e:
        results["scanners"]["homograph_detection"] = {
            "status": "alert",
            "finding": str(e),
        }
        if strict:
            raise
    except Exception as e:
        results["errors"].append(f"Homograph scan failed: {e}")
        logging.exception("Homograph detection error")

    try:
        analyzer = WorkflowTaintAnalyzer(project_root)
        analyzer.scan()
        results["scanners"]["pipeline_taint"] = {
            "status": "completed",
            "findings": len(analyzer.get_findings()),
            "details": analyzer.get_findings(),
        }
    except SuspiciousPipelineHook as e:
        results["scanners"]["pipeline_taint"] = {
            "status": "alert",
            "finding": str(e),
        }
        if strict:
            raise
    except Exception as e:
        results["errors"].append(f"Pipeline taint scan failed: {e}")
        logging.exception("Pipeline analysis error")

    try:
        registry = RegistryForensics(project_root)
        results["scanners"]["registry_forensics"] = {
            "status": "completed",
            "findings": len(registry.get_findings()),
            "details": registry.get_findings(),
        }
    except GhostPackageWarning as e:
        results["scanners"]["registry_forensics"] = {
            "status": "alert",
            "finding": str(e),
        }
        if strict:
            raise
    except Exception as e:
        results["errors"].append(f"Registry forensics scan failed: {e}")
        logging.exception("Registry forensics error")

    _compute_summary(results)
    return results


def _compute_summary(results: dict) -> None:
    """Compute aggregated severity and finding count."""
    total = 0
    max_severity = "PASS"

    for scanner_name, scanner_result in results["scanners"].items():
        if scanner_result is None:
            continue

        if scanner_result.get("status") == "alert":
            max_severity = "CRITICAL"
            total += 1
        elif scanner_result.get("findings", 0) > 0:
            max_severity = "WARNING"
            total += scanner_result["findings"]

    if results.get("errors"):
        max_severity = "ERROR"

    results["summary"]["total_findings"] = total
    results["summary"]["severity"] = max_severity


def format_report(results: dict, json_output: bool = False) -> str:
    """Format scan results into human-readable or JSON output."""
    if json_output:
        return json.dumps(results, indent=2)

    lines = [
        "=" * 70,
        "VANGUARD SUPPLY CHAIN SECURITY REPORT",
        "=" * 70,
        f"Project: {results['project_root']}",
        f"Status: {results['summary']['severity']}",
        f"Total Findings: {results['summary']['total_findings']}",
        "",
    ]

    for scanner_name, result in results["scanners"].items():
        if result is None:
            continue

        lines.append(f"\n[{scanner_name.upper().replace('_', ' ')}]")
        if result.get("status") == "alert":
            lines.append(f"  ⚠ ALERT: {result['finding']}")
        else:
            count = result.get("findings", 0)
            lines.append(f"  Status: {result['status']}")
            if count > 0:
                lines.append(f"  Findings: {count}")
            else:
                lines.append("  Status: CLEAN")

            for detail in result.get("details", [])[:3]:
                if isinstance(detail, dict):
                    if "message" in detail:
                        lines.append(f"    • {detail.get('message', 'N/A')}")
                    elif "file" in detail:
                        lines.append(f"    • {detail.get('file', 'N/A')}")

    if results.get("errors"):
        lines.append("\n[ERRORS]")
        for error in results["errors"]:
            lines.append(f"  ✗ {error}")

    lines.extend(
        [
            "",
            "=" * 70,
        ]
    )

    return "\n".join(lines)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Vanguard: Supply chain security analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vanguard scan /path/to/project
  vanguard scan . --json
  vanguard scan . --strict --verbose
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan project for vulnerabilities")
    scan_parser.add_argument(
        "project_root",
        type=Path,
        help="Root directory to scan",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on first security finding",
    )
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    project_root = args.project_root
    if not project_root.exists():
        logging.error(f"Project root does not exist: {project_root}")
        return 1

    try:
        results = execute_scan(project_root, strict=args.strict)
        report = format_report(results, json_output=args.json)
        print(report)

        if args.strict and results["summary"]["severity"] in {"CRITICAL", "WARNING"}:
            return 1

        return 0

    except VanguardSecurityError as e:
        logging.error(f"Security violation detected: {e}")
        return 2
    except Exception as e:
        logging.exception("Unexpected error during scan")
        return 2


if __name__ == "__main__":
    sys.exit(main())
