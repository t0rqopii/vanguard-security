"""
Custom exception hierarchy for Vanguard supply chain security detection.
"""


class VanguardSecurityError(Exception):
    """Base exception for all Vanguard security detections."""

    pass


class HomographAttackDetected(VanguardSecurityError):
    """
    Raised when Unicode homograph patterns are detected in import statements.
    Indicates potential typosquatting or spoofing via lookalike characters.
    """

    pass


class SuspiciousPipelineHook(VanguardSecurityError):
    """
    Raised when risky patterns are detected in CI/CD pipelines or shell scripts.
    Examples: unpinned actions, remote code execution patterns, tainted variables.
    """

    pass


class GhostPackageWarning(VanguardSecurityError):
    """
    Raised when a package exhibits hallucination trap indicators.
    Indicators: suspicious version history, generic metadata, name similarity spoofing.
    """

    pass
