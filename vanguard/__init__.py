"""
Vanguard: Advanced supply chain security toolkit.
Detects homograph attacks, pipeline tampering, and suspicious package patterns.
"""

__version__ = "0.1.0"
__author__ = "Celebi"

from vanguard.exceptions import (
    HomographAttackDetected,
    SuspiciousPipelineHook,
    GhostPackageWarning,
)

__all__ = [
    "HomographAttackDetected",
    "SuspiciousPipelineHook",
    "GhostPackageWarning",
]
