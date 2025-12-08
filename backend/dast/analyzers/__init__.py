"""
DAST Analyzers Module
CWE detection and vulnerability scoring.
"""

from .cwe_detector import CWETopDetector, CWEInfo
from .vulnerability_scorer import VulnerabilityScorer

__all__ = [
    'CWETopDetector',
    'CWEInfo',
    'VulnerabilityScorer',
]
