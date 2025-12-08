"""
DAST Taint Analysis Module
Triton-based taint tracking for data flow analysis.
"""

from .triton_taint import TritonTaintAnalyzer, TaintResults, TaintedSink

__all__ = [
    'TritonTaintAnalyzer',
    'TaintResults',
    'TaintedSink',
]
