"""
DAST (Dynamic Application Security Testing) Module
For ECU Binary Vulnerability Analysis

This package provides a comprehensive DAST framework for automotive ECU binaries,
including multi-fuzzer support, symbolic execution, protocol fuzzing, and AI enhancement.

Modules:
- fuzzing: AFL++, Honggfuzz, Radamsa based fuzzing
- symbolic: angr-based symbolic execution
- protocol: Boofuzz-based automotive protocol fuzzing (UDS, CAN, DoIP)
- taint: Triton-based taint analysis
- analyzers: CWE detection and vulnerability scoring
- utils: Binary loading and architecture detection

Example usage:
    from dast import ModernDASTOrchestrator, ModernDASTConfig
    
    config = ModernDASTConfig(
        enable_aflpp=True,
        enable_honggfuzz=True,
        enable_ai=True,
        ecu_context={'ecu_type': 'Engine ECU', 'asil': 'ASIL-D'}
    )
    
    orchestrator = ModernDASTOrchestrator('firmware.elf', config)
    results = orchestrator.run_comprehensive_dast()
    print(orchestrator.export_results('sarif'))
"""

from .dast_orchestrator import (
    DASTOrchestrator,
    DASTConfig,
    DASTResults,
    run_dast,
)

from .modern_dast_orchestrator import (
    ModernDASTOrchestrator,
    ModernDASTConfig,
    ModernDASTResults,
    run_modern_dast,
)

from .ai_enhanced_dast import (
    AIEnhancedDAST,
    HybridDASTOrchestrator,
    run_ai_enhanced_dast,
)

from .fuzzing import AFLFuzzer, CrashAnalyzer, HonggfuzzFuzzer, RadamsaFuzzer
from .symbolic import AngrSymbolicEngine, PathExplorer
from .protocol import AutomotiveProtocolFuzzer, UDSFuzzer, CANFuzzer
from .taint import TritonTaintAnalyzer
from .analyzers import CWETopDetector, VulnerabilityScorer
from .utils import BinaryLoader, ArchitectureDetector, SymbolFileHandler
from .version_tracker import VulnerabilityVersionTracker
from .git_integration import GitRepoScanner, scan_github, scan_gitlab

__version__ = '2.1.0'
__author__ = 'ECU Security Team'

__all__ = [
    # Modern Orchestrator (recommended)
    'ModernDASTOrchestrator',
    'ModernDASTConfig',
    'ModernDASTResults',
    'run_modern_dast',
    
    # Legacy Orchestrator
    'DASTOrchestrator',
    'DASTConfig',
    'DASTResults',
    'run_dast',
    
    # AI-Enhanced DAST
    'AIEnhancedDAST',
    'HybridDASTOrchestrator',
    'run_ai_enhanced_dast',
    
    # Fuzzing (Multi-tool)
    'AFLFuzzer',
    'HonggfuzzFuzzer',
    'RadamsaFuzzer',
    'CrashAnalyzer',
    
    # Symbolic execution
    'AngrSymbolicEngine',
    'PathExplorer',
    
    # Protocol fuzzing
    'AutomotiveProtocolFuzzer',
    'UDSFuzzer',
    'CANFuzzer',
    
    # Taint analysis
    'TritonTaintAnalyzer',
    
    # Analyzers
    'CWETopDetector',
    'VulnerabilityScorer',
    
    # Utilities
    'BinaryLoader',
    'ArchitectureDetector',
]

