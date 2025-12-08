"""
Modern DAST Orchestrator
Multi-tool DAST with layered fuzzing, symbolic execution, and AI enhancement.

Architecture:
┌─────────────────────────────────────────────────┐
│  DAST Layer 1: Fuzzing                          │
│  - AFL++ (main fuzzer)                          │
│  - Honggfuzz (secondary)                        │
│  - Radamsa (protocol mutation)                  │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  DAST Layer 2: Protocol-Specific                │
│  - Boofuzz (UDS/DoIP/CAN fuzzing)              │
│  - Custom CAN injector                          │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  DAST Layer 3: Symbolic Execution               │
│  - angr (primary)                               │
│  - Triton (taint analysis)                      │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  DAST Layer 4: AI Enhancement                   │
│  - Claude/Gemini (analysis, PoC, triage)        │
└─────────────────────────────────────────────────┘
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from .fuzzing import AFLFuzzer, CrashAnalyzer, HonggfuzzFuzzer, RadamsaFuzzer
from .symbolic import AngrSymbolicEngine, PathExplorer
from .protocol import AutomotiveProtocolFuzzer
from .taint import TritonTaintAnalyzer
from .analyzers import CWETopDetector, VulnerabilityScorer
from .utils import BinaryLoader, ArchitectureDetector
from .ai_enhanced_dast import AIEnhancedDAST

logger = logging.getLogger(__name__)


@dataclass
class ModernDASTConfig:
    """Configuration for Modern DAST."""
    
    # Layer 1: Fuzzing
    enable_aflpp: bool = True
    enable_honggfuzz: bool = True
    enable_radamsa: bool = True
    fuzzing_timeout: int = 300  # Per-fuzzer
    fuzzing_threads: int = 4
    parallel_fuzzers: bool = False  # Run fuzzers in parallel
    
    # Layer 2: Protocol Fuzzing
    enable_protocol: bool = False
    target_ip: Optional[str] = None
    target_port: int = 13400
    can_interface: Optional[str] = None
    protocol_type: str = 'UDS'
    
    # Layer 3: Symbolic Execution
    enable_symbolic: bool = True
    enable_taint: bool = False
    symbolic_timeout: int = 300
    
    # Layer 4: AI Enhancement
    enable_ai: bool = True
    ai_provider: str = 'gemini'  # 'gemini' or 'anthropic'
    ai_api_key: Optional[str] = None
    
    # ECU Context for AI
    ecu_context: Dict[str, Any] = field(default_factory=lambda: {
        'ecu_type': 'Unknown ECU',
        'asil': 'QM',
        'network': 'Unknown',
        'safety_critical': False,
        'functions': []
    })
    
    # Post-processing
    deduplicate: bool = True
    enrich_cwe: bool = True
    calculate_scores: bool = True
    
    # Output
    output_format: str = 'json'


@dataclass
class ModernDASTResults:
    """Results from Modern DAST analysis."""
    binary_path: str
    architecture: str
    analysis_time: float
    vulnerabilities: List[Dict[str, Any]]
    stats: Dict[str, Any]
    layers_used: List[str]
    ai_enhanced: bool
    executive_summary: Optional[str] = None


class ModernDASTOrchestrator:
    """
    Modern DAST Orchestrator with multi-fuzzer support.
    
    Implements a layered approach:
    1. Multi-fuzzer layer (AFL++, Honggfuzz, Radamsa)
    2. Protocol fuzzing layer (Boofuzz)  
    3. Symbolic execution layer (angr + Triton)
    4. AI enhancement layer (Claude/Gemini)
    
    Example:
        config = ModernDASTConfig(
            enable_aflpp=True,
            enable_honggfuzz=True,
            enable_radamsa=True,
            enable_ai=True,
            ecu_context={'ecu_type': 'Engine ECU', 'asil': 'ASIL-D'}
        )
        
        orchestrator = ModernDASTOrchestrator('firmware.elf', config)
        results = orchestrator.run_comprehensive_dast()
        print(orchestrator.export_results('sarif'))
    """
    
    def __init__(
        self,
        binary_path: str,
        config: Optional[ModernDASTConfig] = None
    ):
        """
        Initialize Modern DAST Orchestrator.
        
        Args:
            binary_path: Path to binary to analyze
            config: Configuration options
        """
        self.binary_path = binary_path
        self.config = config or ModernDASTConfig()
        
        # Analyzers
        self.cwe_detector = CWETopDetector()
        self.scorer = VulnerabilityScorer(automotive_context=True)
        self.arch_detector = ArchitectureDetector()
        
        # Results
        self.results = ModernDASTResults(
            binary_path=binary_path,
            architecture='unknown',
            analysis_time=0.0,
            vulnerabilities=[],
            stats={},
            layers_used=[],
            ai_enhanced=False
        )
        
        # Detect architecture
        self._detect_architecture()
    
    def _detect_architecture(self) -> None:
        """Detect binary architecture."""
        try:
            arch_info = self.arch_detector.detect(self.binary_path)
            self.results.architecture = arch_info.name
            logger.info(f"Architecture: {arch_info.name}")
        except Exception as e:
            logger.warning(f"Architecture detection failed: {e}")
    
    def run_comprehensive_dast(self) -> ModernDASTResults:
        """
        Run comprehensive multi-layer DAST analysis.
        
        Returns:
            ModernDASTResults with all findings
        """
        start_time = time.time()
        all_vulns = []
        
        print("\n" + "=" * 70)
        print("  MODERN DAST ORCHESTRATOR - Multi-Tool Analysis")
        print("=" * 70)
        print(f"  Binary: {self.binary_path}")
        print(f"  Architecture: {self.results.architecture}")
        print("=" * 70 + "\n")
        
        # ═══════════════════════════════════════════════════════════════
        # LAYER 1: FUZZING (AFL++, Honggfuzz, Radamsa)
        # ═══════════════════════════════════════════════════════════════
        print("┌" + "─" * 50 + "┐")
        print("│ LAYER 1: FUZZING                                  │")
        print("└" + "─" * 50 + "┘")
        
        fuzzing_results = self._run_fuzzing_layer()
        all_vulns.extend(fuzzing_results)
        
        # ═══════════════════════════════════════════════════════════════
        # LAYER 2: PROTOCOL FUZZING (Boofuzz)
        # ═══════════════════════════════════════════════════════════════
        if self.config.enable_protocol and self.config.target_ip:
            print("\n┌" + "─" * 50 + "┐")
            print("│ LAYER 2: PROTOCOL FUZZING                        │")
            print("└" + "─" * 50 + "┘")
            
            protocol_results = self._run_protocol_layer()
            all_vulns.extend(protocol_results)
        
        # ═══════════════════════════════════════════════════════════════
        # LAYER 3: SYMBOLIC EXECUTION (angr + Triton)
        # ═══════════════════════════════════════════════════════════════
        if self.config.enable_symbolic:
            print("\n┌" + "─" * 50 + "┐")
            print("│ LAYER 3: SYMBOLIC EXECUTION                      │")
            print("└" + "─" * 50 + "┘")
            
            symbolic_results = self._run_symbolic_layer()
            all_vulns.extend(symbolic_results)
        
        # CWE enrichment
        if self.config.enrich_cwe:
            all_vulns = [self.cwe_detector.enrich_vulnerability(v) for v in all_vulns]
        
        # Deduplication
        if self.config.deduplicate:
            original_count = len(all_vulns)
            all_vulns = self._deduplicate(all_vulns)
            print(f"\n[Dedup] {original_count} → {len(all_vulns)} unique findings")
        
        # Scoring
        if self.config.calculate_scores:
            all_vulns = self.scorer.prioritize_remediation(all_vulns)
        
        # ═══════════════════════════════════════════════════════════════
        # LAYER 4: AI ENHANCEMENT (Claude/Gemini)
        # ═══════════════════════════════════════════════════════════════
        if self.config.enable_ai:
            print("\n┌" + "─" * 50 + "┐")
            print("│ LAYER 4: AI ENHANCEMENT                          │")
            print("└" + "─" * 50 + "┘")
            
            all_vulns, summary = self._run_ai_layer(all_vulns)
            self.results.ai_enhanced = True
            self.results.executive_summary = summary
        
        # Finalize results
        self.results.vulnerabilities = all_vulns
        self.results.analysis_time = time.time() - start_time
        self.results.stats['summary'] = self.scorer.generate_summary_stats(all_vulns)
        
        print("\n" + "=" * 70)
        print("  ANALYSIS COMPLETE")
        print("=" * 70)
        print(f"  Time: {self.results.analysis_time:.1f} seconds")
        print(f"  Total Vulnerabilities: {len(all_vulns)}")
        print(f"  Layers Used: {', '.join(self.results.layers_used)}")
        print(f"  AI Enhanced: {self.results.ai_enhanced}")
        print("=" * 70 + "\n")
        
        return self.results
    
    def _run_fuzzing_layer(self) -> List[Dict[str, Any]]:
        """Run Layer 1: Multi-fuzzer analysis."""
        
        all_vulns = []
        
        fuzzers_to_run = []
        
        if self.config.enable_aflpp:
            fuzzers_to_run.append(('AFL++', self._run_aflpp))
        if self.config.enable_honggfuzz:
            fuzzers_to_run.append(('Honggfuzz', self._run_honggfuzz))
        if self.config.enable_radamsa:
            fuzzers_to_run.append(('Radamsa', self._run_radamsa))
        
        if not fuzzers_to_run:
            return []
        
        self.results.layers_used.append('fuzzing')
        
        if self.config.parallel_fuzzers and len(fuzzers_to_run) > 1:
            # Run fuzzers in parallel
            with ThreadPoolExecutor(max_workers=len(fuzzers_to_run)) as executor:
                futures = {
                    executor.submit(func): name 
                    for name, func in fuzzers_to_run
                }
                
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        result = future.result()
                        vulns = result.get('vulnerabilities', [])
                        all_vulns.extend(vulns)
                        self.results.stats[name.lower()] = result.get('stats', {})
                        print(f"  [{name}] Found {len(vulns)} issues")
                    except Exception as e:
                        print(f"  [{name}] Error: {e}")
        else:
            # Run fuzzers sequentially
            for name, func in fuzzers_to_run:
                print(f"  Running {name}...")
                try:
                    result = func()
                    vulns = result.get('vulnerabilities', [])
                    all_vulns.extend(vulns)
                    self.results.stats[name.lower().replace('+', 'p')] = result.get('stats', {})
                    print(f"  [{name}] Found {len(vulns)} issues")
                except Exception as e:
                    print(f"  [{name}] Error: {e}")
        
        return all_vulns
    
    def _run_aflpp(self) -> Dict[str, Any]:
        """Run AFL++ fuzzer."""
        fuzzer = AFLFuzzer(
            self.binary_path,
            timeout=self.config.fuzzing_timeout
        )
        fuzzer.prepare_environment()
        result = fuzzer.run_fuzzing()
        fuzzer.cleanup()
        return result
    
    def _run_honggfuzz(self) -> Dict[str, Any]:
        """Run Honggfuzz fuzzer."""
        fuzzer = HonggfuzzFuzzer(
            self.binary_path,
            timeout=self.config.fuzzing_timeout,
            threads=self.config.fuzzing_threads
        )
        return fuzzer.run_fuzzing()
    
    def _run_radamsa(self) -> Dict[str, Any]:
        """Run Radamsa mutation fuzzer."""
        fuzzer = RadamsaFuzzer(
            self.binary_path,
            timeout=self.config.fuzzing_timeout
        )
        return fuzzer.run_fuzzing()
    
    def _run_protocol_layer(self) -> List[Dict[str, Any]]:
        """Run Layer 2: Protocol fuzzing."""
        
        self.results.layers_used.append('protocol')
        
        print(f"  Protocol: {self.config.protocol_type}")
        print(f"  Target: {self.config.target_ip}:{self.config.target_port}")
        
        try:
            fuzzer = AutomotiveProtocolFuzzer(
                target_ip=self.config.target_ip,
                target_port=self.config.target_port,
                can_interface=self.config.can_interface
            )
            
            if self.config.protocol_type.upper() == 'UDS':
                result = fuzzer.fuzz_uds_services()
            elif self.config.protocol_type.upper() == 'CAN':
                result = fuzzer.fuzz_can_frames()
            else:
                result = fuzzer.fuzz_doip()
            
            vulns = result.vulnerabilities
            print(f"  [Boofuzz] Found {len(vulns)} issues")
            return vulns
            
        except Exception as e:
            print(f"  [Boofuzz] Error: {e}")
            return []
    
    def _run_symbolic_layer(self) -> List[Dict[str, Any]]:
        """Run Layer 3: Symbolic execution."""
        
        all_vulns = []
        self.results.layers_used.append('symbolic')
        
        # angr
        print("  Running angr symbolic execution...")
        try:
            engine = AngrSymbolicEngine(self.binary_path)
            engine.initialize()
            vulns = engine.find_vulnerabilities()
            all_vulns.extend(vulns)
            print(f"  [angr] Found {len(vulns)} issues")
        except Exception as e:
            print(f"  [angr] Error: {e}")
        
        # Triton taint analysis
        if self.config.enable_taint:
            print("  Running Triton taint analysis...")
            try:
                analyzer = TritonTaintAnalyzer(self.binary_path)
                analyzer.initialize()
                analyzer.taint_input(0x1000, 256, "stdin")
                results = analyzer.run_analysis()
                vulns = analyzer.to_vulnerability_list()
                all_vulns.extend(vulns)
                print(f"  [Triton] Found {len(vulns)} issues")
            except Exception as e:
                print(f"  [Triton] Error: {e}")
        
        return all_vulns
    
    def _run_ai_layer(
        self,
        vulns: List[Dict[str, Any]]
    ) -> tuple:
        """Run Layer 4: AI enhancement."""
        
        self.results.layers_used.append('ai')
        
        print(f"  Provider: {self.config.ai_provider}")
        print(f"  Enhancing {len(vulns)} findings...")
        
        try:
            ai = AIEnhancedDAST(
                provider=self.config.ai_provider,
                api_key=self.config.ai_api_key
            )
            
            enhanced = ai.enhance_dast_results(
                {'vulnerabilities': vulns},
                self.config.ecu_context
            )
            
            enhanced_vulns = enhanced.get('vulnerabilities', vulns)
            summary = enhanced.get('executive_summary', '')
            
            # Count validations
            true_pos = sum(
                1 for v in enhanced_vulns
                if v.get('ai_validation', {}).get('verdict') == 'TRUE_POSITIVE'
            )
            print(f"  [AI] Validated {true_pos} true positives")
            
            return enhanced_vulns, summary
            
        except Exception as e:
            print(f"  [AI] Error: {e}")
            return vulns, None
    
    def _deduplicate(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique = []
        
        for v in vulns:
            # Create fingerprint
            fp = (
                v.get('cwe_id'),
                v.get('type'),
                v.get('function'),
                str(v.get('address'))[:10] if v.get('address') else None,
            )
            
            if fp not in seen:
                seen.add(fp)
                unique.append(v)
        
        return unique
    
    def export_results(self, format: str = 'json') -> str:
        """Export results in JSON or SARIF format."""
        
        if format.lower() == 'sarif':
            return self._to_sarif()
        else:
            return self._to_json()
    
    def _to_json(self) -> str:
        """Export as JSON."""
        output = {
            'binary': self.results.binary_path,
            'architecture': self.results.architecture,
            'analysis_time_seconds': round(self.results.analysis_time, 2),
            'layers_used': self.results.layers_used,
            'ai_enhanced': self.results.ai_enhanced,
            'summary': self.results.stats.get('summary', {}),
            'executive_summary': self.results.executive_summary,
            'vulnerabilities': self.results.vulnerabilities,
            'stats': self.results.stats,
        }
        return json.dumps(output, indent=2, default=str)
    
    def _to_sarif(self) -> str:
        """Export as SARIF 2.1.0."""
        
        rules = {}
        for v in self.results.vulnerabilities:
            cwe_id = v.get('cwe_id', 'UNKNOWN')
            if cwe_id not in rules:
                rules[cwe_id] = {
                    'id': cwe_id,
                    'name': v.get('cwe_name', cwe_id),
                    'shortDescription': {'text': v.get('cwe_name', 'Vulnerability')},
                    'helpUri': v.get('cwe_url', f'https://cwe.mitre.org/'),
                }
        
        sarif = {
            'version': '2.1.0',
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'Modern ECU DAST',
                        'version': '2.0.0',
                        'informationUri': 'https://github.com/example/ecu-dast',
                        'rules': list(rules.values())
                    }
                },
                'results': [
                    {
                        'ruleId': v.get('cwe_id', 'UNKNOWN'),
                        'level': self._severity_to_level(v.get('severity', 'medium')),
                        'message': {'text': v.get('description', v.get('title', ''))},
                        'properties': {
                            'type': v.get('type'),
                            'detection_method': v.get('detection_method'),
                            'priority': v.get('priority'),
                            'ai_validated': v.get('ai_validation', {}).get('verdict'),
                        }
                    }
                    for v in self.results.vulnerabilities
                ]
            }]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _severity_to_level(self, severity: str) -> str:
        mapping = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note'}
        return mapping.get(severity.lower(), 'warning')


# Convenience function
def run_modern_dast(
    binary_path: str,
    ecu_context: Optional[Dict[str, Any]] = None,
    enable_ai: bool = True,
    ai_provider: str = 'gemini'
) -> Dict[str, Any]:
    """
    Run modern multi-tool DAST analysis.
    
    Args:
        binary_path: Path to binary
        ecu_context: ECU context for AI
        enable_ai: Enable AI enhancement
        ai_provider: AI provider (gemini/anthropic)
        
    Returns:
        Analysis results dict
    """
    config = ModernDASTConfig(
        enable_ai=enable_ai,
        ai_provider=ai_provider,
        ecu_context=ecu_context or {}
    )
    
    orchestrator = ModernDASTOrchestrator(binary_path, config)
    results = orchestrator.run_comprehensive_dast()
    
    return {
        'binary': results.binary_path,
        'vulnerabilities': results.vulnerabilities,
        'stats': results.stats,
        'ai_enhanced': results.ai_enhanced,
        'executive_summary': results.executive_summary
    }
