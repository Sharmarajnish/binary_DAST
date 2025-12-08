"""
DAST Orchestrator
Main entry point for Dynamic Application Security Testing.

Coordinates all DAST modules:
- AFL++ Fuzzing
- Symbolic Execution (angr)
- Protocol Fuzzing (Boofuzz)
- Taint Analysis (Triton)
- CWE Detection & Scoring
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .fuzzing import AFLFuzzer
from .symbolic import AngrSymbolicEngine, PathExplorer
from .protocol import AutomotiveProtocolFuzzer
from .taint import TritonTaintAnalyzer
from .analyzers import CWETopDetector, VulnerabilityScorer
from .utils import BinaryLoader, ArchitectureDetector

logger = logging.getLogger(__name__)


@dataclass
class DASTConfig:
    """Configuration for DAST analysis."""
    # Module enables
    enable_fuzzing: bool = True
    enable_symbolic: bool = True
    enable_protocol: bool = False
    enable_taint: bool = False
    
    # Timeouts
    fuzzing_timeout: int = 300  # 5 minutes
    symbolic_timeout: int = 300
    protocol_timeout: int = 300
    
    # Protocol fuzzing config
    target_ip: Optional[str] = None
    target_port: int = 13400
    can_interface: Optional[str] = None
    protocol_type: str = 'UDS'  # UDS, CAN, DoIP
    
    # Analysis options
    use_simulation: bool = False
    deduplicate: bool = True
    enrich_cwe: bool = True
    calculate_scores: bool = True
    
    # Output options
    output_format: str = 'json'  # json, sarif


@dataclass
class DASTResults:
    """Complete DAST analysis results."""
    binary_path: str
    architecture: str
    analysis_time: float
    vulnerabilities: List[Dict[str, Any]]
    stats: Dict[str, Any]
    methods_used: List[str]
    summary: Dict[str, Any]


class DASTOrchestrator:
    """
    Main DAST orchestration - runs all DAST modules.
    
    Example usage:
        orchestrator = DASTOrchestrator('firmware.elf')
        results = orchestrator.run_full_dast()
        print(orchestrator.export_results('json'))
    """
    
    def __init__(
        self,
        binary_path: str,
        symbol_file: Optional[str] = None,
        config: Optional[DASTConfig] = None
    ):
        """
        Initialize DAST orchestrator.
        
        Args:
            binary_path: Path to binary to analyze
            symbol_file: Optional path to symbol file
            config: DAST configuration (uses defaults if not provided)
        """
        self.binary_path = binary_path
        self.symbol_file = symbol_file
        self.config = config or DASTConfig()
        
        # Initialize analyzers
        self.cwe_detector = CWETopDetector()
        self.scorer = VulnerabilityScorer(automotive_context=True)
        self.arch_detector = ArchitectureDetector()
        self.binary_loader = BinaryLoader()
        
        # Results storage
        self.results = DASTResults(
            binary_path=binary_path,
            architecture='unknown',
            analysis_time=0.0,
            vulnerabilities=[],
            stats={},
            methods_used=[],
            summary={}
        )
        
        # Detect architecture
        self._detect_architecture()
    
    def _detect_architecture(self) -> None:
        """Detect binary architecture."""
        try:
            arch_info = self.arch_detector.detect(self.binary_path)
            self.results.architecture = arch_info.name
            logger.info(f"Detected architecture: {arch_info.name} "
                       f"({arch_info.bits}-bit, {arch_info.endianness})")
        except Exception as e:
            logger.warning(f"Architecture detection failed: {e}")
    
    def run_full_dast(self) -> DASTResults:
        """
        Run complete DAST analysis with all enabled modules.
        
        Returns:
            DASTResults with all findings
        """
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"DAST Analysis Started: {self.binary_path}")
        print(f"Architecture: {self.results.architecture}")
        print(f"{'='*60}\n")
        
        all_vulns = []
        
        # 1. Fuzzing (Fast, high value)
        if self.config.enable_fuzzing:
            print("[DAST] Running fuzzing analysis...")
            fuzz_results = self.run_fuzzing()
            all_vulns.extend(fuzz_results.get('vulnerabilities', []))
            self.results.stats['fuzzing'] = fuzz_results.get('stats', {})
            self.results.methods_used.append('fuzzing')
            print(f"[DAST] Fuzzing found {len(fuzz_results.get('vulnerabilities', []))} issues")
        
        # 2. Symbolic Execution (Slower, comprehensive)
        if self.config.enable_symbolic:
            print("[DAST] Running symbolic execution...")
            symbolic_results = self.run_symbolic_execution()
            all_vulns.extend(symbolic_results)
            self.results.methods_used.append('symbolic_execution')
            print(f"[DAST] Symbolic execution found {len(symbolic_results)} issues")
        
        # 3. Protocol Fuzzing (If configured)
        if self.config.enable_protocol and self.config.target_ip:
            print("[DAST] Running protocol fuzzing...")
            protocol_results = self.run_protocol_fuzzing()
            all_vulns.extend(protocol_results)
            self.results.methods_used.append('protocol_fuzzing')
            print(f"[DAST] Protocol fuzzing found {len(protocol_results)} issues")
        
        # 4. Taint Analysis (Deep analysis)
        if self.config.enable_taint:
            print("[DAST] Running taint analysis...")
            taint_results = self.run_taint_analysis()
            all_vulns.extend(taint_results)
            self.results.methods_used.append('taint_analysis')
            print(f"[DAST] Taint analysis found {len(taint_results)} issues")
        
        # 5. Enrich with CWE information
        if self.config.enrich_cwe:
            print("[DAST] Enriching with CWE information...")
            all_vulns = [self.cwe_detector.enrich_vulnerability(v) for v in all_vulns]
        
        # 6. Deduplicate findings
        if self.config.deduplicate:
            all_vulns = self._deduplicate_findings(all_vulns)
            print(f"[DAST] After deduplication: {len(all_vulns)} unique issues")
        
        # 7. Calculate scores and prioritize
        if self.config.calculate_scores:
            print("[DAST] Calculating risk scores...")
            all_vulns = self.scorer.prioritize_remediation(all_vulns)
        
        # Store results
        self.results.vulnerabilities = all_vulns
        self.results.analysis_time = time.time() - start_time
        self.results.summary = self.scorer.generate_summary_stats(all_vulns)
        
        print(f"\n{'='*60}")
        print(f"DAST Analysis Complete")
        print(f"Time: {self.results.analysis_time:.1f} seconds")
        print(f"Total vulnerabilities: {len(all_vulns)}")
        print(f"{'='*60}\n")
        
        return self.results
    
    def run_fuzzing(self) -> Dict[str, Any]:
        """
        Execute fuzzing module.
        
        Returns:
            Fuzzing results dictionary
        """
        try:
            fuzzer = AFLFuzzer(
                self.binary_path,
                timeout=self.config.fuzzing_timeout,
                use_simulation=self.config.use_simulation
            )
            
            fuzzer.prepare_environment()
            results = fuzzer.run_fuzzing()
            fuzzer.cleanup()
            
            return results
            
        except Exception as e:
            logger.error(f"Fuzzing error: {e}")
            return {'vulnerabilities': [], 'stats': {'error': str(e)}}
    
    def run_symbolic_execution(self) -> List[Dict[str, Any]]:
        """
        Execute symbolic execution module.
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            engine = AngrSymbolicEngine(
                self.binary_path,
                use_simulation=self.config.use_simulation
            )
            engine.initialize()
            
            vulnerabilities = engine.find_vulnerabilities()
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Symbolic execution error: {e}")
            return []
    
    def run_protocol_fuzzing(self) -> List[Dict[str, Any]]:
        """
        Execute protocol fuzzing module.
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            fuzzer = AutomotiveProtocolFuzzer(
                target_ip=self.config.target_ip,
                target_port=self.config.target_port,
                can_interface=self.config.can_interface,
                use_simulation=self.config.use_simulation
            )
            
            if self.config.protocol_type.upper() == 'UDS':
                result = fuzzer.fuzz_uds_services(timeout=self.config.protocol_timeout)
            elif self.config.protocol_type.upper() == 'CAN':
                result = fuzzer.fuzz_can_frames(timeout=self.config.protocol_timeout)
            elif self.config.protocol_type.upper() == 'DOIP':
                result = fuzzer.fuzz_doip(timeout=self.config.protocol_timeout)
            else:
                result = fuzzer.fuzz_uds_services(timeout=self.config.protocol_timeout)
            
            return result.vulnerabilities
            
        except Exception as e:
            logger.error(f"Protocol fuzzing error: {e}")
            return []
    
    def run_taint_analysis(self) -> List[Dict[str, Any]]:
        """
        Execute taint analysis module.
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            analyzer = TritonTaintAnalyzer(
                self.binary_path,
                use_simulation=self.config.use_simulation
            )
            analyzer.initialize()
            
            # Taint common input sources
            analyzer.taint_input(0x1000, 256, "stdin")
            analyzer.taint_register('rdi')  # First argument
            
            results = analyzer.run_analysis()
            
            return analyzer.to_vulnerability_list()
            
        except Exception as e:
            logger.error(f"Taint analysis error: {e}")
            return []
    
    def _deduplicate_findings(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities."""
        
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create fingerprint
            fingerprint = (
                vuln.get('cwe_id'),
                vuln.get('type'),
                vuln.get('function'),
                vuln.get('address'),
            )
            
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(vuln)
        
        return unique
    
    def export_results(self, format: str = 'json') -> str:
        """
        Export results in various formats.
        
        Args:
            format: Output format ('json' or 'sarif')
            
        Returns:
            Formatted output string
        """
        if format.lower() == 'sarif':
            return self._to_sarif()
        else:
            return self._to_json()
    
    def _to_json(self) -> str:
        """Convert results to JSON format."""
        
        output = {
            'binary': self.results.binary_path,
            'architecture': self.results.architecture,
            'analysis_time_seconds': round(self.results.analysis_time, 2),
            'methods_used': self.results.methods_used,
            'summary': self.results.summary,
            'vulnerabilities': self.results.vulnerabilities,
            'stats': self.results.stats,
        }
        
        return json.dumps(output, indent=2, default=str)
    
    def _to_sarif(self) -> str:
        """
        Convert to SARIF format (Static Analysis Results Interchange Format).
        
        SARIF is accepted by GitHub Security, Azure DevOps, and many other tools.
        """
        
        # Build rules from unique CWEs
        rules = {}
        for vuln in self.results.vulnerabilities:
            cwe_id = vuln.get('cwe_id', 'UNKNOWN')
            if cwe_id not in rules:
                rules[cwe_id] = {
                    'id': cwe_id,
                    'name': vuln.get('cwe_name', cwe_id),
                    'shortDescription': {
                        'text': vuln.get('cwe_name', 'Unknown Vulnerability')
                    },
                    'fullDescription': {
                        'text': vuln.get('cwe_description', vuln.get('description', ''))
                    },
                    'helpUri': vuln.get('cwe_url', f'https://cwe.mitre.org/data/definitions/{cwe_id.split("-")[-1]}.html'),
                    'defaultConfiguration': {
                        'level': self._severity_to_sarif_level(vuln.get('severity', 'medium'))
                    }
                }
        
        sarif = {
            'version': '2.1.0',
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'ECU DAST Scanner',
                        'version': '1.0.0',
                        'informationUri': 'https://github.com/your-org/ecu-dast',
                        'rules': list(rules.values())
                    }
                },
                'results': [],
                'invocations': [{
                    'executionSuccessful': True,
                    'commandLine': f'dast-scan {self.binary_path}',
                    'workingDirectory': {
                        'uri': str(Path(self.binary_path).parent)
                    }
                }]
            }]
        }
        
        # Add results
        for vuln in self.results.vulnerabilities:
            result = {
                'ruleId': vuln.get('cwe_id', 'UNKNOWN'),
                'level': self._severity_to_sarif_level(vuln.get('severity', 'medium')),
                'message': {
                    'text': vuln.get('description', vuln.get('title', 'No description'))
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': self.binary_path
                        }
                    },
                    'logicalLocations': [{
                        'name': vuln.get('function', 'unknown'),
                        'kind': 'function'
                    }] if vuln.get('function') else []
                }],
                'properties': {
                    'type': vuln.get('type'),
                    'detection_method': vuln.get('detection_method'),
                    'exploitability': vuln.get('exploitability'),
                    'automotive_impact': vuln.get('automotive_impact'),
                    'priority': vuln.get('priority'),
                }
            }
            
            if vuln.get('address'):
                result['locations'][0]['physicalLocation']['address'] = {
                    'absoluteAddress': int(vuln['address'], 16) if isinstance(vuln['address'], str) else vuln['address']
                }
            
            sarif['runs'][0]['results'].append(result)
        
        return json.dumps(sarif, indent=2)
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Map severity to SARIF level."""
        
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note',
        }
        
        return mapping.get(severity.lower(), 'warning')
    
    def get_high_priority_findings(self, max_count: int = 10) -> List[Dict[str, Any]]:
        """
        Get top high-priority findings.
        
        Args:
            max_count: Maximum number of findings to return
            
        Returns:
            List of high-priority vulnerabilities
        """
        sorted_vulns = sorted(
            self.results.vulnerabilities,
            key=lambda x: (x.get('priority', 5), -x.get('calculated_score', 0))
        )
        
        return sorted_vulns[:max_count]
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """
        Generate compliance-focused report.
        
        Includes mappings to:
        - ISO 26262 (Automotive functional safety)
        - ISO 21434 (Automotive cybersecurity)
        - UNECE R155 (Cybersecurity regulations)
        """
        
        report = {
            'binary': self.binary_path,
            'analysis_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_findings': len(self.results.vulnerabilities),
            
            'iso_26262_asil_distribution': {},
            'iso_21434_relevance': [],
            'unece_r155_concerns': [],
            
            'high_priority_actions': [],
        }
        
        # Categorize by ASIL
        for vuln in self.results.vulnerabilities:
            asil = vuln.get('automotive_impact', 'QM')
            report['iso_26262_asil_distribution'][asil] = \
                report['iso_26262_asil_distribution'].get(asil, 0) + 1
        
        # ISO 21434 relevance (cybersecurity)
        cybersec_cwes = ['CWE-287', 'CWE-306', 'CWE-798', 'CWE-862', 'CWE-863']
        for vuln in self.results.vulnerabilities:
            if vuln.get('cwe_id') in cybersec_cwes:
                report['iso_21434_relevance'].append({
                    'cwe': vuln.get('cwe_id'),
                    'title': vuln.get('title'),
                    'severity': vuln.get('severity'),
                })
        
        # UNECE R155 concerns (attack vectors)
        attack_types = ['command_injection', 'security_bypass', 'unauthorized_access']
        for vuln in self.results.vulnerabilities:
            if vuln.get('type') in attack_types:
                report['unece_r155_concerns'].append({
                    'type': vuln.get('type'),
                    'title': vuln.get('title'),
                    'description': vuln.get('description'),
                })
        
        # High priority actions
        report['high_priority_actions'] = self.get_high_priority_findings(5)
        
        return report


# Convenience function for CLI usage
def run_dast(
    binary_path: str,
    enable_fuzzing: bool = True,
    enable_symbolic: bool = True,
    timeout: int = 300,
    output_format: str = 'json'
) -> str:
    """
    Run DAST analysis on a binary.
    
    Args:
        binary_path: Path to binary
        enable_fuzzing: Enable AFL++ fuzzing
        enable_symbolic: Enable symbolic execution
        timeout: Analysis timeout per module
        output_format: Output format (json/sarif)
        
    Returns:
        Analysis results as formatted string
    """
    config = DASTConfig(
        enable_fuzzing=enable_fuzzing,
        enable_symbolic=enable_symbolic,
        fuzzing_timeout=timeout,
        symbolic_timeout=timeout,
        output_format=output_format,
    )
    
    orchestrator = DASTOrchestrator(binary_path, config=config)
    orchestrator.run_full_dast()
    
    return orchestrator.export_results(output_format)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m dast.dast_orchestrator <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    # Enable logging
    logging.basicConfig(level=logging.INFO)
    
    # Run analysis
    result = run_dast(binary_path)
    print(result)
