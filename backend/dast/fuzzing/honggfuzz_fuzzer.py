"""
Honggfuzz Fuzzer Module
Google's feedback-driven fuzzer with hardware-assisted coverage.
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import time

logger = logging.getLogger(__name__)


class HonggfuzzFuzzer:
    """
    Honggfuzz fuzzer for ECU binaries.
    
    Features:
    - Hardware-assisted coverage (Intel PT, BTS)
    - Persistent fuzzing mode
    - Multi-process parallelization
    - Automatic crash deduplication
    """
    
    def __init__(
        self,
        binary_path: str,
        timeout: int = 300,
        threads: int = 4,
        use_simulation: bool = False
    ):
        """
        Initialize Honggfuzz fuzzer.
        
        Args:
            binary_path: Path to binary to fuzz
            timeout: Fuzzing timeout in seconds
            threads: Number of parallel fuzzing threads
            use_simulation: Force simulation mode
        """
        self.binary_path = binary_path
        self.timeout = timeout
        self.threads = threads
        self.use_simulation = use_simulation
        
        self.work_dir: Optional[str] = None
        self.input_dir: Optional[Path] = None
        self.output_dir: Optional[Path] = None
        
        self.honggfuzz_available = self._check_available()
    
    def _check_available(self) -> bool:
        """Check if honggfuzz is installed."""
        try:
            result = subprocess.run(
                ['honggfuzz', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'honggfuzz' in result.stdout.lower() or result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def prepare_environment(self) -> None:
        """Set up fuzzing environment."""
        
        self.work_dir = tempfile.mkdtemp(prefix="honggfuzz_")
        self.input_dir = Path(self.work_dir) / "input"
        self.output_dir = Path(self.work_dir) / "output"
        
        self.input_dir.mkdir(parents=True)
        self.output_dir.mkdir(parents=True)
        
        self._create_seed_inputs()
        
        logger.info(f"Honggfuzz work directory: {self.work_dir}")
    
    def _create_seed_inputs(self) -> None:
        """Create automotive-specific seed inputs."""
        
        seeds = [
            # UDS seeds
            (b"\x10\x01", "uds_session_default"),
            (b"\x10\x03", "uds_session_extended"),
            (b"\x27\x01", "uds_security_seed"),
            (b"\x22\xF1\x90", "uds_read_vin"),
            (b"\x3E\x00", "uds_tester_present"),
            
            # CAN seeds
            (b"\x00" * 8, "can_zeros"),
            (b"\xFF" * 8, "can_max"),
            
            # Buffer test seeds
            (b"A" * 64, "overflow_64"),
            (b"A" * 256, "overflow_256"),
            
            # Edge cases
            (b"\x00", "single_null"),
            (b"\xFF", "single_max"),
        ]
        
        for data, name in seeds:
            (self.input_dir / name).write_bytes(data)
    
    def run_fuzzing(self) -> Dict[str, Any]:
        """
        Execute Honggfuzz fuzzing campaign.
        
        Returns:
            Dict with vulnerabilities and statistics
        """
        if not self.work_dir:
            self.prepare_environment()
        
        print(f"[DAST-Honggfuzz] Starting fuzzing of {self.binary_path}")
        print(f"[DAST-Honggfuzz] Threads: {self.threads}, Timeout: {self.timeout}s")
        
        if self.use_simulation or not self.honggfuzz_available:
            logger.warning("Honggfuzz not available, running simulation")
            return self._run_simulation()
        
        return self._run_honggfuzz()
    
    def _run_honggfuzz(self) -> Dict[str, Any]:
        """Run actual Honggfuzz fuzzing."""
        
        cmd = [
            'honggfuzz',
            '-i', str(self.input_dir),
            '-o', str(self.output_dir),
            '-n', str(self.threads),
            '--timeout', '1',  # Per-execution timeout
            '--run_time', str(self.timeout),
            '-s',  # Save unique crashes
            '--',
            self.binary_path,
            '___FILE___'  # Honggfuzz input placeholder
        ]
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            env = os.environ.copy()
            env['MALLOC_CHECK_'] = '3'  # Enable memory checking
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True
            )
            
            # Wait for timeout
            try:
                process.wait(timeout=self.timeout + 10)
            except subprocess.TimeoutExpired:
                process.terminate()
            
        except Exception as e:
            logger.error(f"Honggfuzz error: {e}")
            return {'vulnerabilities': [], 'stats': {'error': str(e)}}
        
        return self._analyze_results()
    
    def _run_simulation(self) -> Dict[str, Any]:
        """Simulate Honggfuzz for testing."""
        
        vulnerabilities = []
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            # Pattern-based detection
            patterns = [
                (b'strcpy', 'CWE-120', 'high', 'strcpy usage detected'),
                (b'sprintf', 'CWE-134', 'high', 'sprintf usage detected'),
                (b'gets', 'CWE-120', 'critical', 'gets usage detected'),
            ]
            
            for pattern, cwe, severity, desc in patterns:
                if pattern in data:
                    vulnerabilities.append({
                        'type': 'simulated_finding',
                        'cwe_id': cwe,
                        'severity': severity,
                        'title': f'[Simulated Honggfuzz] {desc}',
                        'description': desc,
                        'detection_method': 'honggfuzz_simulation',
                        'note': 'Install honggfuzz for real fuzzing'
                    })
                    
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'stats': {'mode': 'simulation'},
            'fuzzer': 'honggfuzz'
        }
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze Honggfuzz crash results."""
        
        vulnerabilities = []
        
        # Honggfuzz saves crashes to output dir
        crash_patterns = ['SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGFPE', 'SIGILL']
        
        for crash_file in self.output_dir.glob("*"):
            if not crash_file.is_file():
                continue
            
            # Check filename for crash type
            for sig in crash_patterns:
                if sig in crash_file.name.upper():
                    crash_input = crash_file.read_bytes()
                    
                    cwe, severity = self._classify_signal(sig)
                    
                    vulnerabilities.append({
                        'type': 'crash',
                        'cwe_id': cwe,
                        'severity': severity,
                        'title': f'Honggfuzz crash: {sig}',
                        'description': f'Fuzzing triggered {sig} signal',
                        'input_vector': crash_input.hex()[:200],
                        'crash_signal': sig,
                        'detection_method': 'honggfuzz_fuzzing',
                        'exploitability': 'high' if sig == 'SIGSEGV' else 'medium'
                    })
                    break
        
        stats = self._get_stats()
        
        return {
            'vulnerabilities': vulnerabilities,
            'stats': stats,
            'fuzzer': 'honggfuzz'
        }
    
    def _classify_signal(self, signal: str) -> tuple:
        """Map signal to CWE and severity."""
        mapping = {
            'SIGSEGV': ('CWE-787', 'high'),
            'SIGABRT': ('CWE-674', 'medium'),
            'SIGBUS': ('CWE-125', 'high'),
            'SIGFPE': ('CWE-369', 'low'),
            'SIGILL': ('CWE-704', 'medium'),
        }
        return mapping.get(signal, ('CWE-20', 'medium'))
    
    def _get_stats(self) -> Dict[str, Any]:
        """Get Honggfuzz statistics."""
        
        # Honggfuzz writes stats to HONGGFUZZ.REPORT.TXT
        report_file = Path(self.work_dir) / "HONGGFUZZ.REPORT.TXT"
        
        if report_file.exists():
            try:
                content = report_file.read_text()
                # Parse report
                stats = {'raw_report': content[:500]}
                return stats
            except Exception:
                pass
        
        return {'mode': 'honggfuzz'}
    
    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.work_dir and os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)
            self.work_dir = None