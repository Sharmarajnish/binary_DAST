"""
AFL++ Fuzzer Module
High-performance fuzzing with QEMU mode for ECU binaries.
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import json
import time

from ..utils.architecture_detector import ArchitectureDetector
from .crash_analyzer import CrashAnalyzer, CrashReport

logger = logging.getLogger(__name__)


class AFLFuzzer:
    """
    AFL++ fuzzing module for ECU binaries.
    
    Features:
    - QEMU mode for cross-architecture fuzzing
    - Automotive protocol seed inputs (UDS, CAN)
    - Crash categorization and CWE mapping
    - Simulation mode when AFL++ not installed
    """
    
    def __init__(
        self,
        binary_path: str,
        architecture: Optional[str] = None,
        timeout: int = 300,
        use_simulation: bool = False
    ):
        """
        Initialize AFL++ fuzzer.
        
        Args:
            binary_path: Path to binary to fuzz
            architecture: Override architecture detection
            timeout: Fuzzing timeout in seconds (default 5 minutes)
            use_simulation: Force simulation mode (for testing)
        """
        self.binary_path = binary_path
        self.architecture = architecture
        self.timeout = timeout
        self.use_simulation = use_simulation
        
        self.work_dir: Optional[str] = None
        self.input_dir: Optional[Path] = None
        self.output_dir: Optional[Path] = None
        self.use_qemu_mode = False
        self.qemu_arch: Optional[str] = None
        
        self.arch_detector = ArchitectureDetector()
        self.crash_analyzer = CrashAnalyzer()
        
        # Check if AFL++ is available
        self.afl_available = self._check_afl_available()
        
    def _check_afl_available(self) -> bool:
        """Check if AFL++ is installed and available."""
        try:
            result = subprocess.run(
                ['afl-fuzz', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0 or 'afl-fuzz' in result.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def prepare_environment(self) -> None:
        """Set up fuzzing environment with directories and seed inputs."""
        
        logger.info(f"Preparing fuzzing environment for {self.binary_path}")
        
        # Create temporary work directory
        self.work_dir = tempfile.mkdtemp(prefix="afl_")
        self.input_dir = Path(self.work_dir) / "input"
        self.output_dir = Path(self.work_dir) / "output"
        
        self.input_dir.mkdir(parents=True)
        self.output_dir.mkdir(parents=True)
        
        # Create seed inputs
        self._create_seed_inputs()
        
        # Detect architecture and configure QEMU mode
        self._configure_qemu_mode()
        
        logger.info(f"Work directory: {self.work_dir}")
        logger.info(f"QEMU mode: {self.use_qemu_mode} ({self.qemu_arch})")
    
    def _create_seed_inputs(self) -> None:
        """Create initial seed inputs for fuzzing."""
        
        seeds = [
            # UDS (Unified Diagnostic Services) patterns
            (b"\x10\x01", "uds_diagnostic_session"),
            (b"\x10\x02", "uds_programming_session"),
            (b"\x10\x03", "uds_extended_session"),
            (b"\x27\x01", "uds_security_request_seed"),
            (b"\x27\x02", "uds_security_send_key"),
            (b"\x31\x01\xFF\xFF", "uds_routine_control"),
            (b"\x22\xF1\x90", "uds_read_vin"),
            (b"\x22\xF1\x86", "uds_read_active_session"),
            (b"\x34\x00\x44", "uds_request_download"),
            (b"\x36\x01", "uds_transfer_data"),
            (b"\x37", "uds_request_transfer_exit"),
            (b"\x3E\x00", "uds_tester_present"),
            
            # CAN message patterns
            (b"\x00" * 8, "can_empty_frame"),
            (b"\xFF" * 8, "can_max_values"),
            (b"\xAA\x55" * 4, "can_pattern"),
            (b"\x55\xAA" * 4, "can_inverse_pattern"),
            
            # Edge cases for buffer testing
            (b"A" * 1, "size_1"),
            (b"A" * 8, "size_8"),
            (b"A" * 64, "size_64"),
            (b"A" * 256, "size_256"),
            (b"A" * 1024, "size_1k"),
            
            # Boundary values
            (b"\x00\x00\x00\x00", "null_bytes"),
            (b"\xFF\xFF\xFF\xFF", "max_bytes"),
            (b"\x7F\xFF\xFF\xFF", "int_max"),
            (b"\x80\x00\x00\x00", "int_min"),
            
            # Format string patterns
            (b"%s%s%s%s", "fmt_string_s"),
            (b"%x%x%x%x", "fmt_string_x"),
            (b"%n%n%n%n", "fmt_string_n"),
            (b"AAAA%08x.%08x", "fmt_string_read"),
            
            # Injection patterns
            (b"'; DROP TABLE--", "sql_injection"),
            (b"../../etc/passwd", "path_traversal"),
            (b"<script>alert(1)</script>", "xss"),
            (b"{{7*7}}", "ssti"),
        ]
        
        for i, (data, name) in enumerate(seeds):
            seed_file = self.input_dir / f"seed_{i:03d}_{name}"
            seed_file.write_bytes(data)
        
        logger.info(f"Created {len(seeds)} seed inputs")
    
    def _configure_qemu_mode(self) -> None:
        """Configure QEMU mode based on binary architecture."""
        
        if self.architecture:
            # Use provided architecture
            arch_name = self.architecture.lower()
        else:
            # Auto-detect
            arch_info = self.arch_detector.detect(self.binary_path)
            arch_name = arch_info.name
            self.qemu_arch = arch_info.qemu_arch
        
        # Determine if QEMU mode is needed
        native_archs = {'x86', 'x86_64', 'i386', 'amd64'}
        
        if arch_name not in native_archs:
            self.use_qemu_mode = True
            
            # Map architecture to QEMU arch
            qemu_map = {
                'arm': 'arm',
                'aarch64': 'aarch64',
                'arm64': 'aarch64',
                'powerpc': 'ppc',
                'powerpc64': 'ppc64',
                'ppc': 'ppc',
                'ppc64': 'ppc64',
                'riscv': 'riscv64',
            }
            
            if not self.qemu_arch:
                self.qemu_arch = qemu_map.get(arch_name, 'arm')
    
    def run_fuzzing(self) -> Dict[str, Any]:
        """
        Execute AFL++ fuzzing campaign.
        
        Returns:
            Dict with vulnerabilities and statistics
        """
        if not self.work_dir:
            self.prepare_environment()
        
        print(f"[DAST-Fuzz] Starting fuzzing of {self.binary_path}")
        print(f"[DAST-Fuzz] Timeout: {self.timeout} seconds")
        print(f"[DAST-Fuzz] QEMU mode: {self.use_qemu_mode}")
        
        if self.use_simulation or not self.afl_available:
            logger.warning("AFL++ not available, running in simulation mode")
            return self._run_simulation()
        
        return self._run_afl()
    
    def _run_afl(self) -> Dict[str, Any]:
        """Run actual AFL++ fuzzing."""
        
        # Build AFL++ command
        afl_cmd = [
            'afl-fuzz',
            '-i', str(self.input_dir),
            '-o', str(self.output_dir),
            '-t', '1000+',  # 1 second timeout per execution, with auto-scaling
            '-m', 'none',   # No memory limit
        ]
        
        if self.use_qemu_mode:
            afl_cmd.append('-Q')  # QEMU mode
        
        # Add binary and input placeholder
        afl_cmd.extend([
            '--',
            self.binary_path,
            '@@'  # AFL will replace with input file path
        ])
        
        logger.info(f"Running: {' '.join(afl_cmd)}")
        
        try:
            # Start fuzzing process
            env = os.environ.copy()
            env['AFL_SKIP_CPUFREQ'] = '1'
            env['AFL_NO_UI'] = '1'  # Disable UI for scripted operation
            
            process = subprocess.Popen(
                afl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True
            )
            
            # Wait for timeout
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                time.sleep(1)
                
                # Check if process has ended
                if process.poll() is not None:
                    break
                
                # Log progress periodically
                if int(time.time() - start_time) % 30 == 0:
                    stats = self._get_fuzzing_stats()
                    if stats:
                        logger.info(f"Progress: {stats.get('execs_done', 'N/A')} executions")
            
            # Terminate fuzzing
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            
            logger.info("Fuzzing campaign completed, analyzing results...")
            
        except Exception as e:
            logger.error(f"Fuzzing error: {e}")
            return {'vulnerabilities': [], 'stats': {}, 'error': str(e)}
        
        return self._analyze_results()
    
    def _run_simulation(self) -> Dict[str, Any]:
        """
        Simulate fuzzing for testing without AFL++.
        
        Generates realistic-looking results based on binary analysis.
        """
        logger.info("Running fuzzing simulation...")
        
        # Simulate some findings
        simulated_vulns = []
        
        # Analyze binary for potential vulnerabilities
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            # Look for dangerous patterns
            patterns = [
                (b'strcpy', 'CWE-120', 'high', 'Potential buffer overflow via strcpy'),
                (b'gets', 'CWE-120', 'critical', 'Use of dangerous function gets()'),
                (b'sprintf', 'CWE-134', 'high', 'Potential format string vulnerability'),
                (b'%s', 'CWE-134', 'medium', 'Format specifier found in binary'),
            ]
            
            for pattern, cwe, severity, desc in patterns:
                if pattern in data:
                    simulated_vulns.append({
                        'type': 'simulated_finding',
                        'cwe_id': cwe,
                        'severity': severity,
                        'title': f'Simulated: {desc}',
                        'description': f'Pattern "{pattern.decode(errors="ignore")}" found in binary',
                        'test_case': 'fuzzing_simulation',
                        'detection_method': 'pattern_matching',
                        'exploitability': 'unknown',
                        'note': 'This is a simulated finding. Install AFL++ for real fuzzing.'
                    })
        except Exception as e:
            logger.warning(f"Simulation analysis error: {e}")
        
        return {
            'vulnerabilities': simulated_vulns,
            'stats': {
                'mode': 'simulation',
                'execs_done': 0,
                'paths_total': len(list(self.input_dir.glob('*'))) if self.input_dir else 0,
                'crashes_unique': len(simulated_vulns),
            },
            'work_dir': self.work_dir,
            'note': 'AFL++ not available - results are simulated'
        }
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze fuzzing results and extract vulnerabilities."""
        
        crashes_dir = self.output_dir / "default" / "crashes"
        hangs_dir = self.output_dir / "default" / "hangs"
        
        vulnerabilities = []
        
        # Analyze crashes
        if crashes_dir and crashes_dir.exists():
            for crash_file in crashes_dir.glob("id:*"):
                if crash_file.name == "README.txt":
                    continue
                
                vuln = self._analyze_crash(crash_file)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Analyze hangs
        if hangs_dir and hangs_dir.exists():
            for hang_file in hangs_dir.glob("id:*"):
                if hang_file.name == "README.txt":
                    continue
                
                vuln = self._analyze_hang(hang_file)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Get statistics
        stats = self._get_fuzzing_stats()
        
        return {
            'vulnerabilities': vulnerabilities,
            'stats': stats,
            'work_dir': self.work_dir
        }
    
    def _analyze_crash(self, crash_file: Path) -> Optional[Dict[str, Any]]:
        """Analyze individual crash to determine vulnerability type."""
        
        try:
            crash_input = crash_file.read_bytes()
        except Exception as e:
            logger.error(f"Failed to read crash file {crash_file}: {e}")
            return None
        
        # Use crash analyzer for detailed analysis
        crash_report = self.crash_analyzer.analyze(
            crash_input,
            self.binary_path,
            self.work_dir
        )
        
        # Determine CWE based on crash signature
        cwe_id, severity = self._classify_crash(crash_report)
        
        return {
            'type': 'crash',
            'cwe_id': cwe_id,
            'severity': severity,
            'title': f'Crash detected: {crash_report.signal}',
            'description': f'Fuzzing input caused {crash_report.signal} crash',
            'test_case': 'fuzzing',
            'input_vector': crash_input.hex()[:200],
            'crash_details': {
                'signal': crash_report.signal,
                'address': crash_report.crash_address,
                'instruction': crash_report.crash_instruction,
                'registers': crash_report.registers,
                'backtrace': crash_report.backtrace[:5] if crash_report.backtrace else [],
            },
            'detection_method': 'afl_fuzzing',
            'exploitability': crash_report.exploitability,
            'crash_file': str(crash_file),
        }
    
    def _analyze_hang(self, hang_file: Path) -> Optional[Dict[str, Any]]:
        """Analyze hang (timeout) case."""
        
        try:
            hang_input = hang_file.read_bytes()
        except Exception as e:
            logger.error(f"Failed to read hang file {hang_file}: {e}")
            return None
        
        return {
            'type': 'hang',
            'cwe_id': 'CWE-835',  # Loop with Unreachable Exit Condition
            'severity': 'medium',
            'title': 'Infinite loop or hang detected',
            'description': 'Fuzzing input causes application to hang/timeout',
            'test_case': 'fuzzing',
            'input_vector': hang_input.hex()[:200],
            'detection_method': 'afl_fuzzing',
            'exploitability': 'low',
            'hang_file': str(hang_file),
        }
    
    def _classify_crash(self, crash_report: CrashReport) -> tuple:
        """
        Map crash signature to CWE and severity.
        
        Returns:
            Tuple of (cwe_id, severity)
        """
        signal = crash_report.signal
        
        # CWE classification based on crash type
        classifications = {
            'SIGSEGV': ('CWE-787', 'high'),      # Out-of-bounds Write
            'SIGBUS': ('CWE-787', 'high'),       # Bus error (bad memory access)
            'SIGABRT': ('CWE-674', 'medium'),    # Uncontrolled Recursion or assert
            'SIGILL': ('CWE-704', 'medium'),     # Incorrect Type Conversion
            'SIGFPE': ('CWE-369', 'low'),        # Divide By Zero
            'SIGTRAP': ('CWE-20', 'medium'),     # Breakpoint/trap
            'UNKNOWN': ('CWE-20', 'medium'),     # Improper Input Validation
        }
        
        # Refine based on exploitability
        cwe, severity = classifications.get(signal, ('CWE-20', 'medium'))
        
        if crash_report.exploitability == 'high':
            if severity == 'medium':
                severity = 'high'
            elif severity == 'low':
                severity = 'medium'
        
        return cwe, severity
    
    def _get_fuzzing_stats(self) -> Dict[str, Any]:
        """Get AFL++ statistics from fuzzer_stats file."""
        
        if not self.output_dir:
            return {}
        
        stats_file = self.output_dir / "default" / "fuzzer_stats"
        
        if not stats_file.exists():
            return {}
        
        stats = {}
        try:
            for line in stats_file.read_text().splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    stats[key.strip()] = value.strip()
        except Exception as e:
            logger.warning(f"Failed to read fuzzer stats: {e}")
        
        return {
            'execs_done': stats.get('execs_done', '0'),
            'execs_per_sec': stats.get('execs_per_sec', '0'),
            'paths_total': stats.get('paths_total', '0'),
            'crashes_unique': stats.get('unique_crashes', '0'),
            'hangs_unique': stats.get('unique_hangs', '0'),
            'last_path': stats.get('last_path', '0'),
            'stability': stats.get('stability', 'unknown'),
            'bitmap_cvg': stats.get('bitmap_cvg', 'unknown'),
        }
    
    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.work_dir and os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)
            logger.info(f"Cleaned up work directory: {self.work_dir}")
            self.work_dir = None
    
    def __enter__(self):
        """Context manager entry."""
        self.prepare_environment()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
        return False