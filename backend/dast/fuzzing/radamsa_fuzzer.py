"""
Radamsa Mutation Fuzzer Module
Mutation-based fuzzer excellent for protocol fuzzing.
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
import logging

logger = logging.getLogger(__name__)


class RadamsaFuzzer:
    """
    Radamsa mutation-based fuzzer.
    
    Features:
    - Smart mutation of inputs
    - Protocol-aware fuzzing (CAN, UDS)
    - High-throughput mutation generation
    - No instrumentation required
    """
    
    def __init__(
        self,
        binary_path: str,
        timeout: int = 300,
        mutations_per_seed: int = 100,
        use_simulation: bool = False
    ):
        """
        Initialize Radamsa fuzzer.
        
        Args:
            binary_path: Path to binary to fuzz
            timeout: Fuzzing timeout in seconds
            mutations_per_seed: Number of mutations per seed input
            use_simulation: Force simulation mode
        """
        self.binary_path = binary_path
        self.timeout = timeout
        self.mutations_per_seed = mutations_per_seed
        self.use_simulation = use_simulation
        
        self.work_dir: Optional[str] = None
        self.radamsa_available = self._check_available()
    
    def _check_available(self) -> bool:
        """Check if radamsa is installed."""
        try:
            result = subprocess.run(
                ['radamsa', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def generate_mutations(self, seed: bytes, count: int = 100) -> Iterator[bytes]:
        """
        Generate mutated inputs from a seed.
        
        Args:
            seed: Seed input bytes
            count: Number of mutations to generate
            
        Yields:
            Mutated byte sequences
        """
        if not self.radamsa_available:
            # Fallback to simple mutations
            yield from self._simple_mutations(seed, count)
            return
        
        try:
            # Write seed to temp file
            seed_file = Path(tempfile.mktemp(prefix="radamsa_seed_"))
            seed_file.write_bytes(seed)
            
            # Generate mutations
            result = subprocess.run(
                ['radamsa', '-n', str(count), str(seed_file)],
                capture_output=True,
                timeout=30
            )
            
            # Split output into individual mutations
            output = result.stdout
            if output:
                # Each mutation is separated by newlines in most cases
                # For binary, we split by seed-like boundaries
                chunk_size = len(seed) * 2  # Approximate
                for i in range(0, min(len(output), chunk_size * count), max(1, chunk_size)):
                    chunk = output[i:i + chunk_size]
                    if chunk:
                        yield chunk
            
            seed_file.unlink()
            
        except Exception as e:
            logger.debug(f"Radamsa generation error: {e}")
            yield from self._simple_mutations(seed, count)
    
    def _simple_mutations(self, seed: bytes, count: int) -> Iterator[bytes]:
        """Simple mutation fallback when radamsa unavailable."""
        import random
        
        for _ in range(count):
            mutation_type = random.choice(['flip', 'insert', 'delete', 'repeat'])
            mutated = bytearray(seed)
            
            if len(mutated) == 0:
                yield bytes([random.randint(0, 255)])
                continue
            
            if mutation_type == 'flip':
                # Flip random bits
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] ^= (1 << random.randint(0, 7))
            
            elif mutation_type == 'insert':
                # Insert random bytes
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, random.randint(0, 255))
            
            elif mutation_type == 'delete' and len(mutated) > 1:
                # Delete random byte
                pos = random.randint(0, len(mutated) - 1)
                del mutated[pos]
            
            elif mutation_type == 'repeat':
                # Repeat a section
                if len(mutated) >= 2:
                    start = random.randint(0, len(mutated) - 2)
                    end = random.randint(start + 1, len(mutated))
                    mutated = mutated[:end] + mutated[start:end] + mutated[end:]
            
            yield bytes(mutated)
    
    def run_fuzzing(self) -> Dict[str, Any]:
        """
        Execute Radamsa-based fuzzing.
        
        Returns:
            Dict with vulnerabilities and statistics
        """
        print(f"[DAST-Radamsa] Starting mutation fuzzing of {self.binary_path}")
        
        self.work_dir = tempfile.mkdtemp(prefix="radamsa_")
        
        if self.use_simulation or not self.radamsa_available:
            logger.warning("Radamsa not available, using built-in mutations")
        
        vulnerabilities = []
        mutations_tested = 0
        crashes_found = 0
        
        # Automotive-specific seeds
        seeds = self._get_automotive_seeds()
        
        import time
        start_time = time.time()
        
        for seed_name, seed_data in seeds.items():
            if time.time() - start_time > self.timeout:
                break
            
            print(f"[DAST-Radamsa] Mutating seed: {seed_name}")
            
            # Generate mutations
            for mutation in self.generate_mutations(seed_data, self.mutations_per_seed):
                if time.time() - start_time > self.timeout:
                    break
                
                mutations_tested += 1
                
                # Test mutation
                crash = self._test_input(mutation)
                if crash:
                    crashes_found += 1
                    crash['seed'] = seed_name
                    vulnerabilities.append(crash)
        
        self.cleanup()
        
        return {
            'vulnerabilities': vulnerabilities,
            'stats': {
                'mutations_tested': mutations_tested,
                'crashes_found': crashes_found,
                'seeds_used': len(seeds),
            },
            'fuzzer': 'radamsa'
        }
    
    def _get_automotive_seeds(self) -> Dict[str, bytes]:
        """Get automotive protocol seed inputs."""
        return {
            # UDS (ISO 14229)
            'uds_diag_session_default': bytes.fromhex('1001'),
            'uds_diag_session_programming': bytes.fromhex('1002'),
            'uds_diag_session_extended': bytes.fromhex('1003'),
            'uds_security_access_req': bytes.fromhex('2701'),
            'uds_security_access_key': bytes.fromhex('270200000000'),
            'uds_read_vin': bytes.fromhex('22F190'),
            'uds_read_ecu_id': bytes.fromhex('22F18C'),
            'uds_write_did': bytes.fromhex('2EF19000'),
            'uds_routine_start': bytes.fromhex('3101FF00'),
            'uds_routine_stop': bytes.fromhex('3102FF00'),
            'uds_request_download': bytes.fromhex('34004400100000'),
            'uds_transfer_data': bytes.fromhex('3601'),
            'uds_transfer_exit': bytes.fromhex('37'),
            'uds_tester_present': bytes.fromhex('3E00'),
            'uds_ecu_reset_hard': bytes.fromhex('1101'),
            'uds_ecu_reset_soft': bytes.fromhex('1103'),
            
            # CAN frames
            'can_empty': bytes.fromhex('0000000000000000'),
            'can_max': bytes.fromhex('FFFFFFFFFFFFFFFF'),
            'can_pattern_aa55': bytes.fromhex('AA55AA55AA55AA55'),
            'can_pattern_5aa5': bytes.fromhex('5AA55AA55AA55AA5'),
            
            # Attack patterns
            'overflow_small': b'A' * 16,
            'overflow_medium': b'A' * 64,
            'overflow_large': b'A' * 256,
            'format_string_x': b'%x' * 10,
            'format_string_n': b'%n' * 5,
            'format_string_s': b'%s' * 5,
            'path_traversal': b'../../../etc/passwd',
            'null_injection': b'\x00' * 8,
            'integer_max': bytes.fromhex('FFFFFFFF'),
            'integer_neg': bytes.fromhex('FFFFFFFF'),  # -1
        }
    
    def _test_input(self, input_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Test a mutated input against the binary.
        
        Returns:
            Crash info dict if crash detected, None otherwise
        """
        # Write input to temp file
        input_file = Path(self.work_dir) / "current_input"
        input_file.write_bytes(input_data)
        
        try:
            result = subprocess.run(
                [self.binary_path],
                stdin=open(input_file, 'rb'),
                capture_output=True,
                timeout=1
            )
            
            # Check for crash (negative return = signal)
            if result.returncode < 0:
                signal_num = -result.returncode
                signal_map = {
                    11: 'SIGSEGV',
                    6: 'SIGABRT',
                    4: 'SIGILL',
                    8: 'SIGFPE',
                    7: 'SIGBUS',
                }
                signal = signal_map.get(signal_num, f'SIGNAL_{signal_num}')
                
                cwe, severity = self._classify_signal(signal)
                
                return {
                    'type': 'crash',
                    'cwe_id': cwe,
                    'severity': severity,
                    'title': f'Radamsa mutation crash: {signal}',
                    'description': f'Mutated input caused {signal}',
                    'input_vector': input_data.hex()[:200],
                    'crash_signal': signal,
                    'detection_method': 'radamsa_mutation',
                    'exploitability': 'high' if signal == 'SIGSEGV' else 'medium'
                }
                
        except subprocess.TimeoutExpired:
            # Potential hang/DoS
            return {
                'type': 'hang',
                'cwe_id': 'CWE-835',
                'severity': 'medium',
                'title': 'Radamsa mutation hang detected',
                'description': 'Mutated input caused timeout',
                'input_vector': input_data.hex()[:200],
                'detection_method': 'radamsa_mutation',
                'exploitability': 'low'
            }
        except Exception:
            pass
        
        return None
    
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
    
    def fuzz_protocol(
        self,
        protocol: str,
        target_callback: callable
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a specific automotive protocol.
        
        Args:
            protocol: Protocol name (UDS, CAN, DoIP)
            target_callback: Function to send mutated data
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Get protocol-specific seeds
        if protocol.upper() == 'UDS':
            seeds = {k: v for k, v in self._get_automotive_seeds().items() 
                    if k.startswith('uds_')}
        elif protocol.upper() == 'CAN':
            seeds = {k: v for k, v in self._get_automotive_seeds().items() 
                    if k.startswith('can_')}
        else:
            seeds = self._get_automotive_seeds()
        
        for seed_name, seed_data in seeds.items():
            for mutation in self.generate_mutations(seed_data, 50):
                try:
                    # Use callback to test
                    result = target_callback(mutation)
                    if result and result.get('crash'):
                        vulnerabilities.append({
                            'type': 'protocol_crash',
                            'protocol': protocol,
                            'seed': seed_name,
                            'input_vector': mutation.hex()[:200],
                            'detection_method': 'radamsa_protocol_fuzzing',
                            **result
                        })
                except Exception as e:
                    logger.debug(f"Protocol fuzzing error: {e}")
        
        return vulnerabilities
    
    def cleanup(self) -> None:
        """Clean up temporary files."""
        if self.work_dir and os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)
            self.work_dir = None
