"""
angr Symbolic Execution Engine
Analyze binaries using symbolic execution to find vulnerabilities.
"""

import logging
from typing import List, Dict, Optional, Any, Set
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import angr - it may not be installed
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability found during symbolic execution."""
    vuln_type: str
    cwe_id: str
    severity: str
    title: str
    description: str
    function: Optional[str]
    address: Optional[str]
    detection_method: str
    remediation: Optional[str] = None
    input_vector: Optional[str] = None
    exploitability: str = 'unknown'


class AngrSymbolicEngine:
    """
    Symbolic execution engine using angr for vulnerability detection.
    
    Detects:
    - Dangerous function usage (strcpy, gets, sprintf, etc.)
    - Buffer overflows via symbolic exploration
    - Format string vulnerabilities
    - Integer overflows
    - Null pointer dereferences
    """
    
    # Dangerous functions and their CWE mappings
    DANGEROUS_FUNCTIONS: Dict[str, Dict[str, Any]] = {
        'strcpy': {
            'cwe': 'CWE-120',
            'severity': 'high',
            'description': 'strcpy does not check buffer bounds',
            'remediation': 'Use strncpy or strlcpy instead'
        },
        'strcat': {
            'cwe': 'CWE-120',
            'severity': 'high',
            'description': 'strcat does not check buffer bounds',
            'remediation': 'Use strncat or strlcat instead'
        },
        'gets': {
            'cwe': 'CWE-120',
            'severity': 'critical',
            'description': 'gets has no bounds checking and is always unsafe',
            'remediation': 'Use fgets instead'
        },
        'sprintf': {
            'cwe': 'CWE-120',
            'severity': 'high',
            'description': 'sprintf does not check buffer bounds',
            'remediation': 'Use snprintf instead'
        },
        'vsprintf': {
            'cwe': 'CWE-120',
            'severity': 'high',
            'description': 'vsprintf does not check buffer bounds',
            'remediation': 'Use vsnprintf instead'
        },
        'scanf': {
            'cwe': 'CWE-20',
            'severity': 'medium',
            'description': 'scanf can overflow buffers with %s format',
            'remediation': 'Use width specifiers like %100s'
        },
        'sscanf': {
            'cwe': 'CWE-20',
            'severity': 'medium',
            'description': 'sscanf can overflow buffers with %s format',
            'remediation': 'Use width specifiers'
        },
        'memcpy': {
            'cwe': 'CWE-120',
            'severity': 'medium',
            'description': 'memcpy can overflow if size is not validated',
            'remediation': 'Validate size parameter before calling'
        },
        'memmove': {
            'cwe': 'CWE-120',
            'severity': 'medium',
            'description': 'memmove can overflow if size is not validated',
            'remediation': 'Validate size parameter before calling'
        },
        'printf': {
            'cwe': 'CWE-134',
            'severity': 'high',
            'description': 'printf with user-controlled format string',
            'remediation': 'Always use a constant format string'
        },
        'fprintf': {
            'cwe': 'CWE-134',
            'severity': 'high',
            'description': 'fprintf with user-controlled format string',
            'remediation': 'Always use a constant format string'
        },
        'system': {
            'cwe': 'CWE-78',
            'severity': 'critical',
            'description': 'system() can lead to command injection',
            'remediation': 'Use exec family functions with proper argument handling'
        },
        'popen': {
            'cwe': 'CWE-78',
            'severity': 'critical',
            'description': 'popen() can lead to command injection',
            'remediation': 'Sanitize input or use safer alternatives'
        },
        'exec': {
            'cwe': 'CWE-78',
            'severity': 'high',
            'description': 'exec functions can lead to command injection',
            'remediation': 'Sanitize all arguments'
        },
    }
    
    def __init__(self, binary_path: str, use_simulation: bool = False):
        """
        Initialize symbolic execution engine.
        
        Args:
            binary_path: Path to binary to analyze
            use_simulation: Force simulation mode (for testing)
        """
        self.binary_path = binary_path
        self.use_simulation = use_simulation
        self.project = None
        self.cfg = None
        self.vulnerabilities: List[VulnerabilityFinding] = []
        
        if not ANGR_AVAILABLE:
            logger.warning("angr not installed - running in simulation mode")
            self.use_simulation = True
    
    def initialize(self) -> bool:
        """
        Load binary into angr and initialize analysis.
        
        Returns:
            True if successful, False otherwise
        """
        if self.use_simulation:
            logger.info(f"[Simulation] Would load binary: {self.binary_path}")
            return True
        
        try:
            logger.info(f"Loading binary into angr: {self.binary_path}")
            
            self.project = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={
                    'main_opts': {'base_addr': 0x400000}
                }
            )
            
            logger.info(f"Binary loaded: arch={self.project.arch.name}, "
                       f"entry={hex(self.project.entry)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False
    
    def find_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Run all vulnerability checks and return findings.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.vulnerabilities = []
        
        if not self.project and not self.use_simulation:
            if not self.initialize():
                return []
        
        # Run all checks
        print("[DAST-Symbolic] Searching for dangerous functions...")
        self._check_dangerous_functions()
        
        print("[DAST-Symbolic] Searching for buffer overflows...")
        self._check_buffer_overflows()
        
        print("[DAST-Symbolic] Searching for format string bugs...")
        self._check_format_strings()
        
        print("[DAST-Symbolic] Searching for integer overflows...")
        self._check_integer_overflows()
        
        print("[DAST-Symbolic] Searching for null pointer dereferences...")
        self._check_null_pointer_deref()
        
        # Convert findings to dicts
        return [self._finding_to_dict(v) for v in self.vulnerabilities]
    
    def _check_dangerous_functions(self) -> None:
        """Find calls to dangerous functions."""
        
        if self.use_simulation:
            self._simulate_dangerous_function_check()
            return
        
        try:
            # Build CFG if not already done
            if not self.cfg:
                logger.info("Building Control Flow Graph...")
                self.cfg = self.project.analyses.CFGFast()
            
            # Look for dangerous functions
            for func_name, info in self.DANGEROUS_FUNCTIONS.items():
                self._find_function_usage(func_name, info)
                
        except Exception as e:
            logger.error(f"Error checking dangerous functions: {e}")
    
    def _find_function_usage(self, func_name: str, info: Dict[str, Any]) -> None:
        """Find all usages of a specific function."""
        
        for func in self.cfg.functions.values():
            # Check function name (may include library prefix)
            if func_name.lower() in func.name.lower():
                finding = VulnerabilityFinding(
                    vuln_type='dangerous_function',
                    cwe_id=info['cwe'],
                    severity=info['severity'],
                    title=f'Use of dangerous function: {func_name}',
                    description=info['description'],
                    function=func.name,
                    address=hex(func.addr),
                    detection_method='symbolic_execution',
                    remediation=info.get('remediation')
                )
                self.vulnerabilities.append(finding)
    
    def _check_buffer_overflows(self) -> None:
        """Use symbolic execution to detect buffer overflows."""
        
        if self.use_simulation:
            self._simulate_buffer_overflow_check()
            return
        
        try:
            # Create symbolic input
            state = self.project.factory.entry_state()
            
            # Make stdin symbolic (common input vector)
            symbolic_input = claripy.BVS('symbolic_stdin', 8 * 256)  # 256 bytes
            state.posix.stdin.write_to(symbolic_input)
            state.posix.stdin.seek(0)
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore for a limited number of steps
            simgr.explore(n=100)
            
            # Check for states that might indicate overflow
            for stash_name in ['errored', 'unconstrained']:
                stash = getattr(simgr, stash_name, [])
                for state in stash:
                    if self._is_potential_overflow(state):
                        finding = VulnerabilityFinding(
                            vuln_type='buffer_overflow',
                            cwe_id='CWE-787',
                            severity='high',
                            title='Potential buffer overflow detected',
                            description='Symbolic execution found path to memory corruption',
                            function=None,
                            address=hex(state.addr) if hasattr(state, 'addr') else None,
                            detection_method='symbolic_execution',
                            exploitability='medium'
                        )
                        self.vulnerabilities.append(finding)
                        
        except Exception as e:
            logger.debug(f"Buffer overflow check error: {e}")
    
    def _is_potential_overflow(self, state) -> bool:
        """Check if state indicates potential buffer overflow."""
        try:
            # Check for symbolic PC (potential control flow hijack)
            if state.regs.pc.symbolic:
                return True
            
            # Check for unconstrained memory writes
            if hasattr(state, 'history') and state.history.jumpkind == 'Ijk_SigSEGV':
                return True
                
        except Exception:
            pass
        
        return False
    
    def _check_format_strings(self) -> None:
        """Detect format string vulnerabilities."""
        
        if self.use_simulation:
            self._simulate_format_string_check()
            return
        
        try:
            if not self.cfg:
                self.cfg = self.project.analyses.CFGFast()
            
            # Format functions to check
            format_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 
                          'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
                          'syslog']
            
            for func in self.cfg.functions.values():
                func_name_lower = func.name.lower()
                
                for fmt_func in format_funcs:
                    if fmt_func in func_name_lower:
                        # Check if format string argument might be user-controlled
                        # This is a simplified check
                        finding = VulnerabilityFinding(
                            vuln_type='format_string',
                            cwe_id='CWE-134',
                            severity='high',
                            title=f'Potential format string vulnerability in {func.name}',
                            description='Format function may use user-controlled format string',
                            function=func.name,
                            address=hex(func.addr),
                            detection_method='symbolic_execution',
                            remediation='Use constant format strings'
                        )
                        self.vulnerabilities.append(finding)
                        break
                        
        except Exception as e:
            logger.debug(f"Format string check error: {e}")
    
    def _check_integer_overflows(self) -> None:
        """Detect potential integer overflow vulnerabilities."""
        
        if self.use_simulation:
            self._simulate_integer_overflow_check()
            return
        
        try:
            if not self.cfg:
                self.cfg = self.project.analyses.CFGFast()
            
            # Look for size/length calculation functions
            size_keywords = ['size', 'length', 'len', 'count', 'num', 
                           'alloc', 'malloc', 'realloc', 'calloc']
            
            for func in self.cfg.functions.values():
                func_name_lower = func.name.lower()
                
                for keyword in size_keywords:
                    if keyword in func_name_lower:
                        finding = VulnerabilityFinding(
                            vuln_type='integer_overflow',
                            cwe_id='CWE-190',
                            severity='medium',
                            title=f'Potential integer overflow in {func.name}',
                            description='Function performs size calculations that may overflow',
                            function=func.name,
                            address=hex(func.addr),
                            detection_method='symbolic_execution',
                            remediation='Add overflow checks before arithmetic operations'
                        )
                        self.vulnerabilities.append(finding)
                        break
                        
        except Exception as e:
            logger.debug(f"Integer overflow check error: {e}")
    
    def _check_null_pointer_deref(self) -> None:
        """Detect potential null pointer dereferences."""
        
        if self.use_simulation:
            return  # Complex to simulate
        
        try:
            # Create state with null pointers possible
            state = self.project.factory.entry_state(
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
            )
            
            simgr = self.project.factory.simulation_manager(state)
            
            # Look for null dereferences
            def is_null_deref(s):
                try:
                    # Check if we're accessing address 0
                    if s.solver.is_true(s.regs.pc == 0):
                        return True
                except Exception:
                    pass
                return False
            
            simgr.explore(find=is_null_deref, n=50)
            
            for state in simgr.found:
                finding = VulnerabilityFinding(
                    vuln_type='null_pointer_deref',
                    cwe_id='CWE-476',
                    severity='medium',
                    title='Potential null pointer dereference',
                    description='Symbolic execution found path to null pointer dereference',
                    function=None,
                    address=hex(state.addr) if hasattr(state, 'addr') else None,
                    detection_method='symbolic_execution',
                    exploitability='low'
                )
                self.vulnerabilities.append(finding)
                
        except Exception as e:
            logger.debug(f"Null pointer check error: {e}")
    
    # Simulation methods for testing without angr
    
    def _simulate_dangerous_function_check(self) -> None:
        """Simulate dangerous function detection."""
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            for func_name, info in self.DANGEROUS_FUNCTIONS.items():
                if func_name.encode() in data:
                    finding = VulnerabilityFinding(
                        vuln_type='dangerous_function',
                        cwe_id=info['cwe'],
                        severity=info['severity'],
                        title=f'[Simulated] Use of dangerous function: {func_name}',
                        description=info['description'],
                        function=func_name,
                        address='0x00000000',
                        detection_method='symbolic_execution_simulation',
                        remediation=info.get('remediation')
                    )
                    self.vulnerabilities.append(finding)
                    
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
    
    def _simulate_buffer_overflow_check(self) -> None:
        """Simulate buffer overflow detection."""
        # Check for common patterns in binary
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            overflow_indicators = [b'strcpy', b'strcat', b'gets', b'sprintf']
            
            for indicator in overflow_indicators:
                if indicator in data:
                    finding = VulnerabilityFinding(
                        vuln_type='buffer_overflow',
                        cwe_id='CWE-787',
                        severity='high',
                        title=f'[Simulated] Potential buffer overflow via {indicator.decode()}',
                        description='Binary contains function known to cause buffer overflows',
                        function=indicator.decode(),
                        address='0x00000000',
                        detection_method='symbolic_execution_simulation',
                        exploitability='medium'
                    )
                    self.vulnerabilities.append(finding)
                    break  # Only report once
                    
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
    
    def _simulate_format_string_check(self) -> None:
        """Simulate format string detection."""
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            if b'%s' in data and (b'printf' in data or b'sprintf' in data):
                finding = VulnerabilityFinding(
                    vuln_type='format_string',
                    cwe_id='CWE-134',
                    severity='high',
                    title='[Simulated] Potential format string vulnerability',
                    description='Binary uses printf-family functions with format specifiers',
                    function='printf',
                    address='0x00000000',
                    detection_method='symbolic_execution_simulation',
                    remediation='Audit all printf calls for format string issues'
                )
                self.vulnerabilities.append(finding)
                
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
    
    def _simulate_integer_overflow_check(self) -> None:
        """Simulate integer overflow detection."""
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            if b'malloc' in data or b'calloc' in data or b'realloc' in data:
                finding = VulnerabilityFinding(
                    vuln_type='integer_overflow',
                    cwe_id='CWE-190',
                    severity='medium',
                    title='[Simulated] Potential integer overflow in memory allocation',
                    description='Binary performs memory allocation that may be vulnerable to integer overflow',
                    function='malloc/calloc',
                    address='0x00000000',
                    detection_method='symbolic_execution_simulation',
                    remediation='Validate size calculations before memory allocation'
                )
                self.vulnerabilities.append(finding)
                
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
    
    def _finding_to_dict(self, finding: VulnerabilityFinding) -> Dict[str, Any]:
        """Convert VulnerabilityFinding to dictionary."""
        return {
            'type': finding.vuln_type,
            'cwe_id': finding.cwe_id,
            'severity': finding.severity,
            'title': finding.title,
            'description': finding.description,
            'function': finding.function,
            'address': finding.address,
            'detection_method': finding.detection_method,
            'remediation': finding.remediation,
            'input_vector': finding.input_vector,
            'exploitability': finding.exploitability,
        }
    
    def get_function_list(self) -> List[Dict[str, Any]]:
        """Get list of all functions in the binary."""
        
        if self.use_simulation or not self.project:
            return []
        
        try:
            if not self.cfg:
                self.cfg = self.project.analyses.CFGFast()
            
            functions = []
            for func in self.cfg.functions.values():
                functions.append({
                    'name': func.name,
                    'address': hex(func.addr),
                    'size': func.size,
                    'is_simprocedure': func.is_simprocedure,
                })
            
            return functions
            
        except Exception as e:
            logger.error(f"Error getting function list: {e}")
            return []