"""
Triton Taint Analysis Module
Track how user input flows through the program to detect injection vulnerabilities.
"""

import logging
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import Triton
try:
    from triton import TritonContext, ARCH, MODE, MemoryAccess, CPUSIZE
    from triton import Instruction as TritonInstruction
    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False


@dataclass
class TaintedSink:
    """Represents a dangerous sink reached by tainted data."""
    sink_type: str
    address: int
    function_name: Optional[str]
    taint_sources: List[str]
    path_length: int
    cwe_id: str
    severity: str
    description: str


@dataclass
class TaintResults:
    """Results from taint analysis."""
    tainted_sinks: List[TaintedSink]
    taint_propagation_count: int
    instructions_analyzed: int
    tainted_memory_regions: List[tuple]  # (start, end)
    tainted_registers: List[str]
    analysis_complete: bool
    notes: List[str] = field(default_factory=list)


class TritonTaintAnalyzer:
    """
    Taint analysis using Triton framework.
    
    Tracks how user input flows through the program to detect:
    - Command injection (tainted data reaching system/exec)
    - SQL injection (tainted data in SQL queries)
    - Format string bugs (tainted format specifiers)
    - Buffer overflows (tainted size parameters)
    """
    
    # Dangerous sinks and their CWE mappings
    DANGEROUS_SINKS: Dict[str, Dict[str, str]] = {
        'system': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'popen': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execl': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execle': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execlp': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execv': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execve': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'execvp': {'cwe': 'CWE-78', 'severity': 'critical', 'type': 'command_injection'},
        'printf': {'cwe': 'CWE-134', 'severity': 'high', 'type': 'format_string'},
        'fprintf': {'cwe': 'CWE-134', 'severity': 'high', 'type': 'format_string'},
        'sprintf': {'cwe': 'CWE-134', 'severity': 'high', 'type': 'format_string'},
        'snprintf': {'cwe': 'CWE-134', 'severity': 'medium', 'type': 'format_string'},
        'strcpy': {'cwe': 'CWE-120', 'severity': 'high', 'type': 'buffer_overflow'},
        'strcat': {'cwe': 'CWE-120', 'severity': 'high', 'type': 'buffer_overflow'},
        'gets': {'cwe': 'CWE-120', 'severity': 'critical', 'type': 'buffer_overflow'},
        'memcpy': {'cwe': 'CWE-120', 'severity': 'medium', 'type': 'buffer_overflow'},
        'memmove': {'cwe': 'CWE-120', 'severity': 'medium', 'type': 'buffer_overflow'},
        'malloc': {'cwe': 'CWE-190', 'severity': 'medium', 'type': 'integer_overflow'},
        'calloc': {'cwe': 'CWE-190', 'severity': 'medium', 'type': 'integer_overflow'},
        'realloc': {'cwe': 'CWE-190', 'severity': 'medium', 'type': 'integer_overflow'},
    }
    
    def __init__(self, binary_path: str, use_simulation: bool = False):
        """
        Initialize taint analyzer.
        
        Args:
            binary_path: Path to binary to analyze
            use_simulation: Force simulation mode
        """
        self.binary_path = binary_path
        self.use_simulation = use_simulation or not TRITON_AVAILABLE
        
        self.ctx = None
        self.tainted_addresses: Set[int] = set()
        self.tainted_registers: Set[str] = set()
        self.sinks_reached: List[TaintedSink] = []
        self.sink_addresses: Dict[int, str] = {}  # addr -> function name
        
        if not TRITON_AVAILABLE:
            logger.warning("Triton not installed - running in simulation mode")
    
    def initialize(self, architecture: str = 'x86_64') -> bool:
        """
        Initialize Triton context for the target architecture.
        
        Args:
            architecture: Target architecture (x86, x86_64, arm, aarch64)
            
        Returns:
            True if successful
        """
        if self.use_simulation:
            logger.info("[Simulation] Taint analyzer initialized")
            return True
        
        try:
            self.ctx = TritonContext()
            
            # Set architecture
            arch_map = {
                'x86': ARCH.X86,
                'x86_64': ARCH.X86_64,
                'arm': ARCH.ARM32,
                'aarch64': ARCH.AARCH64,
            }
            
            arch = arch_map.get(architecture.lower(), ARCH.X86_64)
            self.ctx.setArchitecture(arch)
            
            # Enable taint engine
            self.ctx.enableTaintEngine(True)
            
            logger.info(f"Triton initialized for {architecture}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Triton: {e}")
            return False
    
    def taint_input(self, address: int, size: int, source_name: str = "user_input") -> None:
        """
        Mark memory region as tainted (user input).
        
        Args:
            address: Starting address
            size: Size in bytes
            source_name: Name of the taint source
        """
        if self.use_simulation:
            self.tainted_addresses.update(range(address, address + size))
            return
        
        try:
            for offset in range(size):
                mem = MemoryAccess(address + offset, CPUSIZE.BYTE)
                self.ctx.taintMemory(mem)
                self.tainted_addresses.add(address + offset)
            
            logger.debug(f"Tainted {size} bytes at {hex(address)} as {source_name}")
            
        except Exception as e:
            logger.error(f"Failed to taint memory: {e}")
    
    def taint_register(self, register_name: str) -> None:
        """
        Mark a register as tainted.
        
        Args:
            register_name: Name of the register (e.g., 'rax', 'rdi')
        """
        if self.use_simulation:
            self.tainted_registers.add(register_name)
            return
        
        try:
            reg = self.ctx.getRegister(register_name)
            self.ctx.taintRegister(reg)
            self.tainted_registers.add(register_name)
            
        except Exception as e:
            logger.error(f"Failed to taint register {register_name}: {e}")
    
    def add_sink(self, address: int, function_name: str) -> None:
        """
        Add a dangerous sink address to watch for.
        
        Args:
            address: Address of the sink function
            function_name: Name of the function
        """
        self.sink_addresses[address] = function_name
    
    def run_analysis(
        self,
        start_address: Optional[int] = None,
        max_instructions: int = 10000
    ) -> TaintResults:
        """
        Run taint analysis on the binary.
        
        Args:
            start_address: Address to start from (default: entry point)
            max_instructions: Maximum instructions to analyze
            
        Returns:
            TaintResults with findings
        """
        if self.use_simulation:
            return self._simulate_analysis()
        
        if not self.ctx:
            if not self.initialize():
                return TaintResults(
                    tainted_sinks=[],
                    taint_propagation_count=0,
                    instructions_analyzed=0,
                    tainted_memory_regions=[],
                    tainted_registers=[],
                    analysis_complete=False,
                    notes=['Failed to initialize Triton']
                )
        
        instructions_analyzed = 0
        taint_propagations = 0
        
        try:
            # Load binary
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Set up memory (simplified - real impl would parse ELF)
            base_addr = 0x400000
            self.ctx.setConcreteMemoryAreaValue(base_addr, binary_data)
            
            pc = start_address or base_addr
            
            # Analysis loop
            while instructions_analyzed < max_instructions:
                # Read and process instruction
                try:
                    opcode = self.ctx.getConcreteMemoryAreaValue(pc, 16)
                    instruction = TritonInstruction()
                    instruction.setOpcode(opcode)
                    instruction.setAddress(pc)
                    
                    if not self.ctx.processing(instruction):
                        break
                    
                    instructions_analyzed += 1
                    
                    # Check for taint propagation
                    if self._check_taint_propagation(instruction):
                        taint_propagations += 1
                    
                    # Check if we hit a sink
                    if pc in self.sink_addresses:
                        self._check_sink(pc, instruction)
                    
                    # Move to next instruction
                    pc = self.ctx.getConcreteRegisterValue(
                        self.ctx.getRegister('rip' if self.ctx.getArchitecture() == ARCH.X86_64 else 'eip')
                    )
                    
                except Exception as e:
                    logger.debug(f"Instruction processing error at {hex(pc)}: {e}")
                    break
            
        except Exception as e:
            logger.error(f"Taint analysis error: {e}")
            return TaintResults(
                tainted_sinks=self.sinks_reached,
                taint_propagation_count=taint_propagations,
                instructions_analyzed=instructions_analyzed,
                tainted_memory_regions=self._get_tainted_regions(),
                tainted_registers=list(self.tainted_registers),
                analysis_complete=False,
                notes=[f'Analysis error: {e}']
            )
        
        return TaintResults(
            tainted_sinks=self.sinks_reached,
            taint_propagation_count=taint_propagations,
            instructions_analyzed=instructions_analyzed,
            tainted_memory_regions=self._get_tainted_regions(),
            tainted_registers=list(self.tainted_registers),
            analysis_complete=True
        )
    
    def _check_taint_propagation(self, instruction) -> bool:
        """Check if instruction propagated taint."""
        
        try:
            # Check if any written register is now tainted
            for reg in instruction.getWrittenRegisters():
                if self.ctx.isRegisterTainted(reg[0]):
                    return True
            
            # Check if any written memory is now tainted
            for mem in instruction.getStoreAccess():
                if self.ctx.isMemoryTainted(mem[0]):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _check_sink(self, address: int, instruction) -> None:
        """Check if tainted data reached a dangerous sink."""
        
        func_name = self.sink_addresses.get(address, 'unknown')
        sink_info = self.DANGEROUS_SINKS.get(func_name, {})
        
        if not sink_info:
            return
        
        # Check if arguments are tainted (x86_64 calling convention)
        arg_registers = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        tainted_args = []
        
        for reg_name in arg_registers:
            try:
                reg = self.ctx.getRegister(reg_name)
                if self.ctx.isRegisterTainted(reg):
                    tainted_args.append(reg_name)
            except Exception:
                pass
        
        if tainted_args:
            sink = TaintedSink(
                sink_type=sink_info.get('type', 'unknown'),
                address=address,
                function_name=func_name,
                taint_sources=tainted_args,
                path_length=0,  # Would need path tracking
                cwe_id=sink_info.get('cwe', 'CWE-20'),
                severity=sink_info.get('severity', 'medium'),
                description=f"Tainted data from {tainted_args} reaches {func_name}"
            )
            self.sinks_reached.append(sink)
    
    def _get_tainted_regions(self) -> List[tuple]:
        """Get contiguous tainted memory regions."""
        
        if not self.tainted_addresses:
            return []
        
        sorted_addrs = sorted(self.tainted_addresses)
        regions = []
        start = sorted_addrs[0]
        end = start
        
        for addr in sorted_addrs[1:]:
            if addr == end + 1:
                end = addr
            else:
                regions.append((start, end))
                start = addr
                end = addr
        
        regions.append((start, end))
        return regions
    
    def _simulate_analysis(self) -> TaintResults:
        """Simulate taint analysis for testing."""
        
        logger.info("[Simulation] Running simulated taint analysis...")
        
        # Analyze binary for patterns
        simulated_sinks = []
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            # Look for dangerous function patterns
            for func_name, info in self.DANGEROUS_SINKS.items():
                if func_name.encode() in data:
                    sink = TaintedSink(
                        sink_type=info['type'],
                        address=0,
                        function_name=func_name,
                        taint_sources=['simulated_input'],
                        path_length=0,
                        cwe_id=info['cwe'],
                        severity=info['severity'],
                        description=f"[Simulated] {func_name} found - may receive tainted data"
                    )
                    simulated_sinks.append(sink)
                    
        except Exception as e:
            logger.debug(f"Simulation error: {e}")
        
        return TaintResults(
            tainted_sinks=simulated_sinks,
            taint_propagation_count=0,
            instructions_analyzed=0,
            tainted_memory_regions=[],
            tainted_registers=[],
            analysis_complete=True,
            notes=[
                'Simulation mode - install Triton for real taint analysis',
                f'Found {len(simulated_sinks)} potential sinks'
            ]
        )
    
    def get_tainted_sinks(self) -> List[TaintedSink]:
        """Get all tainted sinks found during analysis."""
        return self.sinks_reached
    
    def to_vulnerability_list(self) -> List[Dict[str, Any]]:
        """Convert tainted sinks to vulnerability dictionaries."""
        
        vulnerabilities = []
        
        for sink in self.sinks_reached:
            vulnerabilities.append({
                'type': sink.sink_type,
                'cwe_id': sink.cwe_id,
                'severity': sink.severity,
                'title': f'Tainted data reaches {sink.function_name}',
                'description': sink.description,
                'function': sink.function_name,
                'address': hex(sink.address) if sink.address else None,
                'taint_sources': sink.taint_sources,
                'detection_method': 'taint_analysis',
            })
        
        return vulnerabilities