"""
Crash Analyzer Module
Analyzes crashes from fuzzing to determine exploitability and root cause.
"""

import subprocess
import tempfile
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class StackFrame:
    """Represents a single stack frame."""
    index: int
    address: int
    function: str
    offset: int = 0
    source_file: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class CrashReport:
    """Detailed crash analysis report."""
    signal: str
    crash_address: Optional[str] = None
    crash_instruction: Optional[str] = None
    registers: Dict[str, str] = field(default_factory=dict)
    backtrace: List[StackFrame] = field(default_factory=list)
    exploitability: str = 'unknown'
    memory_map: List[str] = field(default_factory=list)
    raw_output: str = ""
    analysis_notes: List[str] = field(default_factory=list)


class CrashAnalyzer:
    """
    Analyze crash dumps to determine vulnerability type and exploitability.
    
    Uses GDB for detailed analysis when available, falls back to
    basic signal analysis otherwise.
    """
    
    # Signal descriptions
    SIGNALS = {
        'SIGSEGV': 'Segmentation fault (invalid memory access)',
        'SIGBUS': 'Bus error (misaligned memory access)',
        'SIGABRT': 'Abort signal (assertion failure or abort() call)',
        'SIGILL': 'Illegal instruction',
        'SIGFPE': 'Floating point exception (divide by zero)',
        'SIGTRAP': 'Trace/breakpoint trap',
        'SIGKILL': 'Kill signal',
        'SIGTERM': 'Termination signal',
    }
    
    def __init__(self):
        self.gdb_available = self._check_gdb_available()
    
    def _check_gdb_available(self) -> bool:
        """Check if GDB is available."""
        try:
            result = subprocess.run(
                ['gdb', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def analyze(
        self,
        crash_input: bytes,
        binary_path: str,
        work_dir: Optional[str] = None
    ) -> CrashReport:
        """
        Analyze a crash to determine root cause and exploitability.
        
        Args:
            crash_input: The input bytes that caused the crash
            binary_path: Path to the binary that crashed
            work_dir: Working directory for temp files
            
        Returns:
            CrashReport with analysis details
        """
        if not work_dir:
            work_dir = tempfile.gettempdir()
        
        # Write crash input to file
        input_file = Path(work_dir) / "crash_input_analyze"
        input_file.write_bytes(crash_input)
        
        if self.gdb_available:
            return self._analyze_with_gdb(input_file, binary_path)
        else:
            return self._analyze_basic(crash_input, binary_path, input_file)
    
    def _analyze_with_gdb(self, input_file: Path, binary_path: str) -> CrashReport:
        """Perform detailed crash analysis using GDB."""
        
        # Create GDB script for batch analysis
        gdb_script = """
set pagination off
set confirm off
set print thread-events off
run < {input_file}
echo \\n=== SIGNAL ===\\n
info signals
echo \\n=== REGISTERS ===\\n
info registers
echo \\n=== BACKTRACE ===\\n
backtrace full
echo \\n=== CURRENT INSTRUCTION ===\\n
x/i $pc
echo \\n=== MEMORY NEAR PC ===\\n
x/16i $pc
echo \\n=== STACK ===\\n
x/32xw $sp
quit
""".format(input_file=str(input_file))
        
        gdb_script_file = input_file.parent / "gdb_crash_script"
        gdb_script_file.write_text(gdb_script)
        
        try:
            result = subprocess.run(
                ['gdb', '-batch', '-x', str(gdb_script_file), binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            
            return self._parse_gdb_output(output)
            
        except subprocess.TimeoutExpired:
            logger.warning("GDB analysis timed out")
            return CrashReport(
                signal='UNKNOWN',
                analysis_notes=['GDB analysis timed out']
            )
        except Exception as e:
            logger.error(f"GDB analysis failed: {e}")
            return CrashReport(
                signal='UNKNOWN',
                analysis_notes=[f'GDB analysis failed: {e}']
            )
    
    def _parse_gdb_output(self, output: str) -> CrashReport:
        """Parse GDB output to extract crash details."""
        
        report = CrashReport(signal='UNKNOWN', raw_output=output[:5000])
        
        # Extract signal
        signal_patterns = [
            r'Program received signal (SIG\w+)',
            r'stopped with signal (SIG\w+)',
            r'(SIGSEGV|SIGBUS|SIGABRT|SIGILL|SIGFPE|SIGTRAP)',
        ]
        
        for pattern in signal_patterns:
            match = re.search(pattern, output)
            if match:
                report.signal = match.group(1)
                break
        
        # Extract registers
        registers_section = self._extract_section(output, '=== REGISTERS ===', '===')
        if registers_section:
            report.registers = self._parse_registers(registers_section)
        
        # Extract backtrace
        backtrace_section = self._extract_section(output, '=== BACKTRACE ===', '===')
        if backtrace_section:
            report.backtrace = self._parse_backtrace(backtrace_section)
        
        # Extract crash address and instruction
        instruction_section = self._extract_section(output, '=== CURRENT INSTRUCTION ===', '===')
        if instruction_section:
            # Parse instruction like "0x400123 <func+0x10>:  mov eax, [ebx]"
            match = re.search(r'(0x[0-9a-fA-F]+).*?:\s*(.+)', instruction_section)
            if match:
                report.crash_address = match.group(1)
                report.crash_instruction = match.group(2).strip()
        
        # Assess exploitability
        report.exploitability = self._assess_exploitability(report)
        
        return report
    
    def _extract_section(self, text: str, start_marker: str, end_marker: str) -> Optional[str]:
        """Extract a section between markers."""
        try:
            start_idx = text.find(start_marker)
            if start_idx == -1:
                return None
            
            start_idx += len(start_marker)
            end_idx = text.find(end_marker, start_idx)
            
            if end_idx == -1:
                return text[start_idx:]
            
            return text[start_idx:end_idx].strip()
        except Exception:
            return None
    
    def _parse_registers(self, section: str) -> Dict[str, str]:
        """Parse register dump from GDB output."""
        registers = {}
        
        # Match patterns like "eax            0x41414141  1094795585"
        pattern = r'(\w+)\s+(0x[0-9a-fA-F]+)'
        
        for match in re.finditer(pattern, section):
            reg_name = match.group(1)
            reg_value = match.group(2)
            registers[reg_name] = reg_value
        
        return registers
    
    def _parse_backtrace(self, section: str) -> List[StackFrame]:
        """Parse backtrace from GDB output."""
        frames = []
        
        # Match patterns like "#0  0x00400123 in func_name (args) at file.c:123"
        pattern = r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?(\S+)?'
        
        for match in re.finditer(pattern, section):
            frame = StackFrame(
                index=int(match.group(1)),
                address=int(match.group(2), 16),
                function=match.group(3) or 'unknown'
            )
            frames.append(frame)
        
        return frames
    
    def _analyze_basic(
        self,
        crash_input: bytes,
        binary_path: str,
        input_file: Path
    ) -> CrashReport:
        """Basic crash analysis without GDB."""
        
        report = CrashReport(signal='UNKNOWN')
        report.analysis_notes.append('GDB not available - basic analysis only')
        
        # Try to run the binary and capture signal
        try:
            with open(input_file, 'rb') as stdin:
                result = subprocess.run(
                    [binary_path],
                    stdin=stdin,
                    capture_output=True,
                    timeout=5
                )
                
                # Check return code
                if result.returncode < 0:
                    # Negative return code indicates signal
                    signal_num = -result.returncode
                    signal_map = {
                        11: 'SIGSEGV',
                        6: 'SIGABRT',
                        4: 'SIGILL',
                        8: 'SIGFPE',
                        7: 'SIGBUS',
                        5: 'SIGTRAP',
                    }
                    report.signal = signal_map.get(signal_num, f'SIGNAL_{signal_num}')
                    
        except subprocess.TimeoutExpired:
            report.signal = 'TIMEOUT'
            report.analysis_notes.append('Binary execution timed out')
        except Exception as e:
            report.analysis_notes.append(f'Execution failed: {e}')
        
        # Basic exploitability assessment
        report.exploitability = self._assess_exploitability(report)
        
        return report
    
    def _assess_exploitability(self, report: CrashReport) -> str:
        """
        Assess exploitability based on crash characteristics.
        
        Returns:
            'high', 'medium', 'low', or 'unknown'
        """
        score = 0
        notes = []
        
        # Signal-based scoring
        signal_scores = {
            'SIGSEGV': 2,  # Memory corruption - potentially exploitable
            'SIGBUS': 2,   # Memory alignment - potentially exploitable  
            'SIGABRT': 1,  # Abort - less exploitable but indicates issues
            'SIGILL': 1,   # Illegal instruction - code injection possible
            'SIGFPE': 0,   # Division by zero - rarely exploitable
        }
        
        score += signal_scores.get(report.signal, 0)
        
        # Check for controlled data in registers (potential RCE indicators)
        interesting_patterns = [
            '0x41414141',  # AAAA pattern
            '0x42424242',  # BBBB pattern
            '0x43434343',  # CCCC pattern
            '0x25782578',  # %x%x pattern
            '0x256e256e',  # %n%n pattern
        ]
        
        for reg_name, reg_value in report.registers.items():
            if reg_value in interesting_patterns:
                score += 2
                notes.append(f'Controlled value in {reg_name}')
        
        # Check for PC/RIP control
        pc_regs = ['pc', 'rip', 'eip']
        for reg in pc_regs:
            if reg in report.registers:
                value = report.registers[reg]
                if value in interesting_patterns:
                    score += 3
                    notes.append('Potential PC control')
                    break
        
        # Check for stack pointer corruption
        sp_regs = ['sp', 'rsp', 'esp']
        for reg in sp_regs:
            if reg in report.registers:
                value = report.registers[reg]
                if value in interesting_patterns:
                    score += 2
                    notes.append('Potential SP control')
                    break
        
        # Determine exploitability level
        if score >= 5:
            report.analysis_notes.extend(notes)
            return 'high'
        elif score >= 3:
            report.analysis_notes.extend(notes)
            return 'medium'
        elif score >= 1:
            return 'low'
        else:
            return 'unknown'
    
    def get_exploitability_description(self, level: str) -> str:
        """Get human-readable description of exploitability level."""
        descriptions = {
            'high': 'Likely exploitable - attacker-controlled values detected in critical registers',
            'medium': 'Potentially exploitable - memory corruption with some control',
            'low': 'Unlikely to be directly exploitable but indicates vulnerability',
            'unknown': 'Exploitability could not be determined',
        }
        return descriptions.get(level, 'Unknown exploitability level')
    
    def extract_stack_trace(self, gdb_output: str) -> List[StackFrame]:
        """
        Extract stack trace from GDB output.
        
        Args:
            gdb_output: Raw GDB output
            
        Returns:
            List of StackFrame objects
        """
        backtrace_section = self._extract_section(gdb_output, 'Backtrace', 'End')
        if not backtrace_section:
            backtrace_section = gdb_output
        
        return self._parse_backtrace(backtrace_section)
