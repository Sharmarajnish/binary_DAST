"""
Architecture Detector Module
Detects CPU architecture of ECU binaries for proper emulation setup.
"""

import subprocess
import struct
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class ArchInfo:
    """Architecture information for a binary."""
    name: str
    bits: int
    endianness: str
    qemu_arch: Optional[str]
    tricore_variant: Optional[str] = None
    description: str = ""


class ArchitectureDetector:
    """
    Detect CPU architecture of binary files.
    
    Supports automotive-common architectures:
    - ARM (32-bit, Thumb, AArch64)
    - PowerPC (common in older ECUs)
    - TriCore (Infineon automotive MCUs)
    - Renesas (RH850, V850)
    - RISC-V (emerging)
    - x86/x64 (simulation/testing)
    """
    
    # ELF e_machine values
    ELF_MACHINES: Dict[int, Tuple[str, str]] = {
        0x03: ('x86', 'i386'),
        0x3E: ('x86_64', 'x86_64'),
        0x28: ('arm', 'arm'),
        0xB7: ('aarch64', 'aarch64'),
        0x14: ('powerpc', 'ppc'),
        0x15: ('powerpc64', 'ppc64'),
        0xF3: ('riscv', 'riscv64'),
        0x2C: ('tricore', None),  # TriCore - no QEMU support
        0x24: ('v850', None),     # Renesas V850
    }
    
    # QEMU user-mode binary names
    QEMU_BINARIES = {
        'arm': 'qemu-arm',
        'aarch64': 'qemu-aarch64',
        'ppc': 'qemu-ppc',
        'ppc64': 'qemu-ppc64',
        'riscv64': 'qemu-riscv64',
        'riscv32': 'qemu-riscv32',
        'i386': 'qemu-i386',
        'x86_64': 'qemu-x86_64',
    }
    
    def __init__(self):
        self._file_command_available = self._check_file_command()
    
    def _check_file_command(self) -> bool:
        """Check if 'file' command is available."""
        try:
            subprocess.run(['file', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            return False
    
    def detect(self, binary_path: str) -> ArchInfo:
        """
        Detect architecture of a binary file.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            ArchInfo with architecture details
        """
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        # Try ELF detection first
        elf_info = self._detect_from_elf(binary_path)
        if elf_info:
            return elf_info
        
        # Fallback to file command
        if self._file_command_available:
            file_info = self._detect_from_file_command(binary_path)
            if file_info:
                return file_info
        
        # Pattern-based detection as last resort
        return self._detect_from_patterns(binary_path)
    
    def _detect_from_elf(self, binary_path: str) -> Optional[ArchInfo]:
        """Detect architecture from ELF header."""
        
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(64)
            
            # Check ELF magic
            if header[:4] != b'\x7fELF':
                return None
            
            # Parse ELF header
            ei_class = header[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = header[5]   # 1 = little, 2 = big
            
            # Get e_machine
            if ei_data == 1:  # Little endian
                e_machine = struct.unpack('<H', header[18:20])[0]
            else:  # Big endian
                e_machine = struct.unpack('>H', header[18:20])[0]
            
            bits = 32 if ei_class == 1 else 64
            endianness = 'little' if ei_data == 1 else 'big'
            
            if e_machine in self.ELF_MACHINES:
                name, qemu_arch = self.ELF_MACHINES[e_machine]
                
                # Special handling for TriCore
                if name == 'tricore':
                    return ArchInfo(
                        name='tricore',
                        bits=32,
                        endianness='little',
                        qemu_arch=None,
                        tricore_variant=self._detect_tricore_variant(binary_path),
                        description='Infineon TriCore (automotive MCU)'
                    )
                
                return ArchInfo(
                    name=name,
                    bits=bits,
                    endianness=endianness,
                    qemu_arch=qemu_arch,
                    description=f'{name.upper()} {bits}-bit {endianness}-endian'
                )
            
            return ArchInfo(
                name=f'unknown_0x{e_machine:04x}',
                bits=bits,
                endianness=endianness,
                qemu_arch=None,
                description=f'Unknown architecture (e_machine=0x{e_machine:04x})'
            )
            
        except Exception as e:
            logger.debug(f"ELF detection failed: {e}")
            return None
    
    def _detect_from_file_command(self, binary_path: str) -> Optional[ArchInfo]:
        """Detect architecture using 'file' command."""
        
        try:
            result = subprocess.run(
                ['file', binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout.lower()
            
            # Parse file command output
            arch_patterns = [
                ('aarch64', 'aarch64', 64, 'little'),
                ('arm', 'arm', 32, 'little'),
                ('arm64', 'aarch64', 64, 'little'),
                ('powerpc64', 'ppc64', 64, 'big'),
                ('powerpc', 'ppc', 32, 'big'),
                ('ppc64', 'ppc64', 64, 'big'),
                ('ppc', 'ppc', 32, 'big'),
                ('x86-64', 'x86_64', 64, 'little'),
                ('x86_64', 'x86_64', 64, 'little'),
                ('i386', 'i386', 32, 'little'),
                ('i686', 'i386', 32, 'little'),
                ('riscv', 'riscv64', 64, 'little'),
                ('tricore', None, 32, 'little'),
            ]
            
            for pattern, qemu, bits, endian in arch_patterns:
                if pattern in output:
                    # Check endianness override
                    if 'big endian' in output or 'msb' in output:
                        endian = 'big'
                    elif 'little endian' in output or 'lsb' in output:
                        endian = 'little'
                    
                    # Check bits override
                    if '64-bit' in output:
                        bits = 64
                    elif '32-bit' in output:
                        bits = 32
                    
                    return ArchInfo(
                        name=pattern.replace('-', '_'),
                        bits=bits,
                        endianness=endian,
                        qemu_arch=qemu,
                        description=result.stdout.strip()
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"File command detection failed: {e}")
            return None
    
    def _detect_from_patterns(self, binary_path: str) -> ArchInfo:
        """Detect architecture from instruction patterns (heuristic)."""
        
        with open(binary_path, 'rb') as f:
            data = f.read(4096)  # Read first 4KB
        
        # ARM detection (common instruction patterns)
        arm_patterns = [
            b'\xe5\x9f',  # LDR instruction
            b'\xe3\xa0',  # MOV instruction
            b'\xe9\x2d',  # PUSH instruction
        ]
        
        arm_count = sum(1 for p in arm_patterns if p in data)
        if arm_count >= 2:
            return ArchInfo(
                name='arm',
                bits=32,
                endianness='little',
                qemu_arch='arm',
                description='ARM (detected from instruction patterns)'
            )
        
        # PowerPC detection
        ppc_patterns = [
            b'\x94\x21',  # stwu
            b'\x7c\x08',  # mflr
        ]
        
        ppc_count = sum(1 for p in ppc_patterns if p in data)
        if ppc_count >= 2:
            return ArchInfo(
                name='powerpc',
                bits=32,
                endianness='big',
                qemu_arch='ppc',
                description='PowerPC (detected from instruction patterns)'
            )
        
        # Default to unknown
        return ArchInfo(
            name='unknown',
            bits=32,
            endianness='little',
            qemu_arch=None,
            description='Unknown architecture'
        )
    
    def _detect_tricore_variant(self, binary_path: str) -> str:
        """Detect specific TriCore variant."""
        # TriCore variants: TC1.3, TC1.6, TC1.6.2, TC1.8
        # This would require deeper analysis of instruction set usage
        return 'tc1.6'  # Default to common variant
    
    def get_qemu_mode(self, arch: str) -> Optional[str]:
        """
        Get the QEMU binary name for an architecture.
        
        Args:
            arch: Architecture name
            
        Returns:
            QEMU binary name or None if not supported
        """
        return self.QEMU_BINARIES.get(arch)
    
    def get_endianness(self, binary_path: str) -> str:
        """
        Get endianness of a binary.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            'little' or 'big'
        """
        arch_info = self.detect(binary_path)
        return arch_info.endianness
    
    def is_supported_for_fuzzing(self, binary_path: str) -> Tuple[bool, str]:
        """
        Check if a binary can be fuzzed with QEMU.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            Tuple of (supported, reason)
        """
        arch_info = self.detect(binary_path)
        
        if arch_info.qemu_arch:
            return True, f"Supported via QEMU ({arch_info.qemu_arch})"
        
        if arch_info.name == 'tricore':
            return False, "TriCore requires specialized emulator (not QEMU)"
        
        if arch_info.name == 'v850':
            return False, "V850/RH850 requires specialized emulator"
        
        return False, f"Architecture {arch_info.name} not supported for fuzzing"
    
    def get_angr_arch(self, binary_path: str) -> str:
        """
        Get angr-compatible architecture string.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            angr architecture string
        """
        arch_info = self.detect(binary_path)
        
        angr_map = {
            'arm': 'ARM',
            'aarch64': 'AARCH64',
            'x86': 'X86',
            'x86_64': 'AMD64',
            'powerpc': 'PPC32',
            'powerpc64': 'PPC64',
            'riscv': 'RISCV',
        }
        
        return angr_map.get(arch_info.name, arch_info.name.upper())
