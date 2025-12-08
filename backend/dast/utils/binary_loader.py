"""
Binary Loader Module
Supports multiple binary formats common in automotive ECUs.
"""

import os
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class Section:
    """Represents a binary section."""
    name: str
    address: int
    size: int
    data: bytes
    flags: Dict[str, bool] = field(default_factory=dict)


@dataclass
class BinaryInfo:
    """Information about a loaded binary."""
    path: str
    format: str
    architecture: str
    endianness: str
    entry_point: int
    sections: List[Section]
    raw_data: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)


class BinaryLoader:
    """
    Loader for various binary formats common in automotive ECUs.
    
    Supported formats:
    - ELF (Executable and Linkable Format)
    - Intel HEX
    - Motorola S-Record (SREC)
    - Raw binary
    """
    
    # ELF Magic bytes
    ELF_MAGIC = b'\x7fELF'
    
    # Intel HEX record types
    IHEX_DATA = 0x00
    IHEX_EOF = 0x01
    IHEX_EXT_SEG_ADDR = 0x02
    IHEX_START_SEG_ADDR = 0x03
    IHEX_EXT_LINEAR_ADDR = 0x04
    IHEX_START_LINEAR_ADDR = 0x05
    
    def __init__(self):
        self.supported_formats = ['elf', 'ihex', 'srec', 'raw']
    
    def load(self, path: str) -> BinaryInfo:
        """
        Load a binary file and return structured information.
        
        Args:
            path: Path to binary file
            
        Returns:
            BinaryInfo with parsed binary data
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Binary file not found: {path}")
        
        format_type = self.detect_format(path)
        logger.info(f"Detected format: {format_type} for {path}")
        
        if format_type == 'elf':
            return self._load_elf(path)
        elif format_type == 'ihex':
            return self._load_intel_hex(path)
        elif format_type == 'srec':
            return self._load_srec(path)
        else:
            return self._load_raw(path)
    
    def detect_format(self, path: str) -> str:
        """
        Detect the format of a binary file.
        
        Args:
            path: Path to binary file
            
        Returns:
            Format type string
        """
        with open(path, 'rb') as f:
            header = f.read(16)
        
        # Check for ELF
        if header[:4] == self.ELF_MAGIC:
            return 'elf'
        
        # Check for Intel HEX (starts with ':')
        try:
            with open(path, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith(':'):
                    return 'ihex'
                # Check for SREC (starts with 'S')
                if first_line.startswith('S'):
                    return 'srec'
        except UnicodeDecodeError:
            pass
        
        return 'raw'
    
    def _load_elf(self, path: str) -> BinaryInfo:
        """Load an ELF binary."""
        
        with open(path, 'rb') as f:
            data = f.read()
        
        # Parse ELF header
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = little endian, 2 = big endian
        ei_machine = struct.unpack('<H' if ei_data == 1 else '>H', data[18:20])[0]
        
        # Determine architecture
        arch_map = {
            0x03: 'x86',
            0x3E: 'x86_64',
            0x28: 'arm',
            0xB7: 'aarch64',
            0x14: 'powerpc',
            0x15: 'powerpc64',
            0xF3: 'riscv',
        }
        architecture = arch_map.get(ei_machine, f'unknown_{ei_machine:02x}')
        
        endianness = 'little' if ei_data == 1 else 'big'
        
        # Parse entry point
        if ei_class == 1:  # 32-bit
            fmt = '<I' if endianness == 'little' else '>I'
            entry_point = struct.unpack(fmt, data[24:28])[0]
        else:  # 64-bit
            fmt = '<Q' if endianness == 'little' else '>Q'
            entry_point = struct.unpack(fmt, data[24:32])[0]
        
        # Extract sections (simplified - would need full ELF parsing for complete impl)
        sections = self._parse_elf_sections(data, ei_class, endianness)
        
        return BinaryInfo(
            path=path,
            format='elf',
            architecture=architecture,
            endianness=endianness,
            entry_point=entry_point,
            sections=sections,
            raw_data=data,
            metadata={
                'class': '32-bit' if ei_class == 1 else '64-bit',
                'machine': ei_machine,
            }
        )
    
    def _parse_elf_sections(self, data: bytes, ei_class: int, endianness: str) -> List[Section]:
        """Parse ELF section headers."""
        sections = []
        
        # Simplified section parsing
        # In a full implementation, would parse section header table
        
        # For now, create a single section with all data
        sections.append(Section(
            name='.text',
            address=0,
            size=len(data),
            data=data,
            flags={'executable': True, 'readable': True, 'writable': False}
        ))
        
        return sections
    
    def _load_intel_hex(self, path: str) -> BinaryInfo:
        """Load an Intel HEX file."""
        
        data_records: Dict[int, bytes] = {}
        entry_point = 0
        base_address = 0
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith(':'):
                    continue
                
                # Parse record
                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data_hex = line[9:9 + byte_count * 2]
                
                if record_type == self.IHEX_DATA:
                    full_address = base_address + address
                    data_records[full_address] = bytes.fromhex(data_hex)
                elif record_type == self.IHEX_EXT_LINEAR_ADDR:
                    base_address = int(data_hex, 16) << 16
                elif record_type == self.IHEX_START_LINEAR_ADDR:
                    entry_point = int(data_hex, 16)
                elif record_type == self.IHEX_EOF:
                    break
        
        # Combine data records
        if data_records:
            min_addr = min(data_records.keys())
            max_addr = max(k + len(v) for k, v in data_records.items())
            raw_data = bytearray(max_addr - min_addr)
            
            for addr, data in data_records.items():
                offset = addr - min_addr
                raw_data[offset:offset + len(data)] = data
            
            raw_data = bytes(raw_data)
        else:
            raw_data = b''
            min_addr = 0
        
        return BinaryInfo(
            path=path,
            format='ihex',
            architecture='unknown',  # Need separate detection
            endianness='little',
            entry_point=entry_point,
            sections=[Section(
                name='.data',
                address=min_addr,
                size=len(raw_data),
                data=raw_data,
                flags={}
            )],
            raw_data=raw_data,
            metadata={'base_address': min_addr}
        )
    
    def _load_srec(self, path: str) -> BinaryInfo:
        """Load a Motorola S-Record file."""
        
        data_records: Dict[int, bytes] = {}
        entry_point = 0
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('S'):
                    continue
                
                record_type = line[1]
                byte_count = int(line[2:4], 16)
                
                if record_type == '1':  # 16-bit address data
                    address = int(line[4:8], 16)
                    data_hex = line[8:8 + (byte_count - 3) * 2]
                    data_records[address] = bytes.fromhex(data_hex)
                elif record_type == '2':  # 24-bit address data
                    address = int(line[4:10], 16)
                    data_hex = line[10:10 + (byte_count - 4) * 2]
                    data_records[address] = bytes.fromhex(data_hex)
                elif record_type == '3':  # 32-bit address data
                    address = int(line[4:12], 16)
                    data_hex = line[12:12 + (byte_count - 5) * 2]
                    data_records[address] = bytes.fromhex(data_hex)
                elif record_type == '7':  # 32-bit start address
                    entry_point = int(line[4:12], 16)
                elif record_type == '8':  # 24-bit start address
                    entry_point = int(line[4:10], 16)
                elif record_type == '9':  # 16-bit start address
                    entry_point = int(line[4:8], 16)
        
        # Combine data records
        if data_records:
            min_addr = min(data_records.keys())
            max_addr = max(k + len(v) for k, v in data_records.items())
            raw_data = bytearray(max_addr - min_addr)
            
            for addr, data in data_records.items():
                offset = addr - min_addr
                raw_data[offset:offset + len(data)] = data
            
            raw_data = bytes(raw_data)
        else:
            raw_data = b''
            min_addr = 0
        
        return BinaryInfo(
            path=path,
            format='srec',
            architecture='unknown',
            endianness='big',  # SREC typically big-endian
            entry_point=entry_point,
            sections=[Section(
                name='.data',
                address=min_addr,
                size=len(raw_data),
                data=raw_data,
                flags={}
            )],
            raw_data=raw_data,
            metadata={'base_address': min_addr}
        )
    
    def _load_raw(self, path: str) -> BinaryInfo:
        """Load a raw binary file."""
        
        with open(path, 'rb') as f:
            data = f.read()
        
        return BinaryInfo(
            path=path,
            format='raw',
            architecture='unknown',
            endianness='little',
            entry_point=0,
            sections=[Section(
                name='.raw',
                address=0,
                size=len(data),
                data=data,
                flags={}
            )],
            raw_data=data,
            metadata={}
        )
    
    def extract_sections(self, path: str) -> List[Section]:
        """
        Extract sections from a binary file.
        
        Args:
            path: Path to binary file
            
        Returns:
            List of Section objects
        """
        binary_info = self.load(path)
        return binary_info.sections
