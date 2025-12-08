"""
Symbol File Handler for Enhanced DAST Analysis
Supports .elf DWARF debug info, .pdb (Windows), and map files.
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import re

logger = logging.getLogger(__name__)


@dataclass
class SymbolInfo:
    """Information about a symbol."""
    name: str
    address: int
    size: int
    type: str  # 'function', 'variable', 'object'
    source_file: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class DebugInfo:
    """Debug information extracted from symbol file."""
    source: str  # 'dwarf', 'pdb', 'map', 'nm'
    functions: Dict[int, SymbolInfo] = field(default_factory=dict)
    variables: Dict[int, SymbolInfo] = field(default_factory=dict)
    source_files: List[str] = field(default_factory=list)
    address_to_line: Dict[int, tuple] = field(default_factory=dict)  # addr -> (file, line)


class SymbolFileHandler:
    """
    Handler for symbol/debug files to improve DAST accuracy.
    
    Supports:
    - ELF with DWARF debug info
    - Separate .debug files
    - Windows .pdb files (via cv2pdb or similar)
    - Linker map files
    - nm symbol tables
    
    Benefits:
    - Maps crash addresses to function names and source lines
    - Provides accurate remediation guidance
    - Improves vulnerability deduplication
    """
    
    def __init__(self):
        self.debug_info: Optional[DebugInfo] = None
        self._addr2line_available = self._check_tool('addr2line')
        self._nm_available = self._check_tool('nm')
        self._objdump_available = self._check_tool('objdump')
    
    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            subprocess.run([tool, '--version'], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def load_symbol_file(self, path: str) -> DebugInfo:
        """
        Load and parse a symbol file.
        
        Args:
            path: Path to symbol file (.elf, .debug, .pdb, .map)
            
        Returns:
            DebugInfo with extracted symbols
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Symbol file not found: {path}")
        
        suffix = path.suffix.lower()
        
        if suffix in ['.elf', '.debug', '.o', '.so', '.a', '']:
            # ELF with DWARF
            self.debug_info = self._parse_elf_symbols(str(path))
        elif suffix == '.pdb':
            # Windows PDB
            self.debug_info = self._parse_pdb_symbols(str(path))
        elif suffix == '.map':
            # Linker map file
            self.debug_info = self._parse_map_file(str(path))
        else:
            # Try nm as fallback
            self.debug_info = self._parse_nm_symbols(str(path))
        
        logger.info(f"Loaded {len(self.debug_info.functions)} functions, "
                   f"{len(self.debug_info.variables)} variables")
        
        return self.debug_info
    
    def _parse_elf_symbols(self, path: str) -> DebugInfo:
        """Parse ELF file with DWARF debug info."""
        
        debug_info = DebugInfo(source='dwarf')
        
        # Use nm to get symbols
        if self._nm_available:
            try:
                result = subprocess.run(
                    ['nm', '-C', '-l', path],  # -C demangles, -l shows line numbers
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            addr = int(parts[0], 16)
                            sym_type = parts[1]
                            name = parts[2]
                            
                            # Parse source location if present
                            source_file = None
                            line_num = None
                            if len(parts) > 3:
                                loc = parts[-1]
                                if ':' in loc:
                                    source_file, line_str = loc.rsplit(':', 1)
                                    try:
                                        line_num = int(line_str)
                                    except ValueError:
                                        pass
                            
                            symbol = SymbolInfo(
                                name=name,
                                address=addr,
                                size=0,
                                type='function' if sym_type.upper() == 'T' else 'variable',
                                source_file=source_file,
                                line_number=line_num
                            )
                            
                            if sym_type.upper() in ['T', 'W']:  # Text/Weak (functions)
                                debug_info.functions[addr] = symbol
                            else:
                                debug_info.variables[addr] = symbol
                                
                        except (ValueError, IndexError):
                            continue
                            
            except Exception as e:
                logger.warning(f"nm parsing failed: {e}")
        
        # Use objdump for additional info
        if self._objdump_available:
            try:
                result = subprocess.run(
                    ['objdump', '-t', path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                for line in result.stdout.splitlines():
                    # Parse objdump symbol table format
                    match = re.match(r'^([0-9a-fA-F]+)\s+.+\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)', line)
                    if match:
                        addr = int(match.group(1), 16)
                        size = int(match.group(3), 16)
                        name = match.group(4)
                        
                        if addr in debug_info.functions:
                            debug_info.functions[addr].size = size
                            
            except Exception as e:
                logger.warning(f"objdump parsing failed: {e}")
        
        return debug_info
    
    def _parse_pdb_symbols(self, path: str) -> DebugInfo:
        """Parse Windows PDB file (placeholder - needs Windows tools)."""
        
        debug_info = DebugInfo(source='pdb')
        
        # PDB parsing typically requires Windows SDK or specialized tools
        # For cross-platform, we'd use llvm-pdbutil or similar
        
        logger.warning("PDB parsing requires Windows tools - using fallback")
        
        return debug_info
    
    def _parse_map_file(self, path: str) -> DebugInfo:
        """Parse linker map file."""
        
        debug_info = DebugInfo(source='map')
        
        try:
            with open(path, 'r') as f:
                content = f.read()
            
            # Common map file patterns
            # Format: ADDRESS SIZE SECTION NAME
            patterns = [
                # GCC/LD map format
                r'^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)',
                # ARM/Keil map format
                r'^\s*(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)',
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    try:
                        groups = match.groups()
                        addr = int(groups[0], 16) if groups[0].startswith('0x') else int(groups[1], 16)
                        size = int(groups[1], 16) if groups[1].startswith('0x') else int(groups[2], 16)
                        name = groups[-1]
                        
                        symbol = SymbolInfo(
                            name=name,
                            address=addr,
                            size=size,
                            type='function'
                        )
                        debug_info.functions[addr] = symbol
                        
                    except (ValueError, IndexError):
                        continue
                        
        except Exception as e:
            logger.error(f"Map file parsing failed: {e}")
        
        return debug_info
    
    def _parse_nm_symbols(self, path: str) -> DebugInfo:
        """Fallback: use nm to extract basic symbols."""
        return self._parse_elf_symbols(path)
    
    def resolve_address(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Resolve an address to function name and source location.
        
        Args:
            address: Memory address to resolve
            
        Returns:
            Dict with name, file, line, offset
        """
        if not self.debug_info:
            return None
        
        # Find the function containing this address
        for func_addr, func in sorted(self.debug_info.functions.items(), reverse=True):
            if func_addr <= address:
                if func.size == 0 or address < func_addr + func.size:
                    offset = address - func_addr
                    return {
                        'name': func.name,
                        'address': hex(func_addr),
                        'offset': offset,
                        'source_file': func.source_file,
                        'line_number': func.line_number,
                        'resolved': True
                    }
        
        return {
            'name': f'unknown_{hex(address)}',
            'address': hex(address),
            'resolved': False
        }
    
    def addr2line(self, binary_path: str, address: int) -> Optional[Dict[str, Any]]:
        """
        Use addr2line for precise source location.
        
        Args:
            binary_path: Path to binary with debug info
            address: Address to resolve
            
        Returns:
            Dict with file and line
        """
        if not self._addr2line_available:
            return self.resolve_address(address)
        
        try:
            result = subprocess.run(
                ['addr2line', '-f', '-C', '-e', binary_path, hex(address)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                func_name = lines[0]
                location = lines[1]
                
                file_path = None
                line_num = None
                
                if ':' in location and location != '??:0':
                    parts = location.rsplit(':', 1)
                    file_path = parts[0]
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        pass
                
                return {
                    'name': func_name if func_name != '??' else None,
                    'source_file': file_path,
                    'line_number': line_num,
                    'address': hex(address),
                    'resolved': func_name != '??'
                }
                
        except Exception as e:
            logger.warning(f"addr2line failed: {e}")
        
        return self.resolve_address(address)
    
    def enhance_vulnerability(
        self,
        vuln: Dict[str, Any],
        binary_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enhance vulnerability with symbol information.
        
        Args:
            vuln: Vulnerability dictionary
            binary_path: Path to binary (for addr2line)
            
        Returns:
            Enhanced vulnerability with source info
        """
        enhanced = vuln.copy()
        
        # Extract address from vulnerability
        address_str = vuln.get('address') or vuln.get('location', '')
        
        try:
            # Parse address (handle formats like "0x080484b6" or "0x080484b6 (function)")
            match = re.search(r'0x([0-9a-fA-F]+)', str(address_str))
            if match:
                address = int(match.group(1), 16)
                
                # Resolve using addr2line if binary available
                if binary_path and self._addr2line_available:
                    resolved = self.addr2line(binary_path, address)
                else:
                    resolved = self.resolve_address(address)
                
                if resolved and resolved.get('resolved'):
                    enhanced['function_name'] = resolved.get('name')
                    enhanced['source_file'] = resolved.get('source_file')
                    enhanced['line_number'] = resolved.get('line_number')
                    
                    # Improve remediation with source context
                    if resolved.get('source_file') and resolved.get('line_number'):
                        enhanced['remediation_location'] = (
                            f"{resolved['source_file']}:{resolved['line_number']}"
                        )
                    
        except Exception as e:
            logger.debug(f"Address resolution failed: {e}")
        
        return enhanced
    
    def get_function_list(self) -> List[str]:
        """Get list of function names."""
        if not self.debug_info:
            return []
        return [f.name for f in self.debug_info.functions.values()]
    
    def export_symbols(self, output_path: str) -> None:
        """Export symbols to JSON."""
        if not self.debug_info:
            return
        
        data = {
            'source': self.debug_info.source,
            'functions': {
                hex(addr): {
                    'name': s.name,
                    'size': s.size,
                    'source_file': s.source_file,
                    'line_number': s.line_number
                }
                for addr, s in self.debug_info.functions.items()
            },
            'variables': {
                hex(addr): {'name': s.name, 'size': s.size}
                for addr, s in self.debug_info.variables.items()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
