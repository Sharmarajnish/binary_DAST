"""
Automotive File Format Loaders
Supports VBF, AUTOSAR ARXML, and ANSI C source analysis.

Implements JLR 3.1.2 format requirements:
- VBF (Volvo Binary Format)
- ANSI C source files
- AUTOSAR ARXML configuration
- Additional: .bin, .hex, .s19
"""

import os
import re
import json
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class VBFHeader:
    """VBF file header information."""
    sw_part_number: str = ''
    sw_version: str = ''
    sw_signature_dev: str = ''
    ecu_address: int = 0
    frame_format: str = 'CAN_STANDARD'
    data_format_identifier: int = 0
    call_type: str = ''
    file_checksum: int = 0


@dataclass
class VBFBlock:
    """VBF data block."""
    start_address: int
    length: int
    data: bytes
    checksum: int


@dataclass
class VBFFile:
    """Parsed VBF file."""
    path: str
    header: VBFHeader
    blocks: List[VBFBlock]
    raw_data: bytes
    
    @property
    def total_size(self) -> int:
        return sum(b.length for b in self.blocks)


class VBFLoader:
    """
    Volvo Binary Format (VBF) loader.
    
    VBF is used by Volvo, JLR, and other OEMs for ECU flashing.
    Format: ASCII header + binary data blocks
    """
    
    def __init__(self):
        self.header_pattern = re.compile(
            r'^\s*(\w+)\s*=\s*"?([^";]+)"?\s*;',
            re.MULTILINE
        )
    
    def load(self, path: str) -> VBFFile:
        """
        Load and parse a VBF file.
        
        Args:
            path: Path to VBF file
            
        Returns:
            Parsed VBFFile object
        """
        with open(path, 'rb') as f:
            raw_data = f.read()
        
        # Find header end (ASCII section before binary data)
        header_end = self._find_header_end(raw_data)
        header_text = raw_data[:header_end].decode('ascii', errors='ignore')
        
        # Parse header
        header = self._parse_header(header_text)
        
        # Parse data blocks
        blocks = self._parse_blocks(raw_data[header_end:])
        
        logger.info(f"Loaded VBF: {header.sw_part_number} v{header.sw_version}, "
                   f"{len(blocks)} blocks, {sum(b.length for b in blocks)} bytes")
        
        return VBFFile(
            path=path,
            header=header,
            blocks=blocks,
            raw_data=raw_data
        )
    
    def _find_header_end(self, data: bytes) -> int:
        """Find where ASCII header ends and binary data begins."""
        
        # VBF header ends with "}" for the header section
        # Look for pattern like "}\n" followed by non-ASCII data
        markers = [b'}\n\n', b'}\r\n\r\n', b'}\ndata', b'}\r\ndata']
        
        for marker in markers:
            pos = data.find(marker)
            if pos != -1:
                return pos + len(marker)
        
        # Fallback: find first non-printable character after reasonable header size
        for i in range(min(4096, len(data))):
            if data[i] > 127 and data[i] not in [0x0a, 0x0d]:
                return i
        
        return min(4096, len(data))
    
    def _parse_header(self, header_text: str) -> VBFHeader:
        """Parse VBF ASCII header."""
        
        header = VBFHeader()
        
        # Extract key-value pairs
        matches = self.header_pattern.findall(header_text)
        header_dict = {k.lower(): v.strip() for k, v in matches}
        
        header.sw_part_number = header_dict.get('sw_part_number', '')
        header.sw_version = header_dict.get('sw_version', '')
        header.sw_signature_dev = header_dict.get('sw_signature_dev', '')
        
        # Parse ECU address
        ecu_addr = header_dict.get('ecu_address', '0')
        try:
            header.ecu_address = int(ecu_addr, 16) if ecu_addr.startswith('0x') else int(ecu_addr)
        except ValueError:
            header.ecu_address = 0
        
        header.frame_format = header_dict.get('frame_format', 'CAN_STANDARD')
        header.call_type = header_dict.get('call', '')
        
        return header
    
    def _parse_blocks(self, data: bytes) -> List[VBFBlock]:
        """Parse VBF binary data blocks."""
        
        blocks = []
        offset = 0
        
        while offset < len(data) - 8:
            try:
                # VBF block format: start_addr (4 bytes) + length (4 bytes) + data + checksum (2 bytes)
                start_addr = int.from_bytes(data[offset:offset+4], 'big')
                length = int.from_bytes(data[offset+4:offset+8], 'big')
                
                if length == 0 or length > 0x100000:  # Sanity check
                    break
                
                block_data = data[offset+8:offset+8+length]
                
                if len(block_data) < length:
                    break
                
                # Checksum (CRC16)
                checksum = int.from_bytes(data[offset+8+length:offset+10+length], 'big')
                
                blocks.append(VBFBlock(
                    start_address=start_addr,
                    length=length,
                    data=block_data,
                    checksum=checksum
                ))
                
                offset += 10 + length
                
            except Exception as e:
                logger.debug(f"Block parsing stopped: {e}")
                break
        
        return blocks
    
    def extract_binary(self, vbf: VBFFile) -> bytes:
        """Extract combined binary data from VBF."""
        
        if not vbf.blocks:
            return b''
        
        # Combine all blocks
        min_addr = min(b.start_address for b in vbf.blocks)
        max_addr = max(b.start_address + b.length for b in vbf.blocks)
        
        result = bytearray(max_addr - min_addr)
        
        for block in vbf.blocks:
            offset = block.start_address - min_addr
            result[offset:offset + len(block.data)] = block.data
        
        return bytes(result)


@dataclass
class AUTOSARComponent:
    """AUTOSAR software component."""
    short_name: str
    category: str
    uuid: str
    ports: List[Dict[str, str]]
    runnables: List[Dict[str, str]]


@dataclass
class AUTOSARConfig:
    """Parsed AUTOSAR configuration."""
    path: str
    ar_packages: List[str]
    components: List[AUTOSARComponent]
    ecu_instances: List[str]
    communication_configs: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class AUTOSARLoader:
    """
    AUTOSAR ARXML Configuration Loader.
    
    Parses AUTOSAR XML configuration files for:
    - Software component definitions
    - ECU configurations
    - Communication settings (CAN, LIN, FlexRay)
    - Run-time environment data
    """
    
    # AUTOSAR namespaces
    AR_NS_4 = {'ar': 'http://autosar.org/schema/r4.0'}
    AR_NS_3 = {'ar': 'http://autosar.org/3.0.0'}
    
    def __init__(self):
        self.ns = self.AR_NS_4  # Default to R4.0
    
    def load(self, path: str) -> AUTOSARConfig:
        """
        Load and parse an ARXML file.
        
        Args:
            path: Path to .arxml file
            
        Returns:
            Parsed AUTOSARConfig object
        """
        tree = ET.parse(path)
        root = tree.getroot()
        
        # Detect namespace version
        self._detect_namespace(root)
        
        # Extract packages
        packages = self._extract_packages(root)
        
        # Extract components
        components = self._extract_components(root)
        
        # Extract ECU instances
        ecu_instances = self._extract_ecu_instances(root)
        
        # Extract communication configs
        comm_configs = self._extract_communication(root)
        
        logger.info(f"Loaded ARXML: {len(packages)} packages, "
                   f"{len(components)} components, {len(ecu_instances)} ECUs")
        
        return AUTOSARConfig(
            path=path,
            ar_packages=packages,
            components=components,
            ecu_instances=ecu_instances,
            communication_configs=comm_configs,
            metadata={'namespace': self.ns.get('ar', 'unknown')}
        )
    
    def _detect_namespace(self, root: ET.Element) -> None:
        """Detect AUTOSAR namespace version."""
        
        tag = root.tag
        if 'r4.0' in tag:
            self.ns = self.AR_NS_4
        elif '3.0' in tag or '3.1' in tag or '3.2' in tag:
            self.ns = self.AR_NS_3
    
    def _extract_packages(self, root: ET.Element) -> List[str]:
        """Extract AR-PACKAGE names."""
        
        packages = []
        
        for pkg in root.iter():
            if 'AR-PACKAGE' in pkg.tag:
                short_name = pkg.find('.//{*}SHORT-NAME')
                if short_name is not None and short_name.text:
                    packages.append(short_name.text)
        
        return packages
    
    def _extract_components(self, root: ET.Element) -> List[AUTOSARComponent]:
        """Extract software component definitions."""
        
        components = []
        
        # Find SWC types
        for elem in root.iter():
            if any(x in elem.tag for x in ['APPLICATION-SW-COMPONENT-TYPE', 'SERVICE-SW-COMPONENT-TYPE']):
                short_name = elem.find('.//{*}SHORT-NAME')
                category = elem.find('.//{*}CATEGORY')
                admin_data = elem.find('.//{*}ADMIN-DATA')
                
                # Extract ports
                ports = []
                for port in elem.iter():
                    if 'PORT' in port.tag and 'PROTOTYPE' in port.tag:
                        port_name = port.find('.//{*}SHORT-NAME')
                        if port_name is not None:
                            ports.append({
                                'name': port_name.text,
                                'direction': 'provided' if 'P-PORT' in port.tag else 'required'
                            })
                
                # Extract runnables
                runnables = []
                for runnable in elem.iter():
                    if 'RUNNABLE-ENTITY' in runnable.tag:
                        run_name = runnable.find('.//{*}SHORT-NAME')
                        symbol = runnable.find('.//{*}SYMBOL')
                        if run_name is not None:
                            runnables.append({
                                'name': run_name.text,
                                'symbol': symbol.text if symbol is not None else ''
                            })
                
                components.append(AUTOSARComponent(
                    short_name=short_name.text if short_name is not None else '',
                    category=category.text if category is not None else '',
                    uuid='',
                    ports=ports,
                    runnables=runnables
                ))
        
        return components
    
    def _extract_ecu_instances(self, root: ET.Element) -> List[str]:
        """Extract ECU instance names."""
        
        ecus = []
        
        for elem in root.iter():
            if 'ECU-INSTANCE' in elem.tag:
                short_name = elem.find('.//{*}SHORT-NAME')
                if short_name is not None and short_name.text:
                    ecus.append(short_name.text)
        
        return ecus
    
    def _extract_communication(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract communication configuration."""
        
        configs = []
        
        # CAN clusters
        for elem in root.iter():
            if 'CAN-CLUSTER' in elem.tag:
                name = elem.find('.//{*}SHORT-NAME')
                baudrate = elem.find('.//{*}BAUDRATE')
                
                configs.append({
                    'type': 'CAN',
                    'name': name.text if name is not None else '',
                    'baudrate': baudrate.text if baudrate is not None else ''
                })
        
        # LIN clusters
        for elem in root.iter():
            if 'LIN-CLUSTER' in elem.tag:
                name = elem.find('.//{*}SHORT-NAME')
                
                configs.append({
                    'type': 'LIN',
                    'name': name.text if name is not None else ''
                })
        
        return configs


@dataclass
class CSourceFile:
    """Parsed C source file for SAST."""
    path: str
    functions: List[Dict[str, Any]]
    includes: List[str]
    defines: List[str]
    global_variables: List[Dict[str, str]]
    potential_vulnerabilities: List[Dict[str, Any]]
    lines_of_code: int


class CSourceAnalyzer:
    """
    ANSI C Source Code Analyzer.
    
    Performs static analysis on C source files for:
    - Dangerous function detection
    - Buffer overflow patterns
    - Format string vulnerabilities
    - Integer overflow patterns
    """
    
    # Dangerous functions (CWE mappings)
    DANGEROUS_FUNCTIONS = {
        # Buffer overflows
        'strcpy': ('CWE-120', 'Use strncpy or strlcpy instead'),
        'strcat': ('CWE-120', 'Use strncat or strlcat instead'),
        'sprintf': ('CWE-120', 'Use snprintf instead'),
        'gets': ('CWE-120', 'Use fgets instead'),
        'scanf': ('CWE-120', 'Use fgets + sscanf with field width'),
        'vsprintf': ('CWE-120', 'Use vsnprintf instead'),
        
        # Format strings
        'printf': ('CWE-134', 'Ensure format string is not user-controlled'),
        'fprintf': ('CWE-134', 'Ensure format string is not user-controlled'),
        'syslog': ('CWE-134', 'Ensure format string is not user-controlled'),
        
        # Memory
        'malloc': ('CWE-789', 'Check return value and size calculations'),
        'realloc': ('CWE-789', 'Check for overflow in size calculation'),
        'free': ('CWE-416', 'Set pointer to NULL after free'),
        
        # Crypto (weak)
        'rand': ('CWE-330', 'Use cryptographic random generator'),
        'srand': ('CWE-330', 'Seed may be predictable'),
        
        # Race conditions
        'access': ('CWE-367', 'TOCTOU race condition possible'),
        'stat': ('CWE-367', 'TOCTOU race condition possible'),
        
        # Command injection
        'system': ('CWE-78', 'Avoid shell commands with user input'),
        'popen': ('CWE-78', 'Avoid shell commands with user input'),
        'exec': ('CWE-78', 'Validate all arguments'),
    }
    
    def __init__(self):
        # Regex patterns
        self.function_pattern = re.compile(
            r'^\s*([\w\s\*]+)\s+(\w+)\s*\(([^)]*)\)\s*{',
            re.MULTILINE
        )
        self.include_pattern = re.compile(r'#include\s*[<"]([^>"]+)[>"]')
        self.define_pattern = re.compile(r'#define\s+(\w+)(?:\s+(.*))?')
        self.global_var_pattern = re.compile(
            r'^(?:static\s+)?(?:const\s+)?([\w\s\*]+)\s+(\w+)\s*(?:=|;)',
            re.MULTILINE
        )
        self.func_call_pattern = re.compile(r'\b(\w+)\s*\(')
    
    def analyze(self, path: str) -> CSourceFile:
        """
        Analyze a C source file.
        
        Args:
            path: Path to .c or .h file
            
        Returns:
            CSourceFile with analysis results
        """
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Count lines
        loc = len([l for l in content.splitlines() if l.strip() and not l.strip().startswith('//')])
        
        # Extract components
        functions = self._extract_functions(content)
        includes = self.include_pattern.findall(content)
        defines = [(m.group(1), m.group(2) or '') for m in self.define_pattern.finditer(content)]
        global_vars = self._extract_globals(content)
        
        # Find vulnerabilities
        vulnerabilities = self._find_vulnerabilities(content, path)
        
        logger.info(f"Analyzed {path}: {len(functions)} functions, "
                   f"{len(vulnerabilities)} potential vulnerabilities")
        
        return CSourceFile(
            path=path,
            functions=functions,
            includes=includes,
            defines=[d[0] for d in defines],
            global_variables=global_vars,
            potential_vulnerabilities=vulnerabilities,
            lines_of_code=loc
        )
    
    def _extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract function definitions."""
        
        functions = []
        
        for match in self.function_pattern.finditer(content):
            return_type = match.group(1).strip()
            name = match.group(2)
            params = match.group(3).strip()
            
            # Skip if it looks like a control statement
            if name in ['if', 'while', 'for', 'switch']:
                continue
            
            functions.append({
                'name': name,
                'return_type': return_type,
                'parameters': params,
                'line': content[:match.start()].count('\n') + 1
            })
        
        return functions
    
    def _extract_globals(self, content: str) -> List[Dict[str, str]]:
        """Extract global variable declarations."""
        
        variables = []
        
        # Remove function bodies first (simplified)
        # This is a simplification - proper parsing would use AST
        
        for match in self.global_var_pattern.finditer(content):
            var_type = match.group(1).strip()
            var_name = match.group(2)
            
            # Filter out function declarations
            if '(' in var_type or var_name in ['if', 'while', 'for', 'return']:
                continue
            
            variables.append({
                'type': var_type,
                'name': var_name
            })
        
        return variables
    
    def _find_vulnerabilities(self, content: str, path: str) -> List[Dict[str, Any]]:
        """Find potential vulnerabilities in source code."""
        
        vulnerabilities = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('/*'):
                continue
            
            # Check for dangerous function calls
            for match in self.func_call_pattern.finditer(line):
                func_name = match.group(1)
                
                if func_name in self.DANGEROUS_FUNCTIONS:
                    cwe, remediation = self.DANGEROUS_FUNCTIONS[func_name]
                    
                    vulnerabilities.append({
                        'file': path,
                        'line': line_num,
                        'function': func_name,
                        'cwe_id': cwe,
                        'severity': self._get_severity(cwe),
                        'description': f"Use of dangerous function '{func_name}'",
                        'remediation': remediation,
                        'code_snippet': line.strip()
                    })
            
            # Check for hardcoded credentials patterns
            if re.search(r'password\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                vulnerabilities.append({
                    'file': path,
                    'line': line_num,
                    'function': '',
                    'cwe_id': 'CWE-798',
                    'severity': 'high',
                    'description': 'Possible hardcoded credential',
                    'remediation': 'Store credentials securely, not in source code',
                    'code_snippet': line.strip()
                })
            
            # Check for integer overflow patterns
            if re.search(r'\*\s*\w+\s*\)', line) and ('malloc' in line or 'alloc' in line):
                vulnerabilities.append({
                    'file': path,
                    'line': line_num,
                    'function': '',
                    'cwe_id': 'CWE-190',
                    'severity': 'medium',
                    'description': 'Potential integer overflow in allocation size',
                    'remediation': 'Check for overflow before multiplication',
                    'code_snippet': line.strip()
                })
        
        return vulnerabilities
    
    def _get_severity(self, cwe: str) -> str:
        """Map CWE to severity."""
        
        critical_cwes = ['CWE-120', 'CWE-78', 'CWE-416']
        high_cwes = ['CWE-134', 'CWE-798', 'CWE-367']
        
        if cwe in critical_cwes:
            return 'critical'
        elif cwe in high_cwes:
            return 'high'
        else:
            return 'medium'


class AutomotiveFormatLoader:
    """
    Unified loader for all automotive file formats.
    
    Supported formats:
    - VBF (Volvo Binary Format)
    - AUTOSAR ARXML
    - ANSI C source files
    - ELF binaries
    - Intel HEX
    - Motorola S-Record
    - Raw binary
    """
    
    def __init__(self):
        self.vbf_loader = VBFLoader()
        self.autosar_loader = AUTOSARLoader()
        self.c_analyzer = CSourceAnalyzer()
    
    def detect_format(self, path: str) -> str:
        """Detect file format."""
        
        ext = Path(path).suffix.lower()
        
        format_map = {
            '.vbf': 'vbf',
            '.arxml': 'autosar',
            '.c': 'c_source',
            '.h': 'c_source',
            '.elf': 'elf',
            '.hex': 'ihex',
            '.s19': 'srec',
            '.s28': 'srec',
            '.s37': 'srec',
            '.bin': 'raw',
        }
        
        return format_map.get(ext, 'unknown')
    
    def load(self, path: str) -> Dict[str, Any]:
        """
        Load any supported automotive file format.
        
        Args:
            path: Path to file
            
        Returns:
            Dict with parsed content and metadata
        """
        fmt = self.detect_format(path)
        
        result = {
            'path': path,
            'format': fmt,
            'success': False,
            'data': None,
            'vulnerabilities': []
        }
        
        try:
            if fmt == 'vbf':
                vbf = self.vbf_loader.load(path)
                result['data'] = {
                    'header': {
                        'sw_part_number': vbf.header.sw_part_number,
                        'sw_version': vbf.header.sw_version,
                        'ecu_address': hex(vbf.header.ecu_address),
                    },
                    'blocks': len(vbf.blocks),
                    'total_size': vbf.total_size,
                }
                result['binary_data'] = self.vbf_loader.extract_binary(vbf)
                result['success'] = True
                
            elif fmt == 'autosar':
                config = self.autosar_loader.load(path)
                result['data'] = {
                    'packages': config.ar_packages,
                    'components': len(config.components),
                    'ecu_instances': config.ecu_instances,
                    'communication': config.communication_configs,
                }
                result['success'] = True
                
            elif fmt == 'c_source':
                analysis = self.c_analyzer.analyze(path)
                result['data'] = {
                    'functions': analysis.functions,
                    'loc': analysis.lines_of_code,
                    'includes': analysis.includes,
                }
                result['vulnerabilities'] = analysis.potential_vulnerabilities
                result['success'] = True
                
            else:
                result['error'] = f"Use BinaryLoader for format: {fmt}"
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Failed to load {path}: {e}")
        
        return result
    
    @staticmethod
    def get_supported_formats() -> List[Dict[str, str]]:
        """Get list of supported formats."""
        
        return [
            {'extension': '.vbf', 'name': 'Volvo Binary Format', 'type': 'binary'},
            {'extension': '.arxml', 'name': 'AUTOSAR Configuration', 'type': 'config'},
            {'extension': '.c', 'name': 'ANSI C Source', 'type': 'source'},
            {'extension': '.h', 'name': 'C Header', 'type': 'source'},
            {'extension': '.elf', 'name': 'ELF Binary', 'type': 'binary'},
            {'extension': '.hex', 'name': 'Intel HEX', 'type': 'binary'},
            {'extension': '.s19', 'name': 'Motorola S-Record', 'type': 'binary'},
            {'extension': '.bin', 'name': 'Raw Binary', 'type': 'binary'},
        ]
