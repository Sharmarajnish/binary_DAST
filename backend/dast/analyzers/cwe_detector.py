"""
CWE Top 25 Detector Module
Map vulnerabilities to CWE (Common Weakness Enumeration) Top 25.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class CWEInfo:
    """Information about a CWE entry."""
    cwe_id: str
    rank: int
    name: str
    description: str
    in_top_25: bool
    automotive_relevance: str  # 'high', 'medium', 'low'
    mitre_url: str


class CWETopDetector:
    """
    Map vulnerabilities to CWE Top 25 Most Dangerous Software Weaknesses.
    
    Based on 2024 CWE Top 25 list with additional automotive-specific
    relevance scoring.
    """
    
    def __init__(self):
        # CWE Top 25 Most Dangerous Software Weaknesses (2024)
        self.cwe_top_25: Dict[str, CWEInfo] = {
            'CWE-787': CWEInfo(
                cwe_id='CWE-787',
                rank=1,
                name='Out-of-bounds Write',
                description='Software writes data past the end of a buffer, leading to memory corruption',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/787.html'
            ),
            'CWE-79': CWEInfo(
                cwe_id='CWE-79',
                rank=2,
                name='Cross-site Scripting (XSS)',
                description='Improper neutralization of input in web page generation',
                in_top_25=True,
                automotive_relevance='low',
                mitre_url='https://cwe.mitre.org/data/definitions/79.html'
            ),
            'CWE-89': CWEInfo(
                cwe_id='CWE-89',
                rank=3,
                name='SQL Injection',
                description='Improper neutralization of SQL commands in queries',
                in_top_25=True,
                automotive_relevance='low',
                mitre_url='https://cwe.mitre.org/data/definitions/89.html'
            ),
            'CWE-416': CWEInfo(
                cwe_id='CWE-416',
                rank=4,
                name='Use After Free',
                description='Referencing memory after it has been freed',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/416.html'
            ),
            'CWE-78': CWEInfo(
                cwe_id='CWE-78',
                rank=5,
                name='OS Command Injection',
                description='Improper neutralization of special elements in OS commands',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/78.html'
            ),
            'CWE-20': CWEInfo(
                cwe_id='CWE-20',
                rank=6,
                name='Improper Input Validation',
                description='Not validating or incorrectly validating input',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/20.html'
            ),
            'CWE-125': CWEInfo(
                cwe_id='CWE-125',
                rank=7,
                name='Out-of-bounds Read',
                description='Reading data past the end of a buffer',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/125.html'
            ),
            'CWE-22': CWEInfo(
                cwe_id='CWE-22',
                rank=8,
                name='Path Traversal',
                description='Improper limitation of pathname to restricted directory',
                in_top_25=True,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/22.html'
            ),
            'CWE-352': CWEInfo(
                cwe_id='CWE-352',
                rank=9,
                name='Cross-Site Request Forgery (CSRF)',
                description='Forcing end user to execute unwanted actions',
                in_top_25=True,
                automotive_relevance='low',
                mitre_url='https://cwe.mitre.org/data/definitions/352.html'
            ),
            'CWE-434': CWEInfo(
                cwe_id='CWE-434',
                rank=10,
                name='Unrestricted Upload of Dangerous File',
                description='Allowing upload of files without proper validation',
                in_top_25=True,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/434.html'
            ),
            'CWE-862': CWEInfo(
                cwe_id='CWE-862',
                rank=11,
                name='Missing Authorization',
                description='Not performing authorization checks for sensitive operations',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/862.html'
            ),
            'CWE-476': CWEInfo(
                cwe_id='CWE-476',
                rank=12,
                name='NULL Pointer Dereference',
                description='Dereferencing a pointer that is NULL',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/476.html'
            ),
            'CWE-287': CWEInfo(
                cwe_id='CWE-287',
                rank=13,
                name='Improper Authentication',
                description='Not properly verifying identity claims',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/287.html'
            ),
            'CWE-190': CWEInfo(
                cwe_id='CWE-190',
                rank=14,
                name='Integer Overflow or Wraparound',
                description='Integer operations that exceed maximum value',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/190.html'
            ),
            'CWE-502': CWEInfo(
                cwe_id='CWE-502',
                rank=15,
                name='Deserialization of Untrusted Data',
                description='Deserializing data without validation',
                in_top_25=True,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/502.html'
            ),
            'CWE-77': CWEInfo(
                cwe_id='CWE-77',
                rank=16,
                name='Command Injection',
                description='Improper neutralization of special elements in commands',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/77.html'
            ),
            'CWE-119': CWEInfo(
                cwe_id='CWE-119',
                rank=17,
                name='Improper Restriction of Operations within Memory Buffer',
                description='Buffer errors from improper memory operations',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/119.html'
            ),
            'CWE-798': CWEInfo(
                cwe_id='CWE-798',
                rank=18,
                name='Use of Hard-coded Credentials',
                description='Embedding fixed credentials in code',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/798.html'
            ),
            'CWE-918': CWEInfo(
                cwe_id='CWE-918',
                rank=19,
                name='Server-Side Request Forgery (SSRF)',
                description='Server making requests to unintended locations',
                in_top_25=True,
                automotive_relevance='low',
                mitre_url='https://cwe.mitre.org/data/definitions/918.html'
            ),
            'CWE-306': CWEInfo(
                cwe_id='CWE-306',
                rank=20,
                name='Missing Authentication for Critical Function',
                description='Not requiring authentication for sensitive functions',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/306.html'
            ),
            'CWE-362': CWEInfo(
                cwe_id='CWE-362',
                rank=21,
                name='Concurrent Execution with Shared Resource (Race Condition)',
                description='Improper synchronization leading to race conditions',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/362.html'
            ),
            'CWE-269': CWEInfo(
                cwe_id='CWE-269',
                rank=22,
                name='Improper Privilege Management',
                description='Not properly managing privileges',
                in_top_25=True,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/269.html'
            ),
            'CWE-94': CWEInfo(
                cwe_id='CWE-94',
                rank=23,
                name='Improper Control of Code Generation (Code Injection)',
                description='Allowing injection of code into application',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/94.html'
            ),
            'CWE-863': CWEInfo(
                cwe_id='CWE-863',
                rank=24,
                name='Incorrect Authorization',
                description='Performing authorization checks incorrectly',
                in_top_25=True,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/863.html'
            ),
            'CWE-276': CWEInfo(
                cwe_id='CWE-276',
                rank=25,
                name='Incorrect Default Permissions',
                description='Setting insecure default permissions',
                in_top_25=True,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/276.html'
            ),
        }
        
        # Additional automotive-relevant CWEs not in Top 25
        self.automotive_cwes: Dict[str, CWEInfo] = {
            'CWE-120': CWEInfo(
                cwe_id='CWE-120',
                rank=0,
                name='Buffer Copy without Checking Size of Input',
                description='Classic buffer overflow from unsafe copy operations',
                in_top_25=False,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/120.html'
            ),
            'CWE-134': CWEInfo(
                cwe_id='CWE-134',
                rank=0,
                name='Use of Externally-Controlled Format String',
                description='Format string vulnerabilities',
                in_top_25=False,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/134.html'
            ),
            'CWE-369': CWEInfo(
                cwe_id='CWE-369',
                rank=0,
                name='Divide By Zero',
                description='Division or modulo by zero',
                in_top_25=False,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/369.html'
            ),
            'CWE-674': CWEInfo(
                cwe_id='CWE-674',
                rank=0,
                name='Uncontrolled Recursion',
                description='Recursion without proper termination',
                in_top_25=False,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/674.html'
            ),
            'CWE-704': CWEInfo(
                cwe_id='CWE-704',
                rank=0,
                name='Incorrect Type Conversion or Cast',
                description='Type confusion vulnerabilities',
                in_top_25=False,
                automotive_relevance='medium',
                mitre_url='https://cwe.mitre.org/data/definitions/704.html'
            ),
            'CWE-835': CWEInfo(
                cwe_id='CWE-835',
                rank=0,
                name='Loop with Unreachable Exit Condition',
                description='Infinite loops',
                in_top_25=False,
                automotive_relevance='high',
                mitre_url='https://cwe.mitre.org/data/definitions/835.html'
            ),
        }
    
    def get_cwe_info(self, cwe_id: str) -> Optional[CWEInfo]:
        """
        Get information about a CWE.
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-787')
            
        Returns:
            CWEInfo or None if not found
        """
        # Normalize CWE ID
        if not cwe_id.upper().startswith('CWE-'):
            cwe_id = f'CWE-{cwe_id}'
        else:
            cwe_id = cwe_id.upper()
        
        # Check Top 25 first
        if cwe_id in self.cwe_top_25:
            return self.cwe_top_25[cwe_id]
        
        # Check automotive CWEs
        if cwe_id in self.automotive_cwes:
            return self.automotive_cwes[cwe_id]
        
        return None
    
    def is_in_top_25(self, cwe_id: str) -> bool:
        """
        Check if CWE is in Top 25.
        
        Args:
            cwe_id: CWE identifier
            
        Returns:
            True if in Top 25
        """
        info = self.get_cwe_info(cwe_id)
        return info.in_top_25 if info else False
    
    def get_automotive_relevance(self, cwe_id: str) -> str:
        """
        Get automotive relevance of a CWE.
        
        Args:
            cwe_id: CWE identifier
            
        Returns:
            'high', 'medium', 'low', or 'unknown'
        """
        info = self.get_cwe_info(cwe_id)
        return info.automotive_relevance if info else 'unknown'
    
    def get_all_top_25(self) -> List[CWEInfo]:
        """Get all CWE Top 25 entries sorted by rank."""
        return sorted(self.cwe_top_25.values(), key=lambda x: x.rank)
    
    def get_high_automotive_relevance(self) -> List[CWEInfo]:
        """Get all CWEs with high automotive relevance."""
        high_relevance = []
        
        for cwe in self.cwe_top_25.values():
            if cwe.automotive_relevance == 'high':
                high_relevance.append(cwe)
        
        for cwe in self.automotive_cwes.values():
            if cwe.automotive_relevance == 'high':
                high_relevance.append(cwe)
        
        return high_relevance
    
    def enrich_vulnerability(self, vuln: Dict) -> Dict:
        """
        Enrich vulnerability with CWE information.
        
        Args:
            vuln: Vulnerability dictionary with 'cwe_id' field
            
        Returns:
            Enriched vulnerability dictionary
        """
        cwe_id = vuln.get('cwe_id')
        if not cwe_id:
            return vuln
        
        info = self.get_cwe_info(cwe_id)
        if info:
            vuln['cwe_name'] = info.name
            vuln['cwe_description'] = info.description
            vuln['cwe_rank'] = info.rank if info.in_top_25 else None
            vuln['in_top_25'] = info.in_top_25
            vuln['automotive_relevance'] = info.automotive_relevance
            vuln['cwe_url'] = info.mitre_url
        
        return vuln
    
    def map_signal_to_cwe(self, signal: str) -> str:
        """
        Map crash signal to most likely CWE.
        
        Args:
            signal: Signal name (e.g., 'SIGSEGV')
            
        Returns:
            CWE ID
        """
        signal_map = {
            'SIGSEGV': 'CWE-787',   # Out-of-bounds Write (or Read)
            'SIGBUS': 'CWE-787',    # Memory access error
            'SIGABRT': 'CWE-674',   # Often from assertion/recursion
            'SIGILL': 'CWE-704',    # Incorrect type/instruction
            'SIGFPE': 'CWE-369',    # Divide by zero
            'SIGTRAP': 'CWE-20',    # Input validation
        }
        
        return signal_map.get(signal, 'CWE-20')