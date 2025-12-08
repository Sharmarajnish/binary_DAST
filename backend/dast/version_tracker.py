"""
Vulnerability Version Tracker
Tracks vulnerability status across multiple versions of ECU binaries.

Implements JLR WP2 requirement:
"Identification of vulnerabilities which have been remediated, re-opened, 
risk accepted across multiple versions of a specific ECU binary file."
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityRecord:
    """Record of a vulnerability instance."""
    id: str
    cwe_id: str
    title: str
    severity: str
    fingerprint: str  # Unique identifier for dedup
    function: Optional[str] = None
    address: Optional[str] = None
    first_seen_version: Optional[str] = None
    first_seen_date: Optional[str] = None
    status: str = 'open'  # open, remediated, reopened, risk_accepted
    status_history: List[Dict[str, str]] = field(default_factory=list)
    notes: str = ''


@dataclass
class VersionRecord:
    """Record of a scanned version."""
    version: str
    scan_date: str
    binary_hash: str
    vulnerabilities: List[str]  # List of vulnerability IDs
    stats: Dict[str, int] = field(default_factory=dict)


class VulnerabilityVersionTracker:
    """
    Track vulnerabilities across ECU binary versions.
    
    Features:
    - Fingerprint-based vulnerability matching
    - Status tracking (open, remediated, reopened, risk_accepted)
    - Version comparison and diff reports
    - Historical trend analysis
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize tracker.
        
        Args:
            storage_path: Path to store tracking data (JSON file)
        """
        self.storage_path = storage_path
        
        # In-memory storage
        self.vulnerabilities: Dict[str, VulnerabilityRecord] = {}
        self.versions: Dict[str, VersionRecord] = {}
        self.ecu_name: str = ''
        
        # Load existing data
        if storage_path and Path(storage_path).exists():
            self.load()
    
    def generate_fingerprint(self, vuln: Dict[str, Any]) -> str:
        """
        Generate unique fingerprint for vulnerability deduplication.
        
        Uses combination of:
        - CWE ID
        - Function name (if available)
        - Vulnerability type
        - Relative address pattern
        """
        components = [
            vuln.get('cwe_id', ''),
            vuln.get('function', vuln.get('function_name', '')),
            vuln.get('type', ''),
            # Normalize address to offset pattern
            self._normalize_address(vuln.get('address', '')),
        ]
        
        fingerprint_str = '|'.join(str(c) for c in components if c)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def _normalize_address(self, address: str) -> str:
        """Normalize address to pattern for matching across versions."""
        if not address:
            return ''
        
        # Extract just the offset portion (last 4 hex digits typically)
        import re
        match = re.search(r'([0-9a-fA-F]{4})$', str(address))
        return match.group(1) if match else ''
    
    def add_scan_results(
        self,
        binary_path: str,
        version: str,
        vulnerabilities: List[Dict[str, Any]],
        ecu_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add scan results for a binary version.
        
        Args:
            binary_path: Path to scanned binary
            version: Version identifier (e.g., "1.2.3", "commit_abc123")
            vulnerabilities: List of vulnerability dicts from DAST
            ecu_name: ECU name for grouping
            
        Returns:
            Comparison report with new/remediated/reopened counts
        """
        if ecu_name:
            self.ecu_name = ecu_name
        
        # Get previous version for comparison
        prev_version = self._get_previous_version()
        prev_vulns = set()
        if prev_version:
            prev_vulns = set(prev_version.vulnerabilities)
        
        # Calculate binary hash
        binary_hash = self._hash_file(binary_path) if Path(binary_path).exists() else 'unknown'
        
        # Process vulnerabilities
        current_vuln_ids = []
        new_count = 0
        reopened_count = 0
        
        for vuln in vulnerabilities:
            fingerprint = self.generate_fingerprint(vuln)
            
            # Check if we've seen this vulnerability before
            existing = self._find_by_fingerprint(fingerprint)
            
            if existing:
                vuln_id = existing.id
                
                # Check if it was previously remediated (reopened case)
                if existing.status == 'remediated':
                    existing.status = 'reopened'
                    existing.status_history.append({
                        'status': 'reopened',
                        'version': version,
                        'date': datetime.now().isoformat()
                    })
                    reopened_count += 1
                elif existing.status == 'risk_accepted':
                    # Risk accepted stays as is
                    pass
                else:
                    existing.status = 'open'
                    
            else:
                # New vulnerability
                vuln_id = f"VULN-{len(self.vulnerabilities) + 1:05d}"
                
                record = VulnerabilityRecord(
                    id=vuln_id,
                    cwe_id=vuln.get('cwe_id', 'Unknown'),
                    title=vuln.get('title', vuln.get('description', 'Unknown')[:100]),
                    severity=vuln.get('severity', 'medium'),
                    fingerprint=fingerprint,
                    function=vuln.get('function', vuln.get('function_name')),
                    address=vuln.get('address'),
                    first_seen_version=version,
                    first_seen_date=datetime.now().isoformat(),
                    status='open',
                    status_history=[{
                        'status': 'open',
                        'version': version,
                        'date': datetime.now().isoformat()
                    }]
                )
                
                self.vulnerabilities[vuln_id] = record
                new_count += 1
            
            current_vuln_ids.append(vuln_id)
        
        # Mark remediated vulnerabilities
        remediated_count = 0
        current_set = set(current_vuln_ids)
        
        for vuln_id in prev_vulns:
            if vuln_id not in current_set:
                vuln_record = self.vulnerabilities.get(vuln_id)
                if vuln_record and vuln_record.status == 'open':
                    vuln_record.status = 'remediated'
                    vuln_record.status_history.append({
                        'status': 'remediated',
                        'version': version,
                        'date': datetime.now().isoformat()
                    })
                    remediated_count += 1
        
        # Create version record
        version_record = VersionRecord(
            version=version,
            scan_date=datetime.now().isoformat(),
            binary_hash=binary_hash,
            vulnerabilities=current_vuln_ids,
            stats={
                'total': len(current_vuln_ids),
                'new': new_count,
                'remediated': remediated_count,
                'reopened': reopened_count,
            }
        )
        
        self.versions[version] = version_record
        
        # Auto-save
        if self.storage_path:
            self.save()
        
        return {
            'version': version,
            'total_vulnerabilities': len(current_vuln_ids),
            'new': new_count,
            'remediated': remediated_count,
            'reopened': reopened_count,
            'unchanged': len(current_vuln_ids) - new_count - reopened_count,
        }
    
    def _find_by_fingerprint(self, fingerprint: str) -> Optional[VulnerabilityRecord]:
        """Find vulnerability by fingerprint."""
        for vuln in self.vulnerabilities.values():
            if vuln.fingerprint == fingerprint:
                return vuln
        return None
    
    def _get_previous_version(self) -> Optional[VersionRecord]:
        """Get the most recent previous version."""
        if not self.versions:
            return None
        
        sorted_versions = sorted(
            self.versions.values(),
            key=lambda v: v.scan_date,
            reverse=True
        )
        
        return sorted_versions[0] if sorted_versions else None
    
    def _hash_file(self, path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]
    
    def set_status(
        self,
        vuln_id: str,
        status: str,
        notes: str = '',
        version: str = 'manual'
    ) -> bool:
        """
        Manually set vulnerability status.
        
        Args:
            vuln_id: Vulnerability ID
            status: New status (open, remediated, risk_accepted)
            notes: Optional notes
            version: Version context
            
        Returns:
            Success boolean
        """
        if vuln_id not in self.vulnerabilities:
            return False
        
        vuln = self.vulnerabilities[vuln_id]
        vuln.status = status
        vuln.notes = notes
        vuln.status_history.append({
            'status': status,
            'version': version,
            'date': datetime.now().isoformat(),
            'notes': notes
        })
        
        if self.storage_path:
            self.save()
        
        return True
    
    def compare_versions(
        self,
        version_a: str,
        version_b: str
    ) -> Dict[str, Any]:
        """
        Compare two versions.
        
        Args:
            version_a: First version (older)
            version_b: Second version (newer)
            
        Returns:
            Comparison report
        """
        if version_a not in self.versions or version_b not in self.versions:
            return {'error': 'Version not found'}
        
        vulns_a = set(self.versions[version_a].vulnerabilities)
        vulns_b = set(self.versions[version_b].vulnerabilities)
        
        new = vulns_b - vulns_a
        remediated = vulns_a - vulns_b
        unchanged = vulns_a & vulns_b
        
        return {
            'version_a': version_a,
            'version_b': version_b,
            'new': [self._vuln_summary(v) for v in new],
            'remediated': [self._vuln_summary(v) for v in remediated],
            'unchanged_count': len(unchanged),
            'summary': {
                'new_count': len(new),
                'remediated_count': len(remediated),
                'unchanged_count': len(unchanged),
            }
        }
    
    def _vuln_summary(self, vuln_id: str) -> Dict[str, str]:
        """Get vulnerability summary."""
        vuln = self.vulnerabilities.get(vuln_id)
        if not vuln:
            return {'id': vuln_id}
        return {
            'id': vuln.id,
            'cwe': vuln.cwe_id,
            'title': vuln.title,
            'severity': vuln.severity,
            'status': vuln.status,
        }
    
    def get_trends(self) -> Dict[str, Any]:
        """
        Get vulnerability trends over versions.
        
        Returns:
            Trend data for visualization
        """
        sorted_versions = sorted(
            self.versions.values(),
            key=lambda v: v.scan_date
        )
        
        trend_data = []
        for v in sorted_versions:
            trend_data.append({
                'version': v.version,
                'date': v.scan_date,
                'total': v.stats.get('total', 0),
                'new': v.stats.get('new', 0),
                'remediated': v.stats.get('remediated', 0),
            })
        
        # Calculate summary
        total_ever = len(self.vulnerabilities)
        open_count = sum(1 for v in self.vulnerabilities.values() if v.status == 'open')
        remediated_count = sum(1 for v in self.vulnerabilities.values() if v.status == 'remediated')
        risk_accepted = sum(1 for v in self.vulnerabilities.values() if v.status == 'risk_accepted')
        
        return {
            'ecu_name': self.ecu_name,
            'versions_scanned': len(self.versions),
            'total_vulnerabilities_ever': total_ever,
            'current_status': {
                'open': open_count,
                'remediated': remediated_count,
                'risk_accepted': risk_accepted,
            },
            'trend_data': trend_data,
        }
    
    def generate_report(self) -> str:
        """Generate text report of vulnerability status."""
        
        trends = self.get_trends()
        
        report = []
        report.append("=" * 60)
        report.append(f"ECU Vulnerability Tracking Report: {self.ecu_name}")
        report.append("=" * 60)
        report.append("")
        report.append(f"Versions Scanned: {trends['versions_scanned']}")
        report.append(f"Total Vulnerabilities (All Time): {trends['total_vulnerabilities_ever']}")
        report.append("")
        report.append("Current Status:")
        report.append(f"  Open:          {trends['current_status']['open']}")
        report.append(f"  Remediated:    {trends['current_status']['remediated']}")
        report.append(f"  Risk Accepted: {trends['current_status']['risk_accepted']}")
        report.append("")
        report.append("-" * 60)
        report.append("Open Vulnerabilities:")
        report.append("-" * 60)
        
        for vuln in self.vulnerabilities.values():
            if vuln.status == 'open':
                report.append(f"  [{vuln.severity.upper()}] {vuln.id}: {vuln.title}")
                report.append(f"           CWE: {vuln.cwe_id}")
                report.append(f"           First seen: {vuln.first_seen_version}")
        
        return "\n".join(report)
    
    def save(self) -> None:
        """Save tracking data to file."""
        if not self.storage_path:
            return
        
        data = {
            'ecu_name': self.ecu_name,
            'vulnerabilities': {k: asdict(v) for k, v in self.vulnerabilities.items()},
            'versions': {k: asdict(v) for k, v in self.versions.items()},
        }
        
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self) -> None:
        """Load tracking data from file."""
        if not self.storage_path or not Path(self.storage_path).exists():
            return
        
        with open(self.storage_path, 'r') as f:
            data = json.load(f)
        
        self.ecu_name = data.get('ecu_name', '')
        
        for k, v in data.get('vulnerabilities', {}).items():
            self.vulnerabilities[k] = VulnerabilityRecord(**v)
        
        for k, v in data.get('versions', {}).items():
            self.versions[k] = VersionRecord(**v)
    
    def export_to_json(self) -> str:
        """Export all data to JSON string."""
        data = {
            'ecu_name': self.ecu_name,
            'trends': self.get_trends(),
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities.values()],
            'versions': [asdict(v) for v in self.versions.values()],
        }
        return json.dumps(data, indent=2)
