#!/usr/bin/env python3
"""
DAST Test Runner
Tests the DAST system with vulnerable ECU binary.

Usage:
    python test_dast.py                     # Test with vulnerable ECU
    python test_dast.py --github owner/repo # Test GitHub repo
    python test_dast.py --gitlab group/project # Test GitLab repo
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dast import ModernDASTOrchestrator, ModernDASTConfig


def compile_vulnerable_ecu():
    """Compile the vulnerable ECU test binary."""
    
    source = Path(__file__).parent / "vulnerable_ecu.c"
    binary = Path(__file__).parent / "vulnerable_ecu"
    
    if not source.exists():
        print(f"[ERROR] Source not found: {source}")
        return None
    
    print("[Build] Compiling vulnerable_ecu.c...")
    
    # Compile with security features disabled
    cmd = [
        'gcc',
        '-o', str(binary),
        str(source),
        '-no-pie',
        '-fno-stack-protector',
        '-Wno-format-security',
        '-Wno-deprecated-declarations',
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[ERROR] Compilation failed: {result.stderr}")
            return None
        
        print(f"[Build] Compiled: {binary}")
        return str(binary)
        
    except FileNotFoundError:
        print("[ERROR] gcc not found. Please install build tools.")
        return None


def test_vulnerable_ecu():
    """Test DAST with vulnerable ECU binary."""
    
    # Compile
    binary_path = compile_vulnerable_ecu()
    if not binary_path:
        # Try to find pre-compiled binary
        binary_path = Path(__file__).parent / "vulnerable_ecu"
        if not binary_path.exists():
            print("[ERROR] No binary available for testing")
            return False
        binary_path = str(binary_path)
    
    print("\n" + "=" * 60)
    print("  DAST TEST: Vulnerable ECU")
    print("=" * 60)
    
    # Configure DAST
    config = ModernDASTConfig(
        enable_aflpp=True,
        enable_honggfuzz=False,  # Use one fuzzer for speed
        enable_radamsa=True,
        enable_symbolic=True,
        enable_protocol=False,
        enable_taint=False,
        enable_ai=False,  # Disable AI for automated tests
        fuzzing_timeout=60,  # 1 minute for test
        ecu_context={
            'ecu_type': 'Test ECU',
            'asil': 'QM',
            'safety_critical': False,
            'network': 'Test',
        }
    )
    
    # Run DAST
    orchestrator = ModernDASTOrchestrator(binary_path, config)
    results = orchestrator.run_comprehensive_dast()
    
    # Analyze results
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    
    vulnerabilities = results.vulnerabilities
    
    print(f"\nVulnerabilities found: {len(vulnerabilities)}")
    
    # Expected vulnerabilities
    expected_cwes = [
        'CWE-120',  # Buffer Overflow
        'CWE-134',  # Format String
        'CWE-190',  # Integer Overflow
        'CWE-416',  # Use-After-Free
        'CWE-798',  # Hardcoded Credentials
        'CWE-306',  # Missing Auth
        'CWE-327',  # Weak Crypto
    ]
    
    found_cwes = set()
    
    for vuln in vulnerabilities:
        cwe = vuln.get('cwe_id', '')
        severity = vuln.get('severity', 'unknown')
        title = vuln.get('title', 'Unknown')
        method = vuln.get('detection_method', 'unknown')
        
        print(f"\n[{severity.upper()}] {title}")
        print(f"  CWE: {cwe}")
        print(f"  Method: {method}")
        
        found_cwes.add(cwe)
    
    # Check coverage
    print("\n" + "-" * 60)
    print("CWE Coverage:")
    
    for cwe in expected_cwes:
        if cwe in found_cwes:
            print(f"  ✅ {cwe} - Found")
        else:
            print(f"  ❌ {cwe} - Not found")
    
    coverage = len(found_cwes.intersection(expected_cwes)) / len(expected_cwes) * 100
    print(f"\nCoverage: {coverage:.0f}%")
    
    # Export results
    output_file = Path(__file__).parent / "dast_test_results.json"
    with open(output_file, 'w') as f:
        json.dump({
            'binary': binary_path,
            'vulnerabilities': vulnerabilities,
            'coverage': coverage,
            'stats': results.stats,
        }, f, indent=2, default=str)
    
    print(f"\nResults saved to: {output_file}")
    
    return coverage >= 50  # Pass if we find at least half


def test_github_repo(repo: str):
    """Test DAST with GitHub repository."""
    
    from dast.git_integration import scan_github
    
    print(f"\n[GitHub] Scanning repository: {repo}")
    
    owner, name = repo.split('/')
    
    # Scan repo
    result = scan_github(owner, name)
    
    binaries = result['binaries']
    print(f"[GitHub] Found {len(binaries)} binaries")
    
    if not binaries:
        print("[GitHub] No binaries found in repository")
        return False
    
    # Test first binary
    binary_path = binaries[0]
    print(f"[GitHub] Testing: {binary_path}")
    
    config = ModernDASTConfig(
        enable_aflpp=True,
        enable_symbolic=True,
        fuzzing_timeout=120,
    )
    
    orchestrator = ModernDASTOrchestrator(binary_path, config)
    results = orchestrator.run_comprehensive_dast()
    
    print(f"\n[GitHub] Found {len(results.vulnerabilities)} vulnerabilities")
    
    return True


def test_gitlab_repo(project: str, gitlab_url: str = "https://gitlab.com"):
    """Test DAST with GitLab repository."""
    
    from dast.git_integration import scan_gitlab
    
    print(f"\n[GitLab] Scanning project: {project}")
    
    # Scan repo
    result = scan_gitlab(project, gitlab_url=gitlab_url)
    
    binaries = result['binaries']
    print(f"[GitLab] Found {len(binaries)} binaries")
    
    if not binaries:
        print("[GitLab] No binaries found in repository")
        return False
    
    # Test first binary
    binary_path = binaries[0]
    print(f"[GitLab] Testing: {binary_path}")
    
    config = ModernDASTConfig(
        enable_aflpp=True,
        enable_symbolic=True,
        fuzzing_timeout=120,
    )
    
    orchestrator = ModernDASTOrchestrator(binary_path, config)
    results = orchestrator.run_comprehensive_dast()
    
    print(f"\n[GitLab] Found {len(results.vulnerabilities)} vulnerabilities")
    
    return True


def run_benchmark():
    """Run DAST benchmark with known vulnerable binaries."""
    
    print("\n" + "=" * 60)
    print("  DAST BENCHMARK")
    print("=" * 60)
    
    # Known vulnerable projects
    benchmark_targets = [
        {
            'name': 'ICSim (Instrument Cluster Simulator)',
            'github': 'zombieCraig/ICSim',
            'expected_vulns': 3,
        },
        {
            'name': 'can-utils',
            'github': 'linux-can/can-utils',
            'expected_vulns': 1,
        },
    ]
    
    results = []
    
    for target in benchmark_targets:
        print(f"\n--- {target['name']} ---")
        
        try:
            from dast.git_integration import scan_github
            
            owner, repo = target['github'].split('/')
            scan_result = scan_github(owner, repo)
            
            if scan_result['binaries']:
                config = ModernDASTConfig(
                    enable_aflpp=True,
                    enable_symbolic=True,
                    fuzzing_timeout=60,
                )
                
                orchestrator = ModernDASTOrchestrator(
                    scan_result['binaries'][0], 
                    config
                )
                dast_result = orchestrator.run_comprehensive_dast()
                
                found = len(dast_result.vulnerabilities)
                expected = target['expected_vulns']
                
                results.append({
                    'name': target['name'],
                    'found': found,
                    'expected': expected,
                    'detection_rate': min(found / max(expected, 1) * 100, 100)
                })
                
                print(f"  Found: {found} vulnerabilities")
            else:
                print("  No binaries found")
                
        except Exception as e:
            print(f"  Error: {e}")
    
    # Summary
    if results:
        print("\n" + "=" * 60)
        print("  BENCHMARK RESULTS")
        print("=" * 60)
        
        for r in results:
            print(f"\n{r['name']}:")
            print(f"  Found: {r['found']}, Expected: {r['expected']}")
            print(f"  Detection Rate: {r['detection_rate']:.0f}%")
        
        avg_rate = sum(r['detection_rate'] for r in results) / len(results)
        print(f"\nAverage Detection Rate: {avg_rate:.0f}%")


def main():
    parser = argparse.ArgumentParser(description='DAST Test Runner')
    parser.add_argument('--github', help='GitHub repository (owner/repo)')
    parser.add_argument('--gitlab', help='GitLab project (group/project)')
    parser.add_argument('--gitlab-url', default='https://gitlab.com', help='GitLab URL')
    parser.add_argument('--benchmark', action='store_true', help='Run benchmark')
    parser.add_argument('--local', help='Test local binary file')
    
    args = parser.parse_args()
    
    if args.github:
        success = test_github_repo(args.github)
    elif args.gitlab:
        success = test_gitlab_repo(args.gitlab, args.gitlab_url)
    elif args.benchmark:
        run_benchmark()
        success = True
    elif args.local:
        config = ModernDASTConfig(enable_aflpp=True, enable_symbolic=True)
        orchestrator = ModernDASTOrchestrator(args.local, config)
        results = orchestrator.run_comprehensive_dast()
        print(f"Found {len(results.vulnerabilities)} vulnerabilities")
        success = True
    else:
        success = test_vulnerable_ecu()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
