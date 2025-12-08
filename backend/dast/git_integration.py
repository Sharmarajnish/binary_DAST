"""
Git Repository Integration for DAST
Supports GitHub and GitLab for CI/CD integration.
"""

import os
import subprocess
import tempfile
import shutil
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class RepoInfo:
    """Repository information."""
    name: str
    url: str
    branch: str
    commit: str
    local_path: str


class GitRepoScanner:
    """
    Scan Git repositories for ECU binaries.
    
    Supports:
    - GitHub (public and private)
    - GitLab (cloud and self-hosted)
    - Local Git repositories
    """
    
    def __init__(
        self,
        github_token: Optional[str] = None,
        gitlab_token: Optional[str] = None,
        gitlab_url: str = "https://gitlab.com"
    ):
        """
        Initialize Git scanner.
        
        Args:
            github_token: GitHub personal access token
            gitlab_token: GitLab personal access token
            gitlab_url: GitLab instance URL (for self-hosted)
        """
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.gitlab_token = gitlab_token or os.getenv('GITLAB_TOKEN')
        self.gitlab_url = gitlab_url
        
        self.work_dir = tempfile.mkdtemp(prefix="dast_git_")
    
    def clone_repository(
        self,
        repo_url: str,
        branch: str = "main",
        depth: int = 1
    ) -> RepoInfo:
        """
        Clone a Git repository.
        
        Args:
            repo_url: Repository URL (HTTPS or SSH)
            branch: Branch to clone
            depth: Clone depth (1 for shallow)
            
        Returns:
            RepoInfo with local path
        """
        # Parse repo name from URL
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
        local_path = os.path.join(self.work_dir, repo_name)
        
        # Build clone command
        cmd = ['git', 'clone', '--depth', str(depth), '--branch', branch]
        
        # Add authentication for private repos
        auth_url = self._add_auth_to_url(repo_url)
        cmd.append(auth_url)
        cmd.append(local_path)
        
        print(f"[Git] Cloning {repo_url} (branch: {branch})...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Clone failed: {result.stderr}")
            
            # Get commit hash
            commit = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=local_path,
                capture_output=True,
                text=True
            ).stdout.strip()
            
            print(f"[Git] Cloned successfully (commit: {commit[:8]})")
            
            return RepoInfo(
                name=repo_name,
                url=repo_url,
                branch=branch,
                commit=commit,
                local_path=local_path
            )
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Clone timed out")
    
    def _add_auth_to_url(self, url: str) -> str:
        """Add authentication token to URL."""
        
        if 'github.com' in url and self.github_token:
            # https://TOKEN@github.com/...
            return url.replace('https://', f'https://{self.github_token}@')
        elif 'gitlab' in url and self.gitlab_token:
            # https://oauth2:TOKEN@gitlab.com/...
            return url.replace('https://', f'https://oauth2:{self.gitlab_token}@')
        
        return url
    
    def find_binaries(
        self,
        local_path: str,
        extensions: Optional[List[str]] = None
    ) -> List[str]:
        """
        Find binary files in repository.
        
        Args:
            local_path: Local repository path
            extensions: File extensions to look for
            
        Returns:
            List of binary file paths
        """
        if extensions is None:
            extensions = ['.bin', '.elf', '.hex', '.s19', '.vbf', '.o', '.so', '.a']
        
        binaries = []
        
        for root, dirs, files in os.walk(local_path):
            # Skip common non-binary directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    binaries.append(os.path.join(root, file))
        
        print(f"[Git] Found {len(binaries)} binary files")
        return binaries
    
    def scan_github_repo(
        self,
        owner: str,
        repo: str,
        branch: str = "main"
    ) -> Dict[str, Any]:
        """
        Scan a GitHub repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Branch to scan
            
        Returns:
            Scan results
        """
        url = f"https://github.com/{owner}/{repo}.git"
        
        # Clone
        repo_info = self.clone_repository(url, branch)
        
        # Find binaries
        binaries = self.find_binaries(repo_info.local_path)
        
        return {
            'repo': repo_info,
            'binaries': binaries,
            'source': 'github'
        }
    
    def scan_gitlab_repo(
        self,
        project_path: str,
        branch: str = "main"
    ) -> Dict[str, Any]:
        """
        Scan a GitLab repository.
        
        Args:
            project_path: Project path (e.g., "group/project")
            branch: Branch to scan
            
        Returns:
            Scan results
        """
        url = f"{self.gitlab_url}/{project_path}.git"
        
        # Clone
        repo_info = self.clone_repository(url, branch)
        
        # Find binaries
        binaries = self.find_binaries(repo_info.local_path)
        
        return {
            'repo': repo_info,
            'binaries': binaries,
            'source': 'gitlab'
        }
    
    def get_github_releases(
        self,
        owner: str,
        repo: str
    ) -> List[Dict[str, Any]]:
        """
        Get GitHub releases with binary assets.
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            List of releases with assets
        """
        headers = {}
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
        
        url = f"https://api.github.com/repos/{owner}/{repo}/releases"
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            releases = []
            for release in response.json():
                assets = []
                for asset in release.get('assets', []):
                    name = asset['name']
                    if any(name.endswith(ext) for ext in ['.bin', '.elf', '.hex', '.vbf', '.zip']):
                        assets.append({
                            'name': name,
                            'url': asset['browser_download_url'],
                            'size': asset['size']
                        })
                
                if assets:
                    releases.append({
                        'tag': release['tag_name'],
                        'name': release['name'],
                        'assets': assets
                    })
            
            return releases
            
        except Exception as e:
            logger.error(f"Failed to get releases: {e}")
            return []
    
    def download_release_asset(
        self,
        url: str,
        output_path: str
    ) -> str:
        """Download a release asset."""
        
        headers = {}
        if self.github_token and 'github.com' in url:
            headers['Authorization'] = f'token {self.github_token}'
        
        response = requests.get(url, headers=headers, stream=True, timeout=120)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        return output_path
    
    def cleanup(self):
        """Clean up temporary files."""
        if os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)


class GitLabCIIntegration:
    """
    GitLab CI/CD integration for DAST.
    
    Generates .gitlab-ci.yml configuration.
    """
    
    @staticmethod
    def generate_ci_config(
        scan_config: Dict[str, Any],
        stages: List[str] = None
    ) -> str:
        """
        Generate GitLab CI configuration.
        
        Args:
            scan_config: DAST configuration
            stages: CI stages to include
            
        Returns:
            YAML configuration string
        """
        if stages is None:
            stages = ['build', 'test', 'dast', 'report']
        
        config = f"""# DAST Scanner GitLab CI Configuration
# Generated by ECU DAST v2.0

stages:
{chr(10).join(f'  - {s}' for s in stages)}

variables:
  DAST_TIMEOUT: "{scan_config.get('timeout', 300)}"
  ENABLE_AI: "{scan_config.get('enableAI', True)}"
  ENABLE_FUZZING: "{scan_config.get('enableFuzzing', True)}"
  ENABLE_SYMBOLIC: "{scan_config.get('enableSymbolic', True)}"

.dast_common: &dast_common
  image: ecu-dast:latest
  before_script:
    - pip install -r requirements.txt

dast_quick:
  <<: *dast_common
  stage: dast
  script:
    - python -m dast.run --binary ${{CI_PROJECT_DIR}}/build/*.elf --mode quick
  artifacts:
    reports:
      sast: dast-report.json
    paths:
      - dast-report.json
      - dast-report.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

dast_standard:
  <<: *dast_common
  stage: dast
  script:
    - python -m dast.run --binary ${{CI_PROJECT_DIR}}/build/*.elf --mode standard
  artifacts:
    reports:
      sast: dast-report.json
    paths:
      - dast-report.json
      - dast-report.sarif
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

dast_deep:
  <<: *dast_common
  stage: dast
  script:
    - python -m dast.run --binary ${{CI_PROJECT_DIR}}/build/*.elf --mode deep
  artifacts:
    reports:
      sast: dast-report.json
    paths:
      - dast-report.json
      - dast-report.sarif
  rules:
    - if: $CI_COMMIT_TAG

report:
  stage: report
  script:
    - python -m dast.generate_report --format html
  artifacts:
    paths:
      - dast-report.html
  dependencies:
    - dast_standard
"""
        return config


class GitHubActionsIntegration:
    """
    GitHub Actions integration for DAST.
    
    Generates workflow configuration.
    """
    
    @staticmethod
    def generate_workflow(
        scan_config: Dict[str, Any]
    ) -> str:
        """
        Generate GitHub Actions workflow.
        
        Args:
            scan_config: DAST configuration
            
        Returns:
            YAML workflow string
        """
        return f"""# DAST Scanner GitHub Actions Workflow
# Generated by ECU DAST v2.0

name: ECU DAST Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  release:
    types: [ published ]

env:
  DAST_TIMEOUT: {scan_config.get('timeout', 300)}
  ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
  GOOGLE_API_KEY: ${{{{ secrets.GOOGLE_API_KEY }}}}

jobs:
  dast-quick:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r backend/requirements.txt
      
      - name: Run Quick DAST
        run: |
          python -m dast.run --binary ./build/*.elf --mode quick
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dast-report.sarif

  dast-standard:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r backend/requirements.txt
      
      - name: Run Standard DAST
        run: |
          python -m dast.run --binary ./build/*.elf --mode standard
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dast-report
          path: |
            dast-report.json
            dast-report.sarif
            dast-report.html

  dast-deep:
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r backend/requirements.txt
      
      - name: Run Deep DAST
        run: |
          python -m dast.run --binary ./build/*.elf --mode deep --enable-protocol
      
      - name: Upload to Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            dast-report.json
            dast-report.html
"""


# Convenience functions
def scan_github(
    owner: str,
    repo: str,
    branch: str = "main",
    token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Quick scan of GitHub repository.
    
    Args:
        owner: Repository owner
        repo: Repository name
        branch: Branch to scan
        token: GitHub token
        
    Returns:
        Scan results
    """
    scanner = GitRepoScanner(github_token=token)
    try:
        return scanner.scan_github_repo(owner, repo, branch)
    finally:
        scanner.cleanup()


def scan_gitlab(
    project_path: str,
    branch: str = "main",
    token: Optional[str] = None,
    gitlab_url: str = "https://gitlab.com"
) -> Dict[str, Any]:
    """
    Quick scan of GitLab repository.
    
    Args:
        project_path: Project path (e.g., "group/project")
        branch: Branch to scan
        token: GitLab token
        gitlab_url: GitLab instance URL
        
    Returns:
        Scan results
    """
    scanner = GitRepoScanner(gitlab_token=token, gitlab_url=gitlab_url)
    try:
        return scanner.scan_gitlab_repo(project_path, branch)
    finally:
        scanner.cleanup()
