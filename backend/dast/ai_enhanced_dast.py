"""
AI-Enhanced DAST Module
Uses LLMs (Claude/Gemini) to provide deep analysis of DAST findings.

Features:
- Deep crash analysis with root cause identification
- Intelligent fuzzing input generation
- False positive validation
- Proof-of-concept exploit generation
- Automotive-specific triage (ISO 26262, ISO 21434, UNECE R155)
- Executive summary generation
- Automated fix recommendations
"""

import json
import logging
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class AIAnalysisResult:
    """Result from AI analysis."""
    success: bool
    content: Dict[str, Any]
    raw_response: str = ""
    error: Optional[str] = None


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """Generate response from AI model."""
        pass


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.client = None
        
        if self.api_key:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
            except ImportError:
                logger.warning("anthropic package not installed")
    
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        if not self.client:
            raise RuntimeError("Anthropic client not initialized")
        
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text


class GeminiProvider(AIProvider):
    """Google Gemini provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('GOOGLE_API_KEY')
        self.model = None
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
            except ImportError:
                logger.warning("google-generativeai package not installed")
    
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        if not self.model:
            raise RuntimeError("Gemini model not initialized")
        
        response = self.model.generate_content(prompt)
        return response.text


class AIEnhancedDAST:
    """
    DAST with AI superpowers.
    
    Enhances traditional DAST results with:
    - Deep crash analysis
    - False positive validation
    - PoC exploit generation
    - Automotive-specific risk assessment
    - Automated fix generation
    - Executive summaries
    """
    
    def __init__(
        self,
        provider: str = 'gemini',
        api_key: Optional[str] = None
    ):
        """
        Initialize AI-enhanced DAST.
        
        Args:
            provider: 'anthropic' or 'gemini'
            api_key: API key (or set via environment variable)
        """
        self.provider_name = provider
        
        if provider == 'anthropic':
            self.ai = AnthropicProvider(api_key)
        else:
            self.ai = GeminiProvider(api_key)
        
        self._initialized = self._check_initialized()
    
    def _check_initialized(self) -> bool:
        """Check if AI provider is properly initialized."""
        try:
            if self.provider_name == 'anthropic':
                return self.ai.client is not None
            else:
                return self.ai.model is not None
        except Exception:
            return False
    
    def enhance_dast_results(
        self,
        dast_results: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Take raw DAST results and enhance with AI analysis.
        
        Args:
            dast_results: Output from traditional DAST (fuzzing, symbolic execution)
            context: ECU context (type, ASIL, network, etc.)
        
        Returns:
            Enhanced results with AI insights
        """
        if not self._initialized:
            logger.warning("AI provider not initialized - returning unenhanced results")
            dast_results['ai_enhanced'] = False
            dast_results['ai_error'] = 'AI provider not configured'
            return dast_results
        
        enhanced_vulns = []
        
        for vuln in dast_results.get('vulnerabilities', []):
            enhanced_vuln = vuln.copy()
            
            try:
                # 1. Deep crash analysis (if crash data available)
                if vuln.get('crash_details') or vuln.get('type') == 'crash':
                    enhanced_vuln['ai_crash_analysis'] = self.analyze_crash(vuln, context)
                
                # 2. False positive validation
                validation = self.validate_finding(vuln, context)
                enhanced_vuln['ai_validation'] = validation
                
                # 3. Generate PoC for true positives
                if validation.get('verdict') == 'TRUE_POSITIVE':
                    enhanced_vuln['ai_poc'] = self.generate_poc(vuln)
                
                # 4. Automotive context triage
                enhanced_vuln['ai_triage'] = self.automotive_triage(vuln, context)
                
                # 5. Generate fix recommendation
                enhanced_vuln['ai_fix'] = self.generate_fix(vuln, context)
                
            except Exception as e:
                logger.error(f"AI enhancement error for vuln: {e}")
                enhanced_vuln['ai_error'] = str(e)
            
            enhanced_vulns.append(enhanced_vuln)
        
        # 6. Generate executive summary
        try:
            executive_summary = self.generate_summary(enhanced_vulns, context)
        except Exception as e:
            executive_summary = f"Error generating summary: {e}"
        
        return {
            'vulnerabilities': enhanced_vulns,
            'executive_summary': executive_summary,
            'ai_enhanced': True,
            'ai_provider': self.provider_name,
            'stats': dast_results.get('stats', {}),
            'methods_used': dast_results.get('methods_used', [])
        }
    
    def analyze_crash(
        self,
        vuln: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Deep AI analysis of crash.
        
        Args:
            vuln: Vulnerability with crash details
            context: ECU context
            
        Returns:
            Detailed crash analysis
        """
        prompt = f"""You are an automotive cybersecurity expert analyzing an ECU binary crash.

Crash Details:
- Signal: {vuln.get('crash_details', {}).get('signal', vuln.get('type', 'unknown'))}
- Address: {vuln.get('address', vuln.get('crash_details', {}).get('address', 'N/A'))}
- Input that caused crash: {vuln.get('input_vector', 'N/A')[:200]}
- CWE: {vuln.get('cwe_id', 'N/A')}
- Description: {vuln.get('description', 'N/A')}

ECU Context:
- Type: {context.get('ecu_type', 'Unknown ECU')}
- ASIL Level: {context.get('asil', 'Unknown')}
- Safety Critical: {context.get('safety_critical', False)}

Provide analysis as JSON (no markdown, just raw JSON):
{{
  "root_cause": "exact technical cause of the crash",
  "exploitable": true/false,
  "exploitation_difficulty": "none/low/medium/high",
  "attack_scenario": "step-by-step attack scenario for automotive context",
  "cvss_vector": "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
  "cvss_score": 0.0,
  "iso_26262_impact": "ASIL level impact assessment",
  "can_attack_vector": "specific CAN/UDS command if applicable, or null"
}}"""

        try:
            response = self.ai.generate(prompt, max_tokens=1500)
            # Extract JSON from response
            return self._parse_json_response(response)
        except Exception as e:
            logger.error(f"Crash analysis error: {e}")
            return {'error': str(e)}
    
    def validate_finding(
        self,
        vuln: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        AI validates if vulnerability is real or false positive.
        
        Args:
            vuln: Vulnerability to validate
            context: ECU context
            
        Returns:
            Validation result
        """
        prompt = f"""Determine if this security finding is a TRUE POSITIVE or FALSE POSITIVE.

Finding:
- Type: {vuln.get('type', 'unknown')}
- CWE: {vuln.get('cwe_id', 'N/A')}
- Severity: {vuln.get('severity', 'medium')}
- Description: {vuln.get('description', 'N/A')}
- Detection Method: {vuln.get('detection_method', 'N/A')}

Context:
- ECU Type: {context.get('ecu_type', 'Unknown')}
- Safety Critical: {context.get('safety_critical', False)}
- Network Exposure: {context.get('network', 'Unknown')}

Return ONLY valid JSON (no markdown):
{{
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE",
  "confidence": 0-100,
  "reasoning": "explanation of decision",
  "exploitability": "none/low/medium/high/critical"
}}"""

        try:
            response = self.ai.generate(prompt, max_tokens=1000)
            return self._parse_json_response(response)
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return {'verdict': 'UNKNOWN', 'error': str(e)}
    
    def generate_poc(self, vuln: Dict[str, Any]) -> str:
        """
        Generate proof-of-concept exploit code.
        
        Args:
            vuln: Vulnerability to create PoC for
            
        Returns:
            PoC code as string
        """
        prompt = f"""Create a proof-of-concept exploit for this automotive ECU vulnerability.

Vulnerability:
- CWE: {vuln.get('cwe_id', 'N/A')}
- Type: {vuln.get('type', 'N/A')}
- Description: {vuln.get('description', 'N/A')}
- Input that triggers: {vuln.get('input_vector', 'N/A')[:200]}
- Function: {vuln.get('function', 'N/A')}
- Address: {vuln.get('address', 'N/A')}

Generate:
1. Python PoC script that demonstrates the vulnerability
2. CAN message payload (if CAN-based attack)
3. UDS command sequence (if diagnostic service)
4. Comments explaining each step

Include disclaimer: "AUTHORIZED SECURITY TESTING ONLY"

Provide working code."""

        try:
            response = self.ai.generate(prompt, max_tokens=2500)
            return response
        except Exception as e:
            logger.error(f"PoC generation error: {e}")
            return f"# Error generating PoC: {e}"
    
    def automotive_triage(
        self,
        vuln: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Automotive-specific risk assessment.
        
        Args:
            vuln: Vulnerability to assess
            context: ECU context
            
        Returns:
            Automotive triage results
        """
        prompt = f"""Assess automotive-specific risk for this ECU vulnerability.

Vulnerability:
- Type: {vuln.get('type', 'unknown')}
- CWE: {vuln.get('cwe_id', 'N/A')}
- Severity: {vuln.get('severity', 'medium')}
- Description: {vuln.get('description', 'N/A')}

ECU Context:
- Type: {context.get('ecu_type', 'Unknown ECU')}
- ASIL Level: {context.get('asil', 'Unknown')}
- Network: {context.get('network', 'Unknown')}
- Safety Critical: {context.get('safety_critical', False)}
- Functions: {context.get('functions', [])}

Return ONLY valid JSON:
{{
  "automotive_severity": 0-10,
  "affects_safety": true/false,
  "safety_explanation": "why it affects or doesn't affect safety",
  "affects_security": true/false,
  "security_explanation": "theft, privacy, etc.",
  "iso_26262_impact": "ASIL impact assessment",
  "iso_21434_impact": "cybersecurity assessment",
  "unece_r155_violation": true/false,
  "exploitation_likelihood": "Remote/Adjacent/Local/Physical",
  "priority": "P0/P1/P2/P3",
  "recommended_action": "specific action to take"
}}"""

        try:
            response = self.ai.generate(prompt, max_tokens=1500)
            return self._parse_json_response(response)
        except Exception as e:
            logger.error(f"Triage error: {e}")
            return {'error': str(e)}
    
    def generate_fix(
        self,
        vuln: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate specific fix recommendation.
        
        Args:
            vuln: Vulnerability to fix
            context: ECU context
            
        Returns:
            Fix recommendation
        """
        prompt = f"""Generate a fix for this automotive ECU vulnerability.

Vulnerability:
- CWE: {vuln.get('cwe_id', 'N/A')}
- Type: {vuln.get('type', 'N/A')}
- Description: {vuln.get('description', 'N/A')}
- Function: {vuln.get('function', 'N/A')}
- Remediation hint: {vuln.get('remediation', 'N/A')}

ECU Type: {context.get('ecu_type', 'Unknown')}

Return ONLY valid JSON:
{{
  "fix_description": "high-level description of the fix",
  "code_before": "vulnerable code pattern (C/C++)",
  "code_after": "fixed code pattern (C/C++)",
  "explanation": "why this fixes the issue",
  "testing_recommendations": ["list", "of", "tests"],
  "alternative_mitigations": ["if code fix not possible"]
}}"""

        try:
            response = self.ai.generate(prompt, max_tokens=2000)
            return self._parse_json_response(response)
        except Exception as e:
            logger.error(f"Fix generation error: {e}")
            return {'error': str(e)}
    
    def generate_summary(
        self,
        vulns: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> str:
        """
        Generate executive summary for management.
        
        Args:
            vulns: List of enhanced vulnerabilities
            context: ECU context
            
        Returns:
            Executive summary text
        """
        # Prepare summary of findings
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        true_positives = 0
        
        for v in vulns:
            sev = v.get('severity', 'medium')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if v.get('ai_validation', {}).get('verdict') == 'TRUE_POSITIVE':
                true_positives += 1
        
        prompt = f"""Generate an executive summary for this ECU security assessment.

ECU: {context.get('ecu_type', 'Unknown ECU')}
ASIL Level: {context.get('asil', 'Unknown')}
Total Findings: {len(vulns)}
AI-Validated True Positives: {true_positives}

Severity Distribution:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

Top Findings (summarized):
{json.dumps([{
    'type': v.get('type'),
    'cwe': v.get('cwe_id'),
    'severity': v.get('severity'),
    'verdict': v.get('ai_validation', {}).get('verdict', 'unknown')
} for v in vulns[:5]], indent=2)}

Write 2-3 paragraph executive summary including:
1. Overall risk assessment
2. Most critical findings and their business impact
3. Compliance implications (ISO 26262, ISO 21434, UNECE R155)
4. Recommended next steps

Professional tone suitable for senior management and compliance officers."""

        try:
            response = self.ai.generate(prompt, max_tokens=1500)
            return response
        except Exception as e:
            logger.error(f"Summary generation error: {e}")
            return f"Error generating executive summary: {e}"
    
    def generate_fuzz_inputs(
        self,
        binary_info: Dict[str, Any]
    ) -> List[bytes]:
        """
        Generate intelligent fuzzing inputs using AI.
        
        Args:
            binary_info: Information about the binary
            
        Returns:
            List of fuzzing input bytes
        """
        prompt = f"""Generate 15 targeted fuzzing inputs for this automotive ECU binary.

Binary Analysis:
- Detected protocols: {binary_info.get('protocols', ['UDS', 'CAN'])}
- Functions found: {binary_info.get('functions', [])[:10]}
- Architecture: {binary_info.get('architecture', 'unknown')}

Generate inputs targeting:
1. UDS diagnostic services (seed/key bypass attempts)
2. CAN message parsing edge cases
3. Buffer overflow triggers
4. Format string vulnerabilities
5. Integer overflow in length fields
6. Authentication bypass patterns

Return ONLY valid JSON array of hex-encoded byte strings:
{{
  "test_cases": [
    {{"hex": "270100000000", "description": "UDS Security Access seed=0"}},
    {{"hex": "22F190", "description": "UDS Read VIN"}}
  ]
}}"""

        try:
            response = self.ai.generate(prompt, max_tokens=2000)
            data = self._parse_json_response(response)
            
            inputs = []
            for tc in data.get('test_cases', []):
                try:
                    inputs.append(bytes.fromhex(tc.get('hex', '')))
                except ValueError:
                    pass
            
            return inputs
            
        except Exception as e:
            logger.error(f"Fuzz input generation error: {e}")
            return []
    
    def explain_symbolic_path(
        self,
        path_info: Dict[str, Any],
        context: Dict[str, Any]
    ) -> str:
        """
        Explain what a symbolic execution path means.
        
        Args:
            path_info: Path information from symbolic execution
            context: ECU context
            
        Returns:
            Explanation text
        """
        prompt = f"""Symbolic execution found this path in an ECU binary.

Path Information:
- Path constraints: {path_info.get('constraints', [])[:5]}
- Functions called: {path_info.get('functions', [])[:10]}
- Ends at address: {path_info.get('ends_at', 'unknown')}
- Path length: {path_info.get('length', 0)} instructions

ECU Type: {context.get('ecu_type', 'Unknown')}

Explain:
1. What does this execution path likely do? (high-level)
2. What input would trigger this path?
3. Is this path suspicious or potentially dangerous?
4. Any business logic vulnerabilities indicated?
5. Safety implications for the vehicle?

Provide clear, technical explanation."""

        try:
            response = self.ai.generate(prompt, max_tokens=1500)
            return response
        except Exception as e:
            return f"Error explaining path: {e}"
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from AI response, handling markdown code blocks."""
        
        # Try direct parse first
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code block
        import re
        
        # Look for ```json ... ``` or ``` ... ```
        patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'\{[\s\S]*\}'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(1) if '```' in pattern else match.group(0)
                    return json.loads(json_str)
                except (json.JSONDecodeError, IndexError):
                    continue
        
        # Return error dict
        return {'parse_error': 'Could not parse JSON from response', 'raw': response[:500]}


class HybridDASTOrchestrator:
    """
    Hybrid DAST orchestrator combining traditional analysis with AI enhancement.
    
    Runs traditional DAST first, then optionally enhances with AI.
    """
    
    def __init__(
        self,
        binary_path: str,
        ai_provider: str = 'gemini',
        ai_api_key: Optional[str] = None,
        enable_ai: bool = True
    ):
        """
        Initialize hybrid DAST orchestrator.
        
        Args:
            binary_path: Path to binary
            ai_provider: 'gemini' or 'anthropic'
            ai_api_key: API key for AI provider
            enable_ai: Whether to enable AI enhancement
        """
        from .dast_orchestrator import DASTOrchestrator, DASTConfig
        
        self.binary_path = binary_path
        self.enable_ai = enable_ai
        
        # Traditional DAST
        self.dast_config = DASTConfig(
            enable_fuzzing=True,
            enable_symbolic=True,
            enable_protocol=False,
            enable_taint=False,
        )
        self.dast = DASTOrchestrator(binary_path, config=self.dast_config)
        
        # AI enhancement
        if enable_ai:
            self.ai_dast = AIEnhancedDAST(provider=ai_provider, api_key=ai_api_key)
        else:
            self.ai_dast = None
    
    def run_hybrid_analysis(
        self,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run full hybrid DAST analysis.
        
        Args:
            context: ECU context for AI analysis
            
        Returns:
            Combined results
        """
        # Default context
        if context is None:
            context = {
                'ecu_type': 'Unknown ECU',
                'asil': 'QM',
                'network': 'Unknown',
                'safety_critical': False,
                'functions': []
            }
        
        print("\n" + "="*60)
        print("HYBRID DAST ANALYSIS")
        print("="*60)
        
        # Phase 1: Traditional DAST
        print("\n[Phase 1] Running traditional DAST analysis...")
        raw_results = self.dast.run_full_dast()
        
        # Convert to dict if needed
        results = {
            'binary_path': raw_results.binary_path,
            'architecture': raw_results.architecture,
            'vulnerabilities': raw_results.vulnerabilities,
            'stats': raw_results.stats,
            'methods_used': raw_results.methods_used,
            'analysis_time': raw_results.analysis_time,
        }
        
        print(f"[Phase 1] Found {len(results['vulnerabilities'])} potential issues")
        
        # Phase 2: AI Enhancement
        if self.enable_ai and self.ai_dast and self.ai_dast._initialized:
            print("\n[Phase 2] Running AI enhancement...")
            results = self.ai_dast.enhance_dast_results(results, context)
            
            # Count true positives
            true_positives = sum(
                1 for v in results['vulnerabilities']
                if v.get('ai_validation', {}).get('verdict') == 'TRUE_POSITIVE'
            )
            print(f"[Phase 2] AI validated {true_positives} true positives")
        else:
            print("\n[Phase 2] AI enhancement skipped (not configured)")
            results['ai_enhanced'] = False
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60 + "\n")
        
        return results
    
    def export_results(self, format: str = 'json') -> str:
        """Export results in various formats."""
        return self.dast.export_results(format)
    
    def get_ai_summary(self) -> Optional[str]:
        """Get AI-generated executive summary."""
        if hasattr(self, '_last_results') and 'executive_summary' in self._last_results:
            return self._last_results['executive_summary']
        return None


# Convenience function
def run_ai_enhanced_dast(
    binary_path: str,
    context: Optional[Dict[str, Any]] = None,
    ai_provider: str = 'gemini',
    ai_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run AI-enhanced DAST analysis.
    
    Args:
        binary_path: Path to binary
        context: ECU context
        ai_provider: 'gemini' or 'anthropic'
        ai_api_key: API key
        
    Returns:
        Enhanced analysis results
    """
    orchestrator = HybridDASTOrchestrator(
        binary_path,
        ai_provider=ai_provider,
        ai_api_key=ai_api_key,
        enable_ai=True
    )
    
    return orchestrator.run_hybrid_analysis(context)