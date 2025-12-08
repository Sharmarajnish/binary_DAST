import React, { useState } from 'react';
import {
    BookOpen, FileText, Shield, Code, Cpu, Workflow, ChevronRight,
    CheckCircle2, AlertTriangle, Terminal, GitBranch, Zap, Lock,
    Target, Layers, Database, Globe, ArrowRight, ExternalLink
} from 'lucide-react';

interface DocSection {
    id: string;
    title: string;
    icon: React.FC<any>;
    content: React.ReactNode;
}

const Documentation: React.FC = () => {
    const [activeSection, setActiveSection] = useState('methodology');

    const sections: DocSection[] = [
        {
            id: 'methodology',
            title: 'Methodology',
            icon: Target,
            content: <MethodologyContent />
        },
        {
            id: 'compliance',
            title: 'Compliance Frameworks',
            icon: Shield,
            content: <ComplianceContent />
        },
        {
            id: 'integration',
            title: 'Integration Guides',
            icon: Workflow,
            content: <IntegrationContent />
        },
        {
            id: 'api',
            title: 'API Reference',
            icon: Code,
            content: <APIContent />
        },
        {
            id: 'best-practices',
            title: 'Best Practices',
            icon: CheckCircle2,
            content: <BestPracticesContent />
        },
    ];

    const currentSection = sections.find(s => s.id === activeSection) || sections[0];

    return (
        <div className="h-full overflow-hidden bg-precogs-50/30 flex">
            {/* Sidebar Navigation */}
            <div className="w-72 bg-white border-r border-surface-200 flex flex-col">
                <div className="p-6 border-b border-surface-200">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-precogs-100 rounded-xl flex items-center justify-center">
                            <BookOpen className="w-5 h-5 text-precogs-600" />
                        </div>
                        <div>
                            <h1 className="font-bold text-slate-900">Documentation</h1>
                            <p className="text-xs text-slate-600">Precogs AI Platform</p>
                        </div>
                    </div>
                </div>

                <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
                    {sections.map(section => {
                        const Icon = section.icon;
                        return (
                            <button
                                key={section.id}
                                onClick={() => setActiveSection(section.id)}
                                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${activeSection === section.id
                                    ? 'bg-precogs-50 text-precogs-700 border border-precogs-200'
                                    : 'text-slate-700 hover:bg-precogs-50'
                                    }`}
                            >
                                <Icon className="w-5 h-5" />
                                {section.title}
                                {activeSection === section.id && (
                                    <ChevronRight className="w-4 h-4 ml-auto" />
                                )}
                            </button>
                        );
                    })}
                </nav>

                {/* Version Footer */}
                <div className="p-4 border-t border-surface-200">
                    <div className="px-4 py-3 bg-precogs-50/30 rounded-lg">
                        <p className="text-xs text-slate-600">Platform Version</p>
                        <p className="text-sm font-semibold text-slate-900">v2.5.0 Enterprise</p>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 overflow-y-auto">
                <div className="max-w-4xl mx-auto p-8">
                    {currentSection.content}
                </div>
            </div>
        </div>
    );
};

// ============ METHODOLOGY SECTION ============
const MethodologyContent: React.FC = () => (
    <div className="space-y-8">
        <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">DAST Methodology</h1>
            <p className="text-slate-700 text-lg">
                Precogs AI employs a multi-layered approach to Dynamic Application Security Testing,
                specifically optimized for automotive and embedded systems.
            </p>
        </div>

        {/* Overview Card */}
        <div className="bg-gradient-to-br from-precogs-500 to-precogs-700 rounded-2xl p-6 text-white">
            <h2 className="text-xl font-bold mb-4">Analysis Pipeline Overview</h2>
            <div className="grid grid-cols-5 gap-3">
                {[
                    { step: '1', label: 'Format Detection', icon: FileText },
                    { step: '2', label: 'Architecture Analysis', icon: Cpu },
                    { step: '3', label: 'Vulnerability Scan', icon: Shield },
                    { step: '4', label: 'AI Validation', icon: Zap },
                    { step: '5', label: 'Report Generation', icon: Target },
                ].map((item, i) => (
                    <div key={i} className="text-center">
                        <div className="w-12 h-12 mx-auto bg-white/20 rounded-xl flex items-center justify-center mb-2">
                            <item.icon className="w-6 h-6" />
                        </div>
                        <p className="text-xs font-medium opacity-90">{item.label}</p>
                    </div>
                ))}
            </div>
        </div>

        {/* Detection Methods */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-precogs-600" />
                Detection Methods
            </h3>

            <div className="space-y-4">
                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">Pattern-Based Analysis (SAST)</h4>
                    <p className="text-sm text-slate-700 mb-3">
                        Static pattern matching identifies known vulnerability signatures in source code and binaries.
                        Covers CWE Top 25 with automotive-specific patterns.
                    </p>
                    <div className="flex flex-wrap gap-2">
                        {['CWE-120', 'CWE-134', 'CWE-190', 'CWE-416', 'CWE-798', 'CWE-306'].map(cwe => (
                            <span key={cwe} className="px-2 py-1 bg-amber-100 text-amber-700 text-xs rounded-md font-medium">
                                {cwe}
                            </span>
                        ))}
                    </div>
                </div>

                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">Fuzzing (Precogs Fuzzer, Precogs HF)</h4>
                    <p className="text-sm text-slate-700 mb-3">
                        Coverage-guided fuzzing generates malformed inputs to trigger edge-case vulnerabilities.
                        Emulates automotive architectures via QEMU for cross-platform testing.
                    </p>
                    <div className="flex flex-wrap gap-2">
                        {['ARM', 'TriCore', 'RISC-V', 'PowerPC', 'x86'].map(arch => (
                            <span key={arch} className="px-2 py-1 bg-emerald-100 text-emerald-700 text-xs rounded-md font-medium">
                                {arch}
                            </span>
                        ))}
                    </div>
                </div>

                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">Symbolic Execution (Precogs SE)</h4>
                    <p className="text-sm text-slate-700">
                        Explores all possible execution paths to find reachable vulnerabilities.
                        Generates proof-of-concept inputs that trigger specific vulnerability conditions.
                    </p>
                </div>

                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">Protocol Fuzzing (Precogs Protocol)</h4>
                    <p className="text-sm text-slate-700">
                        Tests automotive communication protocols including UDS (Unified Diagnostic Services),
                        CAN bus, DoIP, and FlexRay for protocol-level vulnerabilities.
                    </p>
                </div>
            </div>
        </div>

        {/* CVSS Scoring */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Target className="w-5 h-5 text-precogs-600" />
                CVSS Scoring Methodology
            </h3>
            <p className="text-sm text-slate-700 mb-4">
                All vulnerabilities are scored using CVSS 3.1 with automotive-specific adjustments
                based on ASIL ratings and safety criticality context.
            </p>

            <table className="w-full text-sm">
                <thead>
                    <tr className="border-b border-surface-200">
                        <th className="text-left py-2 font-semibold text-slate-900">Severity</th>
                        <th className="text-left py-2 font-semibold text-slate-900">CVSS Range</th>
                        <th className="text-left py-2 font-semibold text-slate-900">Response Time</th>
                    </tr>
                </thead>
                <tbody className="text-slate-700">
                    <tr className="border-b border-surface-100">
                        <td className="py-2"><span className="px-2 py-0.5 bg-red-100 text-red-700 rounded font-medium">Critical</span></td>
                        <td className="py-2">9.0 - 10.0</td>
                        <td className="py-2">Immediate</td>
                    </tr>
                    <tr className="border-b border-surface-100">
                        <td className="py-2"><span className="px-2 py-0.5 bg-orange-100 text-orange-700 rounded font-medium">High</span></td>
                        <td className="py-2">7.0 - 8.9</td>
                        <td className="py-2">24 hours</td>
                    </tr>
                    <tr className="border-b border-surface-100">
                        <td className="py-2"><span className="px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded font-medium">Medium</span></td>
                        <td className="py-2">4.0 - 6.9</td>
                        <td className="py-2">7 days</td>
                    </tr>
                    <tr>
                        <td className="py-2"><span className="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded font-medium">Low</span></td>
                        <td className="py-2">0.1 - 3.9</td>
                        <td className="py-2">30 days</td>
                    </tr>
                </tbody>
            </table>
        </div>

        {/* AI Enhancement */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Zap className="w-5 h-5 text-precogs-600" />
                AI-Enhanced Analysis
            </h3>
            <p className="text-sm text-slate-700 mb-4">
                Precogs AI uses Google Gemini to validate findings, reduce false positives,
                and generate contextual remediation guidance.
            </p>

            <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-precogs-50 rounded-lg border border-precogs-100">
                    <h4 className="font-semibold text-precogs-900 mb-2">False Positive Reduction</h4>
                    <p className="text-sm text-precogs-700">
                        AI reviews each finding in context, filtering noise and confirming exploitability.
                    </p>
                </div>
                <div className="p-4 bg-precogs-50 rounded-lg border border-precogs-100">
                    <h4 className="font-semibold text-precogs-900 mb-2">Remediation Guidance</h4>
                    <p className="text-sm text-precogs-700">
                        Generates code-level fix suggestions tailored to the specific vulnerability and codebase.
                    </p>
                </div>
            </div>
        </div>
    </div>
);

// ============ COMPLIANCE SECTION ============
const ComplianceContent: React.FC = () => (
    <div className="space-y-8">
        <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Compliance Frameworks</h1>
            <p className="text-slate-700 text-lg">
                Precogs AI maps all findings to major automotive and industrial cybersecurity standards.
            </p>
        </div>

        {[
            {
                name: 'UNECE R155',
                fullName: 'UN Regulation No. 155 - Cyber Security Management System',
                color: 'cyan',
                description: 'Mandatory for vehicle type approval in 60+ countries. Requires cybersecurity management throughout vehicle lifecycle.',
                requirements: [
                    'Threat assessment and risk mitigation',
                    'Security by design verification',
                    'Incident detection and response capabilities',
                    'Secure software update mechanisms',
                ],
            },
            {
                name: 'ISO 21434',
                fullName: 'Road Vehicles - Cybersecurity Engineering',
                color: 'purple',
                description: 'International standard for automotive cybersecurity engineering throughout the product development lifecycle.',
                requirements: [
                    'Cybersecurity management at organizational level',
                    'Threat Analysis and Risk Assessment (TARA)',
                    'Cybersecurity validation and verification',
                    'Post-production cybersecurity management',
                ],
            },
            {
                name: 'ISO 26262',
                fullName: 'Functional Safety for Road Vehicles',
                color: 'emerald',
                description: 'Safety standard addressing hazards caused by malfunctioning E/E systems. Includes ASIL ratings.',
                requirements: [
                    'Hazard analysis and risk assessment',
                    'Safety requirements specification',
                    'Software development process (ASIL rated)',
                    'Safety validation and verification',
                ],
            },
            {
                name: 'MISRA C:2012',
                fullName: 'MISRA C Guidelines for Safe Coding',
                color: 'amber',
                description: 'C language coding standard for embedded systems. Widely adopted in automotive.',
                requirements: [
                    '143 mandatory rules',
                    '14 advisory rules',
                    'Decidable vs undecidable rule categories',
                    'Deviation process documentation',
                ],
            },
        ].map(framework => (
            <div key={framework.name} className="bg-white rounded-xl border border-surface-200 p-6">
                <div className="flex items-start justify-between mb-4">
                    <div>
                        <h3 className="text-xl font-bold text-slate-900">{framework.name}</h3>
                        <p className="text-sm text-slate-600">{framework.fullName}</p>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs font-medium bg-${framework.color}-100 text-${framework.color}-700`}>
                        Supported
                    </span>
                </div>

                <p className="text-slate-700 mb-4">{framework.description}</p>

                <h4 className="font-semibold text-slate-900 mb-2">Key Requirements:</h4>
                <ul className="space-y-2">
                    {framework.requirements.map((req, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-slate-700">
                            <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                            {req}
                        </li>
                    ))}
                </ul>
            </div>
        ))}
    </div>
);

// ============ INTEGRATION SECTION ============
const IntegrationContent: React.FC = () => (
    <div className="space-y-8">
        <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Integration Guides</h1>
            <p className="text-slate-700 text-lg">
                Integrate Precogs AI into your development workflow with our CI/CD pipelines and tool integrations.
            </p>
        </div>

        {/* CI/CD Integration */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-precogs-600" />
                CI/CD Pipeline Integration
            </h3>

            <div className="space-y-4">
                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">GitLab CI Example</h4>
                    <pre className="bg-surface-900 text-surface-100 p-4 rounded-lg text-sm overflow-x-auto font-mono">
                        {`security_scan:
  stage: test
  script:
    - |
      RESULT=$(curl -s -X POST "$PRECOGS_URL/api/ci/scan" \\
        -H "Content-Type: application/json" \\
        -d '{"file_content_base64": "'$(base64 -w0 firmware.bin)'"}')
      SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
      # Poll for completion
      while [ "$(curl -s "$PRECOGS_URL/api/ci/result/$SCAN_ID" | jq -r '.completed')" != "true" ]; do
        sleep 5
      done
      # Check pass/fail
      if [ "$(curl -s "$PRECOGS_URL/api/ci/result/$SCAN_ID" | jq -r '.passed')" = "false" ]; then
        exit 1
      fi
  artifacts:
    reports:
      sast: scan_report.sarif`}
                    </pre>
                </div>

                <div className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200">
                    <h4 className="font-semibold text-slate-900 mb-2">GitHub Actions Example</h4>
                    <pre className="bg-surface-900 text-surface-100 p-4 rounded-lg text-sm overflow-x-auto font-mono">
                        {`name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Precogs AI Scan
        run: |
          curl -X POST "$\{{ secrets.PRECOGS_URL }}/api/ci/scan" \\
            -H "Content-Type: application/json" \\
            -d '{"file_content_base64": "'$(base64 -w0 firmware.bin)'"}'`}
                    </pre>
                </div>
            </div>
        </div>

        {/* SBOM Integration */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Database className="w-5 h-5 text-precogs-600" />
                SBOM Integration
            </h3>
            <p className="text-slate-700 mb-4">
                Import and export Software Bill of Materials in industry-standard formats.
            </p>

            <div className="grid grid-cols-3 gap-4">
                {['SPDX 2.3', 'CycloneDX 1.5', 'CPE CSV'].map(format => (
                    <div key={format} className="p-4 bg-precogs-50/30 rounded-lg border border-surface-200 text-center">
                        <FileText className="w-8 h-8 text-precogs-600 mx-auto mb-2" />
                        <p className="font-semibold text-slate-900">{format}</p>
                        <p className="text-xs text-slate-600">Import & Export</p>
                    </div>
                ))}
            </div>
        </div>

        {/* Jira Integration */}
        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Layers className="w-5 h-5 text-precogs-600" />
                Jira Integration
            </h3>
            <p className="text-slate-700 mb-4">
                Automatically create Jira tickets for vulnerabilities with priority mapping.
            </p>

            <table className="w-full text-sm">
                <thead>
                    <tr className="border-b border-surface-200">
                        <th className="text-left py-2 font-semibold text-slate-900">Severity</th>
                        <th className="text-left py-2 font-semibold text-slate-900">Jira Priority</th>
                        <th className="text-left py-2 font-semibold text-slate-900">Labels</th>
                    </tr>
                </thead>
                <tbody className="text-slate-700">
                    <tr className="border-b border-surface-100">
                        <td className="py-2">Critical</td>
                        <td className="py-2">Highest</td>
                        <td className="py-2">security, dast, p0</td>
                    </tr>
                    <tr className="border-b border-surface-100">
                        <td className="py-2">High</td>
                        <td className="py-2">High</td>
                        <td className="py-2">security, dast, p1</td>
                    </tr>
                    <tr className="border-b border-surface-100">
                        <td className="py-2">Medium</td>
                        <td className="py-2">Medium</td>
                        <td className="py-2">security, dast</td>
                    </tr>
                    <tr>
                        <td className="py-2">Low</td>
                        <td className="py-2">Low</td>
                        <td className="py-2">security, dast</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
);

// ============ API REFERENCE SECTION ============
const APIContent: React.FC = () => (
    <div className="space-y-8">
        <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">API Reference</h1>
            <p className="text-slate-700 text-lg">
                RESTful API for programmatic access to all Precogs AI capabilities.
            </p>
        </div>

        <div className="bg-precogs-50 border border-precogs-100 rounded-xl p-4">
            <p className="text-sm text-precogs-800">
                <strong>Base URL:</strong> <code className="bg-white px-2 py-1 rounded font-mono">http://localhost:8000</code>
            </p>
        </div>

        {[
            {
                method: 'POST',
                endpoint: '/scans/upload',
                description: 'Upload a binary file for analysis',
                request: 'FormData with "file" field',
                response: '{ "file_id": "uuid", "filename": "...", "size": 1234 }',
            },
            {
                method: 'POST',
                endpoint: '/scans/start',
                description: 'Start a security scan on an uploaded file',
                request: '{ "file_id": "uuid", "config": {...} }',
                response: '{ "scan_id": "uuid", "status": "running" }',
            },
            {
                method: 'GET',
                endpoint: '/scans/{scan_id}',
                description: 'Get scan status and results',
                request: 'Path parameter: scan_id',
                response: '{ "status": "completed", "findings": [...], "progress": 100 }',
            },
            {
                method: 'GET',
                endpoint: '/scans/{scan_id}/report/sarif',
                description: 'Download SARIF 2.1.0 format report',
                request: 'Path parameter: scan_id',
                response: 'SARIF JSON',
            },
            {
                method: 'POST',
                endpoint: '/compliance/audit',
                description: 'Run compliance-focused quick audit',
                request: '{ "file_id": "uuid", "frameworks": ["iso21434", "unece155"] }',
                response: '{ "scan_id": "uuid", "message": "..." }',
            },
        ].map((endpoint, i) => (
            <div key={i} className="bg-white rounded-xl border border-surface-200 p-6">
                <div className="flex items-center gap-3 mb-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${endpoint.method === 'GET' ? 'bg-emerald-100 text-emerald-700' : 'bg-precogs-100 text-precogs-700'
                        }`}>
                        {endpoint.method}
                    </span>
                    <code className="font-mono text-sm text-slate-900">{endpoint.endpoint}</code>
                </div>
                <p className="text-slate-700 mb-4">{endpoint.description}</p>

                <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <p className="font-semibold text-slate-700 mb-1">Request:</p>
                        <code className="text-xs text-slate-700">{endpoint.request}</code>
                    </div>
                    <div>
                        <p className="font-semibold text-slate-700 mb-1">Response:</p>
                        <code className="text-xs text-slate-700">{endpoint.response}</code>
                    </div>
                </div>
            </div>
        ))}
    </div>
);

// ============ BEST PRACTICES SECTION ============
const BestPracticesContent: React.FC = () => (
    <div className="space-y-8">
        <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Best Practices</h1>
            <p className="text-slate-700 text-lg">
                Guidelines for maximizing the effectiveness of your security testing program.
            </p>
        </div>

        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Lock className="w-5 h-5 text-precogs-600" />
                Automotive ECU Security Guidelines
            </h3>

            <div className="space-y-4">
                {[
                    {
                        title: 'Implement Secure Boot',
                        description: 'Verify firmware integrity before execution using cryptographic signatures.',
                    },
                    {
                        title: 'Use Hardware Security Modules (HSM)',
                        description: 'Store cryptographic keys in tamper-resistant hardware, not in firmware.',
                    },
                    {
                        title: 'Authenticate All Diagnostic Sessions',
                        description: 'Require SecurityAccess (0x27) before any critical UDS operations.',
                    },
                    {
                        title: 'Encrypt CAN Bus Communications',
                        description: 'Implement SecOC or equivalent for message authentication.',
                    },
                    {
                        title: 'Apply Defense in Depth',
                        description: 'Layer multiple security controls so compromise of one does not defeat all.',
                    },
                ].map((tip, i) => (
                    <div key={i} className="flex items-start gap-3 p-4 bg-precogs-50/30 rounded-lg">
                        <CheckCircle2 className="w-5 h-5 text-emerald-500 mt-0.5 flex-shrink-0" />
                        <div>
                            <h4 className="font-semibold text-slate-900">{tip.title}</h4>
                            <p className="text-sm text-slate-700">{tip.description}</p>
                        </div>
                    </div>
                ))}
            </div>
        </div>

        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                Common Pitfalls to Avoid
            </h3>

            <div className="space-y-3">
                {[
                    'Hardcoding encryption keys or passwords in source code',
                    'Using sprintf/strcpy without buffer size validation',
                    'Failing to validate inputs from external interfaces',
                    'Ignoring warnings from static analysis tools',
                    'Not testing with fuzzed/malformed protocol messages',
                ].map((pitfall, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm">
                        <span className="text-red-500 font-bold">✗</span>
                        <span className="text-slate-700">{pitfall}</span>
                    </div>
                ))}
            </div>
        </div>

        <div className="bg-white rounded-xl border border-surface-200 p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Workflow className="w-5 h-5 text-precogs-600" />
                Recommended Workflow
            </h3>

            <ol className="space-y-4">
                {[
                    { step: 1, title: 'Shift Left', desc: 'Integrate security scanning early in development cycle' },
                    { step: 2, title: 'Automate', desc: 'Run scans on every commit via CI/CD pipeline' },
                    { step: 3, title: 'Prioritize', desc: 'Focus on critical/high severity first using AI triage' },
                    { step: 4, title: 'Track', desc: 'Log all vulnerabilities and remediations for audit trail' },
                    { step: 5, title: 'Verify', desc: 'Re-scan after fixes to confirm resolution' },
                ].map(item => (
                    <li key={item.step} className="flex items-start gap-4">
                        <span className="w-8 h-8 bg-precogs-100 text-precogs-700 rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0">
                            {item.step}
                        </span>
                        <div>
                            <h4 className="font-semibold text-slate-900">{item.title}</h4>
                            <p className="text-sm text-slate-700">{item.desc}</p>
                        </div>
                    </li>
                ))}
            </ol>
        </div>
    </div>
);

export default Documentation;
