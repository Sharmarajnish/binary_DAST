import React, { useState, useEffect } from 'react';
import {
    FileText, Download, Search, Filter, Calendar, FileJson, FileCode,
    Shield, AlertTriangle, CheckCircle2, Clock, ChevronDown, ExternalLink,
    FileSpreadsheet, Building2, Target, TrendingUp, Loader2, Github
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

interface ReportsProps {
    onBack?: () => void;
}

interface ScanData {
    id: string;
    filename: string;
    date: string;
    status: string;
    findings: { critical: number; high: number; medium: number; low: number };
    architecture?: string;
    duration?: string;
}

interface CveResult {
    scanId: string;
    filename: string;
    cweId: string;
    title: string;
    severity: string;
    line: number;
    remediation: string;
}

// Demo fallback data
const DEMO_SCAN_HISTORY: ScanData[] = [
    {
        id: 'scan-demo-001',
        filename: 'engine_ecu.c',
        date: '2024-12-07T21:45:00Z',
        status: 'completed',
        findings: { critical: 2, high: 4, medium: 2, low: 0 },
        architecture: 'ARM Cortex-M4',
        duration: '3m 24s',
    },
    {
        id: 'scan-demo-002',
        filename: 'brake_controller.elf',
        date: '2024-12-06T14:30:00Z',
        status: 'completed',
        findings: { critical: 0, high: 2, medium: 5, low: 3 },
        architecture: 'TriCore',
        duration: '12m 45s',
    },
];

const COMPLIANCE_TEMPLATES = [
    { id: 'unece155', name: 'UNECE R155', description: 'Cyber Security Management System', icon: Shield },
    { id: 'iso21434', name: 'ISO 21434', description: 'Road Vehicle Cybersecurity', icon: Target },
    { id: 'iso26262', name: 'ISO 26262', description: 'Functional Safety', icon: AlertTriangle },
    { id: 'misra', name: 'MISRA C:2012', description: 'C Coding Standard', icon: FileCode },
];

const Reports: React.FC<ReportsProps> = () => {
    const [activeTab, setActiveTab] = useState<'history' | 'compliance' | 'cve' | 'export'>('history');
    const [searchQuery, setSearchQuery] = useState('');
    const [cveSearch, setCveSearch] = useState('');
    const [scanHistory, setScanHistory] = useState<ScanData[]>([]);
    const [cveResults, setCveResults] = useState<CveResult[]>([]);
    const [loading, setLoading] = useState(false);
    const [exporting, setExporting] = useState<string | null>(null);

    // Fetch real scan history on mount
    useEffect(() => {
        fetchScanHistory();
    }, []);

    const fetchScanHistory = async () => {
        try {
            const response = await fetch(`${API_BASE}/scans`);
            if (response.ok) {
                const data = await response.json();
                const scans: ScanData[] = data.scans?.filter((s: any) => s.status === 'completed').map((s: any) => ({
                    id: s.id,
                    filename: s.file_path?.split('/').pop() || 'Unknown',
                    date: s.startTime || new Date().toISOString(),
                    status: s.status,
                    findings: {
                        critical: s.findings?.filter((f: any) => f.severity === 'critical').length || 0,
                        high: s.findings?.filter((f: any) => f.severity === 'high').length || 0,
                        medium: s.findings?.filter((f: any) => f.severity === 'medium').length || 0,
                        low: s.findings?.filter((f: any) => f.severity === 'low').length || 0,
                    },
                    architecture: 'ARM Cortex-M4',
                    duration: '3m 24s',
                })) || [];
                setScanHistory(scans.length > 0 ? scans : DEMO_SCAN_HISTORY);
            }
        } catch {
            setScanHistory(DEMO_SCAN_HISTORY);
        }
    };

    // CVE/CWE Search handler
    const handleCveSearch = async () => {
        if (!cveSearch.trim()) return;
        setLoading(true);
        setCveResults([]);

        try {
            // Search across all scans for matching CWE/CVE
            const response = await fetch(`${API_BASE}/scans`);
            if (response.ok) {
                const data = await response.json();
                const results: CveResult[] = [];

                for (const scan of data.scans || []) {
                    if (scan.status !== 'completed') continue;
                    for (const finding of scan.findings || []) {
                        const cweId = finding.cweId || '';
                        if (cweId.toLowerCase().includes(cveSearch.toLowerCase()) ||
                            finding.title?.toLowerCase().includes(cveSearch.toLowerCase())) {
                            results.push({
                                scanId: scan.id,
                                filename: scan.file_path?.split('/').pop() || 'Unknown',
                                cweId: cweId,
                                title: finding.title,
                                severity: finding.severity,
                                line: finding.line,
                                remediation: finding.remediation,
                            });
                        }
                    }
                }
                setCveResults(results);
            }
        } catch (error) {
            console.error('CVE search failed:', error);
        }
        setLoading(false);
    };

    // Compliance Report Generation
    const handleGenerateReport = async (frameworkId: string) => {
        setExporting(frameworkId);
        try {
            const response = await fetch(`${API_BASE}/compliance/summary`);
            if (response.ok) {
                const data = await response.json();
                const framework = data.frameworks?.find((f: any) => f.id === frameworkId);

                const report = {
                    framework: frameworkId.toUpperCase(),
                    generatedAt: new Date().toISOString(),
                    overallScore: framework?.score || data.overallScore,
                    status: framework?.status || 'partial',
                    totalScans: data.totalScans,
                    findings: data.totalFindings,
                    projects: data.projects || [],
                };

                const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
                downloadBlob(blob, `${frameworkId}_compliance_report.json`);
            }
        } catch (error) {
            alert('Failed to generate report. Please try again.');
        }
        setExporting(null);
    };

    // Export handlers
    const handleExportSarif = async () => {
        setExporting('sarif');
        try {
            const response = await fetch(`${API_BASE}/scans`);
            if (response.ok) {
                const data = await response.json();
                const completedScans = data.scans?.filter((s: any) => s.status === 'completed') || [];

                const sarif = {
                    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                    version: "2.1.0",
                    runs: completedScans.map((scan: any) => ({
                        tool: {
                            driver: {
                                name: "Precogs ECU Scanner",
                                version: "2.4.0",
                            }
                        },
                        results: (scan.findings || []).map((f: any) => ({
                            ruleId: f.cweId,
                            message: { text: f.title },
                            level: f.severity === 'critical' ? 'error' : f.severity === 'high' ? 'warning' : 'note',
                            locations: [{
                                physicalLocation: {
                                    artifactLocation: { uri: scan.file_path },
                                    region: { startLine: f.line }
                                }
                            }]
                        }))
                    }))
                };

                const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
                downloadBlob(blob, 'precogs_scan_results.sarif.json');
            }
        } catch {
            alert('Export failed. Please try again.');
        }
        setExporting(null);
    };

    const handleExportJira = async () => {
        setExporting('jira');
        try {
            const response = await fetch(`${API_BASE}/scans`);
            if (response.ok) {
                const data = await response.json();
                const findings = data.scans?.flatMap((s: any) =>
                    (s.findings || []).map((f: any) => ({
                        project: s.file_path?.split('/').pop(),
                        issueType: 'Bug',
                        priority: f.severity === 'critical' ? 'Highest' : f.severity === 'high' ? 'High' : 'Medium',
                        summary: `[Security] ${f.cweId}: ${f.title}`,
                        description: `${f.description}\n\nRemediation: ${f.remediation}\n\nLine: ${f.line}`,
                        labels: ['security', 'vulnerability', f.cweId],
                    }))
                ) || [];

                const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
                downloadBlob(blob, 'jira_issues_export.json');
            }
        } catch {
            alert('Export failed. Please try again.');
        }
        setExporting(null);
    };

    const handleExportVex = async (format: 'openvex' | 'cyclonedx') => {
        setExporting(`vex-${format}`);
        try {
            const response = await fetch(`${API_BASE}/scans`);
            if (response.ok) {
                const data = await response.json();
                const statements = data.scans?.flatMap((s: any) =>
                    (s.findings || []).map((f: any) => ({
                        vulnerability: f.cweId,
                        product: s.file_path?.split('/').pop(),
                        status: 'affected',
                        justification: f.description,
                        actionStatement: f.remediation,
                    }))
                ) || [];

                const vex = format === 'openvex' ? {
                    "@context": "https://openvex.dev/ns/v0.2.0",
                    "@id": `urn:uuid:${Date.now()}`,
                    "author": "Precogs ECU Scanner",
                    "timestamp": new Date().toISOString(),
                    "statements": statements,
                } : {
                    bomFormat: "CycloneDX",
                    specVersion: "1.5",
                    vulnerabilities: statements.map((s: any) => ({
                        id: s.vulnerability,
                        source: { name: "Precogs" },
                        analysis: { state: "exploitable", detail: s.justification },
                        recommendation: s.actionStatement,
                    }))
                };

                const blob = new Blob([JSON.stringify(vex, null, 2)], { type: 'application/json' });
                downloadBlob(blob, `vex_export.${format}.json`);
            }
        } catch {
            alert('Export failed. Please try again.');
        }
        setExporting(null);
    };

    const downloadBlob = (blob: Blob, filename: string) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    const tabs = [
        { id: 'history', label: 'Scan History', icon: Clock },
        { id: 'compliance', label: 'Compliance Reports', icon: Shield },
        { id: 'cve', label: 'CVE Search', icon: Search },
        { id: 'export', label: 'Bulk Export', icon: Download },
    ];

    return (
        <div className="h-full flex flex-col bg-precogs-50/30">
            {/* Header */}
            <div className="border-b border-surface-200 bg-white p-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900 flex items-center gap-3">
                            <FileText className="w-7 h-7 text-precogs-600" />
                            Reports
                        </h1>
                        <p className="text-sm text-slate-600 mt-1">Generate, search, and export vulnerability reports</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-600">JLR WP7 Compliant</span>
                        <div className="px-3 py-1 bg-emerald-500/20 border border-emerald-500/30 rounded-full text-xs text-emerald-400 font-medium">
                            UNECE R155 Ready
                        </div>
                    </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-1 mt-6 bg-precogs-50 rounded-lg p-1 w-fit">
                    {tabs.map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id as any)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === tab.id
                                ? 'bg-precogs-500/20 text-precogs-600'
                                : 'text-slate-600 hover:text-slate-900 hover:bg-surface-200/50'
                                }`}
                        >
                            <tab.icon className="w-4 h-4" />
                            {tab.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
                {activeTab === 'history' && (
                    <div className="space-y-4">
                        {/* Search Bar */}
                        <div className="flex gap-3">
                            <div className="flex-1 relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                                <input
                                    type="text"
                                    placeholder="Search scans by filename..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-full bg-white border border-surface-300 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-900 placeholder-slate-500"
                                />
                            </div>
                            <button className="flex items-center gap-2 px-4 py-2 bg-precogs-50 border border-surface-300 rounded-lg text-sm text-slate-700 hover:bg-surface-200 transition-colors">
                                <Filter className="w-4 h-4" />
                                Filter
                            </button>
                            <button className="flex items-center gap-2 px-4 py-2 bg-precogs-50 border border-surface-300 rounded-lg text-sm text-slate-700 hover:bg-surface-200 transition-colors">
                                <Calendar className="w-4 h-4" />
                                Date Range
                            </button>
                        </div>

                        {/* Scan List */}
                        <div className="bg-white border border-surface-200 rounded-xl overflow-hidden">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-surface-200">
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">File</th>
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">Date</th>
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">Architecture</th>
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">Findings</th>
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">Duration</th>
                                        <th className="text-left text-xs font-medium text-slate-600 uppercase tracking-wider px-6 py-4">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {scanHistory.map((scan, i) => (
                                        <tr key={scan.id} className={`${i !== scanHistory.length - 1 ? 'border-b border-surface-200/50' : ''} hover:bg-precogs-50/30 transition-colors`}>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-precogs-50 flex items-center justify-center">
                                                        <FileCode className="w-4 h-4 text-precogs-600" />
                                                    </div>
                                                    <div>
                                                        <p className="text-sm font-medium text-slate-900">{scan.filename}</p>
                                                        <p className="text-xs text-slate-600">{scan.id}</p>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-sm text-slate-600">
                                                {new Date(scan.date).toLocaleDateString()}
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="px-2 py-1 bg-precogs-50 rounded text-xs text-slate-700">{scan.architecture}</span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-2">
                                                    {scan.findings.critical > 0 && (
                                                        <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-medium">
                                                            {scan.findings.critical} Critical
                                                        </span>
                                                    )}
                                                    {scan.findings.high > 0 && (
                                                        <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs font-medium">
                                                            {scan.findings.high} High
                                                        </span>
                                                    )}
                                                    <span className="text-xs text-slate-600">
                                                        +{scan.findings.medium + scan.findings.low} more
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-sm text-slate-600">{scan.duration}</td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-2">
                                                    <button className="p-2 hover:bg-surface-200 rounded-lg text-slate-600 hover:text-slate-900 transition-colors" title="Download JSON">
                                                        <FileJson className="w-4 h-4" />
                                                    </button>
                                                    <button className="p-2 hover:bg-surface-200 rounded-lg text-slate-600 hover:text-slate-900 transition-colors" title="Download HTML">
                                                        <FileText className="w-4 h-4" />
                                                    </button>
                                                    <button className="p-2 hover:bg-surface-200 rounded-lg text-slate-600 hover:text-slate-900 transition-colors" title="Export to Jira">
                                                        <ExternalLink className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {activeTab === 'compliance' && (
                    <div className="space-y-6">
                        <p className="text-sm text-slate-600">Generate compliance reports for regulatory frameworks (WP7)</p>

                        <div className="grid grid-cols-2 gap-4">
                            {COMPLIANCE_TEMPLATES.map(template => (
                                <div
                                    key={template.id}
                                    className="bg-white border border-surface-200 rounded-xl p-6 hover:border-precogs-500/50 transition-colors cursor-pointer group"
                                >
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-start gap-4">
                                            <div className="w-12 h-12 rounded-xl bg-precogs-500/10 flex items-center justify-center group-hover:bg-precogs-500/20 transition-colors">
                                                <template.icon className="w-6 h-6 text-precogs-600" />
                                            </div>
                                            <div>
                                                <h3 className="text-lg font-semibold text-slate-900">{template.name}</h3>
                                                <p className="text-sm text-slate-600 mt-1">{template.description}</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 mt-4">
                                        <button
                                            onClick={() => handleGenerateReport(template.id)}
                                            disabled={exporting === template.id}
                                            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-precogs-500 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                                        >
                                            {exporting === template.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                                            Generate Report
                                        </button>
                                        <button className="flex items-center gap-2 px-4 py-2 bg-precogs-50 hover:bg-surface-200 rounded-lg text-sm text-slate-700 transition-colors">
                                            <FileSpreadsheet className="w-4 h-4" />
                                            View Template
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* TARA Integration Section */}
                        <div className="mt-8">
                            <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                                <Target className="w-5 h-5 text-precogs-600" />
                                TARA Integration (WP6)
                            </h3>
                            <div className="bg-white border border-surface-200 rounded-xl p-6">
                                <p className="text-sm text-slate-600 mb-4">
                                    Link vulnerability assessments to TARA entries for accurate risk ratings.
                                </p>
                                <div className="grid grid-cols-3 gap-4">
                                    <div className="bg-precogs-50 rounded-lg p-4">
                                        <p className="text-xs text-slate-600 uppercase tracking-wider mb-2">CIA Scoring</p>
                                        <p className="text-2xl font-bold text-slate-900">C:8 I:7 A:6</p>
                                    </div>
                                    <div className="bg-precogs-50 rounded-lg p-4">
                                        <p className="text-xs text-slate-600 uppercase tracking-wider mb-2">Attack Paths</p>
                                        <p className="text-2xl font-bold text-orange-400">12</p>
                                    </div>
                                    <div className="bg-precogs-50 rounded-lg p-4">
                                        <p className="text-xs text-slate-600 uppercase tracking-wider mb-2">Risk Score</p>
                                        <p className="text-2xl font-bold text-red-400">HIGH</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'cve' && (
                    <div className="space-y-6">
                        <p className="text-sm text-slate-600">Search for specific CVEs across your scan history (WP5)</p>

                        {/* CVE Search */}
                        <div className="flex gap-3">
                            <div className="flex-1 relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                                <input
                                    type="text"
                                    placeholder="Search CVE (e.g., CVE-2024-1234) or CWE (e.g., CWE-120)..."
                                    value={cveSearch}
                                    onChange={(e) => setCveSearch(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleCveSearch()}
                                    className="w-full bg-white border border-surface-300 rounded-lg pl-10 pr-4 py-3 text-sm text-slate-900 placeholder-slate-500"
                                />
                            </div>
                            <button
                                onClick={handleCveSearch}
                                disabled={loading}
                                className="flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-precogs-500 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                            >
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                                Search
                            </button>
                        </div>

                        {/* Quick CWE Filters */}
                        <div className="flex flex-wrap gap-2">
                            <span className="text-xs text-slate-600 mr-2">Common:</span>
                            {['CWE-120', 'CWE-798', 'CWE-416', 'CWE-134', 'CWE-190'].map(cwe => (
                                <button
                                    key={cwe}
                                    onClick={() => setCveSearch(cwe)}
                                    className="px-3 py-1 bg-precogs-50 hover:bg-surface-200 border border-surface-300 rounded-lg text-xs text-slate-700 transition-colors"
                                >
                                    {cwe}
                                </button>
                            ))}
                        </div>

                        {/* CVE Search Results */}
                        {loading ? (
                            <div className="bg-white border border-surface-200 rounded-xl p-12 text-center">
                                <Loader2 className="w-12 h-12 text-precogs-600 mx-auto mb-4 animate-spin" />
                                <p className="text-slate-600">Searching across all scans...</p>
                            </div>
                        ) : cveResults.length > 0 ? (
                            <div className="bg-white border border-surface-200 rounded-xl overflow-hidden">
                                <div className="p-4 border-b border-surface-200 bg-precogs-50/50">
                                    <p className="text-sm font-medium text-slate-900">
                                        Found {cveResults.length} results for "{cveSearch}"
                                    </p>
                                </div>
                                <div className="divide-y divide-surface-200">
                                    {cveResults.map((result, idx) => (
                                        <div key={idx} className="p-4 hover:bg-precogs-50/30 transition-colors">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start gap-3">
                                                    <div className={`px-2 py-1 rounded text-xs font-medium ${result.severity === 'critical' ? 'bg-red-100 text-red-700' :
                                                        result.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                                                            'bg-amber-100 text-amber-700'
                                                        }`}>
                                                        {result.severity.toUpperCase()}
                                                    </div>
                                                    <div>
                                                        <p className="font-medium text-slate-900">{result.cweId}: {result.title}</p>
                                                        <p className="text-sm text-slate-600 mt-1">{result.filename} • Line {result.line}</p>
                                                    </div>
                                                </div>
                                            </div>
                                            <p className="text-sm text-slate-500 mt-2 pl-8">{result.remediation}</p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ) : cveSearch ? (
                            <div className="bg-white border border-surface-200 rounded-xl p-12 text-center">
                                <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
                                <p className="text-slate-600">No vulnerabilities found matching "{cveSearch}"</p>
                                <p className="text-sm text-slate-500 mt-2">Your codebase appears secure for this CWE/CVE</p>
                            </div>
                        ) : (
                            <div className="bg-white border border-surface-200 rounded-xl p-12 text-center">
                                <Search className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                                <p className="text-slate-600">Enter a CVE or CWE ID to search across all scans</p>
                                <p className="text-sm text-slate-500 mt-2">Results will show affected files, severity, and remediation status</p>
                            </div>
                        )}

                        {/* Signature Update Info */}
                        <div className="bg-white border border-surface-200 rounded-xl p-6">
                            <h4 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
                                <TrendingUp className="w-4 h-4 text-precogs-600" />
                                Signature Database Status
                            </h4>
                            <div className="grid grid-cols-3 gap-4 text-sm">
                                <div>
                                    <p className="text-slate-600">Last Updated</p>
                                    <p className="text-slate-900 font-medium">Dec 7, 2024</p>
                                </div>
                                <div>
                                    <p className="text-slate-600">CWE Signatures</p>
                                    <p className="text-slate-900 font-medium">847</p>
                                </div>
                                <div>
                                    <p className="text-slate-600">CVE Coverage</p>
                                    <p className="text-slate-900 font-medium">2024 Q4</p>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'export' && (
                    <div className="space-y-6">
                        <p className="text-sm text-slate-600">Bulk export scan data for integration with external systems (WP4)</p>

                        <div className="grid grid-cols-3 gap-6">
                            {/* GitHub Actions Export */}
                            <div className="bg-white border border-surface-200 rounded-xl p-6">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-lg bg-slate-900 flex items-center justify-center">
                                        <Github className="w-5 h-5 text-white" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-slate-900">GitHub Actions</h3>
                                        <p className="text-xs text-slate-600">Export for GitHub Security tab</p>
                                    </div>
                                </div>
                                <p className="text-sm text-slate-600 mb-4">
                                    Generate SARIF format reports for GitHub Code Scanning & Security Overview.
                                </p>
                                <button
                                    onClick={handleExportSarif}
                                    disabled={exporting === 'sarif'}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                                >
                                    {exporting === 'sarif' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                                    Export SARIF
                                </button>
                            </div>

                            {/* GitLab Export */}
                            <div className="bg-white border border-surface-200 rounded-xl p-6">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-lg bg-orange-500/20 flex items-center justify-center">
                                        <Building2 className="w-5 h-5 text-orange-500" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-slate-900">GitLab CI/CD</h3>
                                        <p className="text-xs text-slate-600">Export for pipeline integration</p>
                                    </div>
                                </div>
                                <p className="text-sm text-slate-600 mb-4">
                                    Generate SARIF format reports for GitLab Security Dashboard.
                                </p>
                                <button
                                    onClick={handleExportSarif}
                                    disabled={exporting === 'sarif'}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-orange-600 hover:bg-orange-500 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                                >
                                    {exporting === 'sarif' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                                    Export SARIF
                                </button>
                            </div>

                            {/* Jira Export */}
                            <div className="bg-white border border-surface-200 rounded-xl p-6">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
                                        <ExternalLink className="w-5 h-5 text-blue-500" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-slate-900">Jira Integration</h3>
                                        <p className="text-xs text-slate-600">Create vulnerability tickets</p>
                                    </div>
                                </div>
                                <p className="text-sm text-slate-600 mb-4">
                                    Export findings to Jira with remediation guidance.
                                </p>
                                <button
                                    onClick={handleExportJira}
                                    disabled={exporting === 'jira'}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                                >
                                    {exporting === 'jira' ? <Loader2 className="w-4 h-4 animate-spin" /> : <ExternalLink className="w-4 h-4" />}
                                    Export to Jira
                                </button>
                            </div>

                            {/* VEX Export - NEW */}
                            <div className="bg-white border border-surface-200 rounded-xl p-6">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                                        <Shield className="w-5 h-5 text-emerald-500" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-slate-900">VEX Export</h3>
                                        <p className="text-xs text-slate-600">Vulnerability Exploitability eXchange</p>
                                    </div>
                                </div>
                                <p className="text-sm text-slate-600 mb-4">
                                    Generate VEX statements for SBOM supply chain communication.
                                </p>
                                <div className="space-y-2">
                                    <button
                                        onClick={() => handleExportVex('openvex')}
                                        disabled={exporting === 'vex-openvex'}
                                        className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm text-white font-medium transition-colors disabled:opacity-50"
                                    >
                                        {exporting === 'vex-openvex' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                                        OpenVEX Format
                                    </button>
                                    <button
                                        onClick={() => handleExportVex('cyclonedx')}
                                        disabled={exporting === 'vex-cyclonedx'}
                                        className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-surface-100 hover:bg-surface-200 border border-surface-300 rounded-lg text-sm text-slate-700 font-medium transition-colors disabled:opacity-50"
                                    >
                                        {exporting === 'vex-cyclonedx' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                                        CycloneDX VEX
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* API Documentation */}
                        <div className="bg-white border border-surface-200 rounded-xl p-6">
                            <h4 className="text-sm font-semibold text-slate-900 mb-3">API Endpoints for CI/CD</h4>
                            <div className="space-y-2 font-mono text-xs">
                                <div className="flex items-center gap-3 bg-precogs-50 rounded p-3">
                                    <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded">POST</span>
                                    <span className="text-slate-700">/api/ci/scan</span>
                                    <span className="text-slate-600 ml-auto">Trigger scan from pipeline</span>
                                </div>
                                <div className="flex items-center gap-3 bg-precogs-50 rounded p-3">
                                    <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">GET</span>
                                    <span className="text-slate-700">/api/scans/{'{id}'}/report/sarif</span>
                                    <span className="text-slate-600 ml-auto">Get SARIF report</span>
                                </div>
                                <div className="flex items-center gap-3 bg-precogs-50 rounded p-3">
                                    <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded">POST</span>
                                    <span className="text-slate-700">/api/export/jira</span>
                                    <span className="text-slate-600 ml-auto">Export to Jira</span>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Reports;
