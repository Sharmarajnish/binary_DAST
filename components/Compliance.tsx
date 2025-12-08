import React, { useState, useEffect, useRef } from 'react';
import {
    Shield, CheckCircle2, AlertTriangle, XCircle, TrendingUp, FileText,
    Download, Eye, ChevronRight, Zap, Award, Target, Lock, Globe,
    Car, Cpu, BarChart3, RefreshCw, Database, Upload, X, Play, Loader2
} from 'lucide-react';

interface ComplianceProps {
    onBack?: () => void;
}

interface Framework {
    id: string;
    name: string;
    fullName: string;
    description: string;
    score: number;
    passed: number;
    failed: number;
    warnings: number;
    status: string;
    lastAssessed: string | null;
}

interface Assessment {
    file: string;
    framework: string;
    score: number;
    issues: number;
    date: string;
    scanId?: string;
}

interface ComplianceData {
    overallScore: number;
    totalScans: number;
    totalFindings: number;
    frameworks: Framework[];
    recentAssessments: Assessment[];
    hasRealData: boolean;
}

// Demo fallback data
const DEMO_FRAMEWORKS: Framework[] = [
    {
        id: 'unece155',
        name: 'UNECE R155',
        fullName: 'UN Regulation No. 155',
        description: 'Cyber Security Management System for Vehicle Approval',
        status: 'compliant',
        score: 94,
        passed: 11,
        failed: 0,
        warnings: 1,
        lastAssessed: '2024-12-07',
    },
    {
        id: 'iso21434',
        name: 'ISO 21434',
        fullName: 'Road Vehicles - Cybersecurity Engineering',
        description: 'Cybersecurity engineering for the entire lifecycle',
        status: 'compliant',
        score: 89,
        passed: 16,
        failed: 0,
        warnings: 2,
        lastAssessed: '2024-12-06',
    },
    {
        id: 'iso26262',
        name: 'ISO 26262',
        fullName: 'Functional Safety for Road Vehicles',
        description: 'Functional safety with ASIL ratings',
        status: 'partial',
        score: 76,
        passed: 18,
        failed: 2,
        warnings: 4,
        lastAssessed: '2024-12-05',
    },
    {
        id: 'misra',
        name: 'MISRA C:2012',
        fullName: 'MISRA C Guidelines 2012',
        description: 'C coding standards for embedded systems',
        status: 'partial',
        score: 82,
        passed: 117,
        failed: 8,
        warnings: 18,
        lastAssessed: '2024-12-07',
    },
    {
        id: 'eucra',
        name: 'EU CRA',
        fullName: 'EU Cyber Resilience Act',
        description: 'European regulation for connected products security',
        status: 'partial',
        score: 71,
        passed: 14,
        failed: 3,
        warnings: 5,
        lastAssessed: '2024-12-08',
    },
];

const DEMO_ASSESSMENTS: Assessment[] = [
    { file: 'engine_ecu.c', framework: 'MISRA C:2012', score: 85, issues: 12, date: '2 hours ago' },
    { file: 'brake_controller.elf', framework: 'ISO 26262', score: 92, issues: 3, date: '1 day ago' },
    { file: 'infotainment.bin', framework: 'UNECE R155', score: 78, issues: 8, date: '3 days ago' },
];

const FRAMEWORK_ICONS: Record<string, React.FC<any>> = {
    unece155: Globe,
    iso21434: Car,
    iso26262: Shield,
    misra: Cpu,
    eucra: Lock,
};

const FRAMEWORK_COLORS: Record<string, string> = {
    unece155: 'cyan',
    iso21434: 'purple',
    iso26262: 'emerald',
    misra: 'amber',
    eucra: 'blue',
};

const API_BASE = 'http://localhost:8000';

const Compliance: React.FC<ComplianceProps> = () => {
    const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [complianceData, setComplianceData] = useState<ComplianceData | null>(null);
    const [isRealData, setIsRealData] = useState(false);

    // Quick Audit state
    const [showAuditModal, setShowAuditModal] = useState(false);
    const [auditFile, setAuditFile] = useState<File | null>(null);
    const [auditFileId, setAuditFileId] = useState<string | null>(null);
    const [auditUploading, setAuditUploading] = useState(false);
    const [auditRunning, setAuditRunning] = useState(false);
    const [auditSuccess, setAuditSuccess] = useState<string | null>(null);
    const [auditError, setAuditError] = useState<string | null>(null);
    const [selectedAuditFrameworks, setSelectedAuditFrameworks] = useState<string[]>(['unece155', 'iso21434', 'iso26262', 'misra']);
    const fileInputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        fetchComplianceData();
    }, []);

    const fetchComplianceData = async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/compliance/summary`);
            if (response.ok) {
                const data = await response.json();
                setComplianceData(data);
                setIsRealData(data.hasRealData);
            } else {
                // Use demo data
                setComplianceData({
                    overallScore: 85,
                    totalScans: 0,
                    totalFindings: 0,
                    frameworks: DEMO_FRAMEWORKS,
                    recentAssessments: DEMO_ASSESSMENTS,
                    hasRealData: false,
                });
                setIsRealData(false);
            }
        } catch (error) {
            // Use demo data on error
            setComplianceData({
                overallScore: 85,
                totalScans: 0,
                totalFindings: 0,
                frameworks: DEMO_FRAMEWORKS,
                recentAssessments: DEMO_ASSESSMENTS,
                hasRealData: false,
            });
            setIsRealData(false);
        }
        setLoading(false);
    };

    const handleAuditFileUpload = async (file: File) => {
        setAuditUploading(true);
        setAuditError(null);
        try {
            const formData = new FormData();
            formData.append('file', file);
            const response = await fetch(`${API_BASE}/scans/upload`, {
                method: 'POST',
                body: formData,
            });
            if (response.ok) {
                const data = await response.json();
                setAuditFileId(data.file_id);
                setAuditFile(file);
            } else {
                const errorData = await response.json().catch(() => ({}));
                setAuditError(errorData.detail || `Upload failed: ${response.status}`);
            }
        } catch (error) {
            console.error('Upload failed:', error);
            setAuditError('Failed to upload file. Please check if backend is running.');
        }
        setAuditUploading(false);
    };

    const handleStartAudit = async () => {
        if (!auditFileId) return;
        setAuditRunning(true);
        setAuditError(null);
        setAuditSuccess(null);
        try {
            const response = await fetch(`${API_BASE}/compliance/audit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_id: auditFileId,
                    frameworks: selectedAuditFrameworks,
                }),
            });
            if (response.ok) {
                const data = await response.json();
                // Show success message and close modal
                setAuditSuccess(`Compliance audit started! Scan ID: ${data.scan_id?.slice(0, 8)}...`);
                setShowAuditModal(false);
                setAuditFile(null);
                setAuditFileId(null);
                // Refresh after a delay to show new scan
                setTimeout(() => {
                    fetchComplianceData();
                    setAuditSuccess(null);
                }, 5000);
            } else {
                const errorData = await response.json().catch(() => ({}));
                setAuditError(errorData.detail || `Server error: ${response.status}`);
            }
        } catch (error) {
            console.error('Audit failed:', error);
            setAuditError('Failed to connect to server. Please check if the backend is running.');
        }
        setAuditRunning(false);
    };

    const toggleAuditFramework = (id: string) => {
        setSelectedAuditFrameworks(prev =>
            prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id]
        );
    };

    const frameworks = complianceData?.frameworks || DEMO_FRAMEWORKS;
    const assessments = complianceData?.recentAssessments?.length
        ? complianceData.recentAssessments
        : DEMO_ASSESSMENTS;
    const overallScore = complianceData?.overallScore || 85;

    return (
        <div className="h-full overflow-y-auto bg-precogs-50/30">
            {/* Success Toast */}
            {auditSuccess && (
                <div className="fixed top-4 right-4 z-50 flex items-center gap-3 px-5 py-3 bg-emerald-500/20 border border-emerald-500/50 rounded-xl text-emerald-400 shadow-lg shadow-emerald-500/10 backdrop-blur animate-pulse">
                    <CheckCircle2 className="w-5 h-5" />
                    <span>{auditSuccess}</span>
                </div>
            )}

            {/* Hero Header with Gradient */}
            <div className="relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-900/30 via-cyan-900/20 to-slate-950" />
                <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMyMjIiIGZpbGwtb3BhY2l0eT0iMC4wNSI+PGNpcmNsZSBjeD0iMzAiIGN5PSIzMCIgcj0iMiIvPjwvZz48L2c+PC9zdmc+')] opacity-50" />

                <div className="relative px-8 py-10">
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="flex items-center gap-3 mb-3">
                                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                    <Shield className="w-6 h-6 text-slate-900" />
                                </div>
                                <div>
                                    <h1 className="text-3xl font-bold text-slate-900">Compliance Center</h1>
                                    <p className="text-slate-600">Automotive Security Standards & Regulations</p>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-4">
                            {/* Data Source Indicator */}
                            <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border ${isRealData
                                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                                }`}>
                                <Database className="w-4 h-4" />
                                <span className="text-xs font-medium">
                                    {isRealData ? 'Live Data' : 'Demo Mode'}
                                </span>
                            </div>

                            <div className="bg-precogs-50 backdrop-blur border border-surface-300 rounded-2xl px-6 py-4">
                                <p className="text-xs text-slate-600 uppercase tracking-wider mb-1">Overall Score</p>
                                <div className="flex items-center gap-3">
                                    <span className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                                        {overallScore}%
                                    </span>
                                    <TrendingUp className="w-5 h-5 text-emerald-400" />
                                </div>
                            </div>

                            <button
                                onClick={fetchComplianceData}
                                className="p-3 bg-precogs-50 hover:bg-surface-200 rounded-xl text-slate-600 hover:text-slate-900 transition-colors"
                            >
                                <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
                            </button>

                            <button className="flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 rounded-xl text-slate-900 font-semibold shadow-lg shadow-cyan-500/20 transition-all">
                                <Download className="w-4 h-4" />
                                Export All Reports
                            </button>
                        </div>
                    </div>

                    {/* Stats Row */}
                    {isRealData && (
                        <div className="flex items-center gap-6 mt-6">
                            <div className="flex items-center gap-2 text-sm text-slate-600">
                                <span className="font-semibold text-slate-900">{complianceData?.totalScans || 0}</span>
                                Scans Completed
                            </div>
                            <div className="flex items-center gap-2 text-sm text-slate-600">
                                <span className="font-semibold text-slate-900">{complianceData?.totalFindings || 0}</span>
                                Total Findings
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Framework Cards */}
            <div className="px-8 py-6">
                <div className="grid grid-cols-2 gap-6">
                    {frameworks.map((fw) => {
                        const Icon = FRAMEWORK_ICONS[fw.id] || Shield;
                        const color = FRAMEWORK_COLORS[fw.id] || 'cyan';

                        return (
                            <div
                                key={fw.id}
                                onClick={() => setSelectedFramework(fw.id)}
                                className={`group relative bg-white backdrop-blur border rounded-2xl p-6 cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:shadow-2xl ${selectedFramework === fw.id
                                    ? 'border-precogs-500 shadow-lg shadow-cyan-500/20'
                                    : 'border-surface-200 hover:border-surface-300'
                                    }`}
                            >
                                {/* Score Ring */}
                                <div className="absolute top-6 right-6">
                                    <div className="relative w-20 h-20">
                                        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                                            <path
                                                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                                                fill="none"
                                                stroke="#1e293b"
                                                strokeWidth="3"
                                            />
                                            <path
                                                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                                                fill="none"
                                                stroke={`url(#gradient-${fw.id})`}
                                                strokeWidth="3"
                                                strokeDasharray={`${fw.score}, 100`}
                                                strokeLinecap="round"
                                            />
                                            <defs>
                                                <linearGradient id={`gradient-${fw.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
                                                    <stop offset="0%" stopColor={color === 'cyan' ? '#06b6d4' : color === 'purple' ? '#a855f7' : color === 'emerald' ? '#10b981' : color === 'blue' ? '#3b82f6' : '#f59e0b'} />
                                                    <stop offset="100%" stopColor={color === 'cyan' ? '#3b82f6' : color === 'purple' ? '#ec4899' : color === 'emerald' ? '#06b6d4' : color === 'blue' ? '#6366f1' : '#ef4444'} />
                                                </linearGradient>
                                            </defs>
                                        </svg>
                                        <div className="absolute inset-0 flex items-center justify-center">
                                            <span className="text-xl font-bold text-slate-900">{fw.score}%</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Header */}
                                <div className="flex items-start gap-4 mb-4">
                                    <div className={`w-14 h-14 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform ${color === 'cyan' ? 'bg-precogs-500/20' :
                                        color === 'purple' ? 'bg-purple-500/20' :
                                            color === 'emerald' ? 'bg-emerald-500/20' :
                                                color === 'blue' ? 'bg-blue-500/20' : 'bg-amber-500/20'
                                        }`}>
                                        <Icon className={`w-7 h-7 ${color === 'cyan' ? 'text-precogs-600' :
                                            color === 'purple' ? 'text-purple-400' :
                                                color === 'emerald' ? 'text-emerald-400' :
                                                    color === 'blue' ? 'text-blue-400' : 'text-amber-400'
                                            }`} />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="text-xl font-bold text-slate-900">{fw.name}</h3>
                                        <p className="text-sm text-slate-600">{fw.fullName}</p>
                                    </div>
                                </div>

                                <p className="text-sm text-slate-600 mb-6 pr-24">{fw.description}</p>

                                {/* Stats Row */}
                                <div className="flex items-center gap-4 mb-4">
                                    <div className="flex items-center gap-2">
                                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                        <span className="text-sm text-slate-700">{fw.passed} passed</span>
                                    </div>
                                    {fw.failed > 0 && (
                                        <div className="flex items-center gap-2">
                                            <XCircle className="w-4 h-4 text-red-400" />
                                            <span className="text-sm text-slate-700">{fw.failed} failed</span>
                                        </div>
                                    )}
                                    {fw.warnings > 0 && (
                                        <div className="flex items-center gap-2">
                                            <AlertTriangle className="w-4 h-4 text-amber-400" />
                                            <span className="text-sm text-slate-700">{fw.warnings} warnings</span>
                                        </div>
                                    )}
                                </div>

                                {/* Footer */}
                                <div className="flex items-center justify-between pt-4 border-t border-surface-200">
                                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${fw.status === 'compliant' ? 'bg-emerald-500/20 text-emerald-400' :
                                        fw.status === 'partial' ? 'bg-amber-500/20 text-amber-400' :
                                            'bg-red-500/20 text-red-400'
                                        }`}>
                                        {fw.status === 'compliant' ? '✓ Compliant' :
                                            fw.status === 'partial' ? '⚠ Partial' :
                                                fw.status === 'not-assessed' ? '○ Not Assessed' : '✗ Non-Compliant'}
                                    </span>
                                    <button className="flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900 transition-colors">
                                        View Details <ChevronRight className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Recent Assessments & Quick Actions */}
            <div className="px-8 py-6 grid grid-cols-3 gap-6">
                {/* Recent Assessments */}
                <div className="col-span-2 bg-white border border-surface-200 rounded-2xl p-6">
                    <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                        <BarChart3 className="w-5 h-5 text-precogs-600" />
                        Recent Compliance Assessments
                        {!isRealData && (
                            <span className="ml-2 px-2 py-0.5 bg-amber-500/20 text-amber-400 text-xs rounded-full">Demo</span>
                        )}
                    </h3>

                    <div className="space-y-3">
                        {assessments.map((assessment, i) => (
                            <div
                                key={i}
                                className="flex items-center justify-between p-4 bg-precogs-50/30 rounded-xl hover:bg-precogs-50 transition-colors cursor-pointer"
                            >
                                <div className="flex items-center gap-4">
                                    <div className="w-10 h-10 rounded-lg bg-slate-700 flex items-center justify-center">
                                        <FileText className="w-5 h-5 text-slate-600" />
                                    </div>
                                    <div>
                                        <p className="font-medium text-slate-900">{assessment.file}</p>
                                        <p className="text-xs text-slate-600">{assessment.framework} • {assessment.date}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-4">
                                    <div className="text-right">
                                        <p className={`text-lg font-bold ${assessment.score >= 90 ? 'text-emerald-400' :
                                            assessment.score >= 70 ? 'text-amber-400' : 'text-red-400'
                                            }`}>{assessment.score}%</p>
                                        <p className="text-xs text-slate-600">{assessment.issues} issues</p>
                                    </div>
                                    <Eye className="w-5 h-5 text-slate-600 hover:text-slate-900 transition-colors" />
                                </div>
                            </div>
                        ))}
                    </div>

                    {!isRealData && (
                        <p className="text-xs text-slate-600 mt-4 text-center">
                            Run a scan to see real compliance data here
                        </p>
                    )}
                </div>

                {/* Quick Actions */}
                <div className="space-y-4">
                    <div className="bg-gradient-to-br from-cyan-50 to-purple-50 border border-cyan-200 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-10 h-10 rounded-xl bg-precogs-500/20 flex items-center justify-center">
                                <Zap className="w-5 h-5 text-precogs-600" />
                            </div>
                            <div>
                                <h4 className="font-semibold text-slate-900">Quick Audit</h4>
                                <p className="text-xs text-slate-600">Run compliance check</p>
                            </div>
                        </div>
                        <button
                            onClick={() => setShowAuditModal(true)}
                            className="w-full py-2.5 bg-gradient-to-r from-cyan-600 to-precogs-600 hover:from-cyan-500 hover:to-precogs-500 rounded-lg text-white font-medium text-sm transition-all shadow-lg shadow-cyan-500/20"
                        >
                            Start Audit
                        </button>
                    </div>

                    <div className="bg-white border border-surface-200 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-10 h-10 rounded-xl bg-purple-500/20 flex items-center justify-center">
                                <Award className="w-5 h-5 text-purple-400" />
                            </div>
                            <div>
                                <h4 className="font-semibold text-slate-900">Certifications</h4>
                                <p className="text-xs text-slate-600">3 active certificates</p>
                            </div>
                        </div>
                        <button className="w-full py-2.5 bg-precogs-50 hover:bg-surface-200 rounded-lg text-slate-700 font-medium text-sm transition-colors">
                            View Certificates
                        </button>
                    </div>

                    <div className="bg-white border border-surface-200 rounded-2xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                                <Target className="w-5 h-5 text-emerald-400" />
                            </div>
                            <div>
                                <h4 className="font-semibold text-slate-900">TARA Integration</h4>
                                <p className="text-xs text-slate-600">Link to threat analysis</p>
                            </div>
                        </div>
                        <button className="w-full py-2.5 bg-precogs-50 hover:bg-surface-200 rounded-lg text-slate-700 font-medium text-sm transition-colors">
                            Configure TARA
                        </button>
                    </div>
                </div>
            </div>

            {/* Quick Audit Modal */}
            {showAuditModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
                    <div className="bg-white border border-surface-300 rounded-2xl p-6 w-full max-w-lg shadow-2xl">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-xl font-bold text-slate-900">Quick Compliance Audit</h3>
                            <button
                                onClick={() => { setShowAuditModal(false); setAuditFile(null); setAuditFileId(null); }}
                                className="text-slate-600 hover:text-slate-900"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        {/* File Upload */}
                        <div className="mb-6">
                            <label className="block text-sm text-slate-600 mb-2">Upload Binary/Source</label>
                            <input
                                ref={fileInputRef}
                                type="file"
                                className="hidden"
                                accept=".c,.h,.elf,.bin,.vbf,.hex,.s19"
                                onChange={(e) => e.target.files && handleAuditFileUpload(e.target.files[0])}
                            />
                            <div
                                onClick={() => fileInputRef.current?.click()}
                                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${auditFile ? 'border-precogs-500 bg-precogs-500/10' : 'border-surface-300 hover:border-surface-400'
                                    }`}
                            >
                                {auditUploading ? (
                                    <Loader2 className="w-8 h-8 text-precogs-600 mx-auto animate-spin" />
                                ) : auditFile ? (
                                    <div className="flex items-center justify-center gap-2 text-precogs-600">
                                        <CheckCircle2 className="w-5 h-5" />
                                        <span>{auditFile.name}</span>
                                    </div>
                                ) : (
                                    <>
                                        <Upload className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                                        <p className="text-slate-600 text-sm">Click to upload or drag file</p>
                                        <p className="text-slate-600 text-xs mt-1">.c, .elf, .bin, .vbf, .hex supported</p>
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Framework Selection */}
                        <div className="mb-6">
                            <label className="block text-sm text-slate-600 mb-2">Select Frameworks</label>
                            <div className="grid grid-cols-2 gap-2">
                                {[
                                    { id: 'unece155', name: 'UNECE R155', activeClass: 'bg-cyan-500/20 text-cyan-600 border-cyan-500/50' },
                                    { id: 'iso21434', name: 'ISO 21434', activeClass: 'bg-purple-500/20 text-purple-600 border-purple-500/50' },
                                    { id: 'iso26262', name: 'ISO 26262', activeClass: 'bg-emerald-500/20 text-emerald-600 border-emerald-500/50' },
                                    { id: 'misra', name: 'MISRA C', activeClass: 'bg-amber-500/20 text-amber-600 border-amber-500/50' },
                                    { id: 'eucra', name: 'EU CRA', activeClass: 'bg-blue-500/20 text-blue-600 border-blue-500/50' },
                                ].map((fw) => (
                                    <button
                                        key={fw.id}
                                        onClick={() => toggleAuditFramework(fw.id)}
                                        className={`px-3 py-2 rounded-lg text-sm font-medium transition-all border ${selectedAuditFrameworks.includes(fw.id)
                                            ? fw.activeClass
                                            : 'bg-precogs-50 text-slate-600 border-surface-300 hover:border-slate-400'
                                            }`}
                                    >
                                        {fw.name}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Error/Success Messages */}
                        {auditError && (
                            <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 text-sm">
                                {auditError}
                            </div>
                        )}

                        {/* Start Button */}
                        <button
                            onClick={handleStartAudit}
                            disabled={!auditFileId || auditRunning || selectedAuditFrameworks.length === 0}
                            className={`w-full py-3 rounded-xl font-semibold flex items-center justify-center gap-2 transition-all ${auditFileId && !auditRunning && selectedAuditFrameworks.length > 0
                                ? 'bg-gradient-to-r from-cyan-600 to-purple-600 text-white hover:from-cyan-500 hover:to-purple-500 shadow-lg'
                                : 'bg-slate-200 text-slate-500 cursor-not-allowed'
                                }`}
                        >
                            {auditRunning ? (
                                <><Loader2 className="w-5 h-5 animate-spin" /> Running Audit...</>
                            ) : (
                                <><Play className="w-5 h-5" /> Start Compliance Audit</>
                            )}
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Compliance;
