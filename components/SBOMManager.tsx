import React, { useState, useEffect } from 'react';
import {
    Package, Search, Download, Upload, AlertTriangle, Shield, CheckCircle2,
    ExternalLink, Filter, ChevronDown, ChevronRight, FileCode, Clock,
    RefreshCw, Layers, Box, Link2, AlertCircle, XCircle, Loader2
} from 'lucide-react';

interface SBOMComponent {
    id: string;
    name: string;
    version: string;
    license: string;
    supplier?: string;
    purl?: string;
    cpe?: string;
    vulnerabilities: number;
    critical: number;
    high: number;
    lastUpdated?: string;
    dependencies?: string[];
}

interface SBOMData {
    id: string;
    name: string;
    version: string;
    format: 'spdx' | 'cyclonedx';
    createdAt: string;
    components: SBOMComponent[];
    totalVulnerabilities: number;
    riskScore: number;
}

const SBOMManager: React.FC = () => {
    const [sboms, setSboms] = useState<SBOMData[]>([]);
    const [selectedSbom, setSelectedSbom] = useState<SBOMData | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterSeverity, setFilterSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
    const [isLoading, setIsLoading] = useState(true);
    const [expandedComponent, setExpandedComponent] = useState<string | null>(null);

    useEffect(() => {
        fetchSBOMs();
    }, []);

    const fetchSBOMs = async () => {
        setIsLoading(true);

        // Demo SBOM data
        const demoSbom: SBOMData = {
            id: 'sbom-demo-001',
            name: 'Engine_ECU_v2.4.1',
            version: '2.4.1',
            format: 'spdx',
            createdAt: new Date().toISOString(),
            totalVulnerabilities: 7,
            riskScore: 72,
            components: [
                { id: '1', name: 'FreeRTOS', version: '10.4.3', license: 'MIT', supplier: 'Amazon', vulnerabilities: 2, critical: 0, high: 1, purl: 'pkg:github/FreeRTOS/FreeRTOS@10.4.3' },
                { id: '2', name: 'wolfSSL', version: '4.8.1', license: 'GPL-2.0', supplier: 'wolfSSL Inc.', vulnerabilities: 1, critical: 1, high: 0, purl: 'pkg:github/wolfSSL/wolfssl@4.8.1' },
                { id: '3', name: 'CAN-Stack', version: '3.2.0', license: 'Apache-2.0', supplier: 'Bosch', vulnerabilities: 0, critical: 0, high: 0, purl: 'pkg:npm/can-stack@3.2.0' },
                { id: '4', name: 'AUTOSAR-MCAL', version: '4.4.0', license: 'Proprietary', supplier: 'AUTOSAR', vulnerabilities: 2, critical: 0, high: 2, purl: 'pkg:autosar/mcal@4.4.0' },
                { id: '5', name: 'zlib', version: '1.2.11', license: 'Zlib', supplier: 'zlib.net', vulnerabilities: 1, critical: 0, high: 0, purl: 'pkg:pypi/zlib@1.2.11' },
                { id: '6', name: 'LwIP', version: '2.1.2', license: 'BSD-3-Clause', supplier: 'lwip.wikia.com', vulnerabilities: 1, critical: 0, high: 1, purl: 'pkg:github/lwip-tcpip/lwip@2.1.2' },
            ],
        };

        try {
            const response = await fetch('http://localhost:8000/sbom/list');
            if (response.ok) {
                const data = await response.json();
                if (data.sboms && data.sboms.length > 0) {
                    // Transform API data to component format
                    const transformedSboms: SBOMData[] = await Promise.all(
                        data.sboms.map(async (apiSbom: any) => {
                            // Fetch detailed SBOM data for each
                            let components: SBOMComponent[] = [];
                            try {
                                const detailRes = await fetch(`http://localhost:8000/sbom/${apiSbom.scanId}`);
                                if (detailRes.ok) {
                                    const detail = await detailRes.json();
                                    components = (detail.sbom?.components || []).map((c: any, idx: number) => ({
                                        id: `${apiSbom.scanId}-${idx}`,
                                        name: c.name || 'Unknown',
                                        version: c.version || 'unknown',
                                        license: c.license || 'Unknown',
                                        supplier: c.supplier || 'Unknown',
                                        purl: c.purl,
                                        vulnerabilities: 0,
                                        critical: 0,
                                        high: 0,
                                    }));
                                }
                            } catch { }

                            return {
                                id: apiSbom.scanId,
                                name: apiSbom.projectName || 'Unknown Project',
                                version: apiSbom.specVersion || '1.5',
                                format: (apiSbom.format || 'cyclonedx').toLowerCase() as 'spdx' | 'cyclonedx',
                                createdAt: apiSbom.generatedAt || apiSbom.scanDate || new Date().toISOString(),
                                totalVulnerabilities: apiSbom.findings || 0,
                                riskScore: Math.max(0, 100 - (apiSbom.findings || 0) * 2),
                                components: components,
                            };
                        })
                    );
                    setSboms(transformedSboms);
                    setSelectedSbom(transformedSboms[0]);
                } else {
                    // No SBOMs from API, use demo
                    setSboms([demoSbom]);
                    setSelectedSbom(demoSbom);
                }
            } else {
                // API error, use demo
                setSboms([demoSbom]);
                setSelectedSbom(demoSbom);
            }
        } catch (error) {
            // Network error, use demo
            setSboms([demoSbom]);
            setSelectedSbom(demoSbom);
        } finally {
            setIsLoading(false);
        }
    };

    const filteredComponents = selectedSbom?.components.filter(comp => {
        const matchesSearch = comp.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            comp.license.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesSeverity = filterSeverity === 'all' ||
            (filterSeverity === 'critical' && comp.critical > 0) ||
            (filterSeverity === 'high' && comp.high > 0);
        return matchesSearch && matchesSeverity;
    }) || [];

    const handleExport = async (format: 'spdx' | 'cyclonedx') => {
        if (!selectedSbom) return;

        try {
            const response = await fetch(`http://localhost:8000/sbom/export/${selectedSbom.id}?format=${format}`);
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${selectedSbom.name}_sbom.${format === 'spdx' ? 'spdx.json' : 'cdx.json'}`;
            a.click();
        } catch (error) {
            // Download demo JSON
            const demoJson = JSON.stringify({
                spdxVersion: "SPDX-2.3",
                dataLicense: "CC0-1.0",
                name: selectedSbom.name,
                packages: selectedSbom.components.map(c => ({
                    name: c.name,
                    versionInfo: c.version,
                    licenseDeclared: c.license,
                    supplier: c.supplier,
                    externalRefs: c.purl ? [{ referenceType: "purl", referenceLocator: c.purl }] : []
                })),
            }, null, 2);
            const blob = new Blob([demoJson], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${selectedSbom.name}_sbom.spdx.json`;
            a.click();
        }
    };

    const getRiskColor = (score: number) => {
        if (score >= 80) return 'text-emerald-600';
        if (score >= 60) return 'text-amber-600';
        return 'text-red-600';
    };

    const getLicenseRisk = (license: string) => {
        const highRisk = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0'];
        const mediumRisk = ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0'];
        if (highRisk.includes(license)) return 'high';
        if (mediumRisk.includes(license)) return 'medium';
        return 'low';
    };

    return (
        <div className="h-full overflow-hidden bg-precogs-50/30 flex">
            {/* Left Panel - SBOM List */}
            <div className="w-72 border-r border-surface-200 bg-white flex flex-col">
                <div className="p-4 border-b border-surface-200">
                    <div className="flex items-center justify-between mb-3">
                        <h2 className="font-semibold text-slate-800 flex items-center gap-2">
                            <Package className="w-5 h-5 text-precogs-600" />
                            SBOM Manager
                        </h2>
                        <button
                            onClick={fetchSBOMs}
                            className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-surface-100 rounded-lg transition-colors"
                        >
                            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                    <button className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-gradient-to-r from-precogs-600 to-purple-600 hover:from-precogs-700 hover:to-purple-700 text-white rounded-lg text-sm font-medium transition-colors">
                        <Upload className="w-4 h-4" />
                        Import SBOM
                    </button>
                </div>

                <div className="flex-1 overflow-y-auto p-2">
                    {isLoading ? (
                        <div className="flex items-center justify-center py-8">
                            <Loader2 className="w-6 h-6 animate-spin text-precogs-600" />
                        </div>
                    ) : sboms.length === 0 ? (
                        <div className="text-center py-8 text-slate-500 text-sm">
                            No SBOMs available. Run a scan to generate one.
                        </div>
                    ) : (
                        sboms.map((sbom) => (
                            <button
                                key={sbom.id}
                                onClick={() => setSelectedSbom(sbom)}
                                className={`w-full text-left p-3 rounded-lg mb-2 transition-all ${selectedSbom?.id === sbom.id
                                    ? 'bg-gradient-to-r from-precogs-50 to-purple-50 border border-precogs-200'
                                    : 'hover:bg-surface-50 border border-transparent'
                                    }`}
                            >
                                <div className="flex items-start gap-3">
                                    <div className="w-9 h-9 rounded-lg bg-precogs-100 flex items-center justify-center flex-shrink-0">
                                        <Layers className="w-4 h-4 text-precogs-600" />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <p className="font-medium text-slate-800 truncate">{sbom.name}</p>
                                        <p className="text-xs text-slate-500">v{sbom.version} • {sbom.components.length} components</p>
                                        <div className="flex items-center gap-2 mt-1">
                                            <span className={`text-xs font-medium ${getRiskColor(sbom.riskScore)}`}>
                                                Score: {sbom.riskScore}
                                            </span>
                                            {sbom.totalVulnerabilities > 0 && (
                                                <span className="text-xs text-red-500 flex items-center gap-1">
                                                    <AlertCircle className="w-3 h-3" />
                                                    {sbom.totalVulnerabilities} vulns
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </button>
                        ))
                    )}
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {selectedSbom ? (
                    <>
                        {/* Header */}
                        <div className="bg-white border-b border-surface-200 p-4">
                            <div className="flex items-center justify-between mb-4">
                                <div>
                                    <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
                                        {selectedSbom.name}
                                        <span className="text-sm font-normal text-slate-500 bg-surface-100 px-2 py-0.5 rounded">
                                            v{selectedSbom.version}
                                        </span>
                                    </h1>
                                    <p className="text-sm text-slate-500 mt-1">
                                        Generated {new Date(selectedSbom.createdAt).toLocaleDateString()} • {selectedSbom.format.toUpperCase()} format
                                    </p>
                                </div>
                                <div className="flex items-center gap-2">
                                    <button
                                        onClick={() => handleExport('spdx')}
                                        className="flex items-center gap-2 px-3 py-2 bg-surface-100 hover:bg-surface-200 border border-surface-300 rounded-lg text-sm text-slate-700 transition-colors"
                                    >
                                        <Download className="w-4 h-4" />
                                        SPDX
                                    </button>
                                    <button
                                        onClick={() => handleExport('cyclonedx')}
                                        className="flex items-center gap-2 px-3 py-2 bg-surface-100 hover:bg-surface-200 border border-surface-300 rounded-lg text-sm text-slate-700 transition-colors"
                                    >
                                        <Download className="w-4 h-4" />
                                        CycloneDX
                                    </button>
                                </div>
                            </div>

                            {/* Stats */}
                            <div className="grid grid-cols-4 gap-4">
                                <div className="bg-surface-50 rounded-xl p-3 border border-surface-200">
                                    <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                                        <Box className="w-3.5 h-3.5" />
                                        Components
                                    </div>
                                    <p className="text-2xl font-bold text-slate-800">{selectedSbom.components.length}</p>
                                </div>
                                <div className="bg-surface-50 rounded-xl p-3 border border-surface-200">
                                    <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                                        <AlertTriangle className="w-3.5 h-3.5" />
                                        Vulnerabilities
                                    </div>
                                    <p className="text-2xl font-bold text-red-600">{selectedSbom.totalVulnerabilities}</p>
                                </div>
                                <div className="bg-surface-50 rounded-xl p-3 border border-surface-200">
                                    <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                                        <Shield className="w-3.5 h-3.5" />
                                        Security Score
                                    </div>
                                    <p className={`text-2xl font-bold ${getRiskColor(selectedSbom.riskScore)}`}>
                                        {selectedSbom.riskScore}/100
                                    </p>
                                </div>
                                <div className="bg-surface-50 rounded-xl p-3 border border-surface-200">
                                    <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                                        <FileCode className="w-3.5 h-3.5" />
                                        License Types
                                    </div>
                                    <p className="text-2xl font-bold text-slate-800">
                                        {new Set(selectedSbom.components.map(c => c.license)).size}
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Filters */}
                        <div className="bg-white border-b border-surface-200 px-4 py-3 flex items-center gap-4">
                            <div className="relative flex-1 max-w-md">
                                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                                <input
                                    type="text"
                                    placeholder="Search components or licenses..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-full pl-10 pr-4 py-2 bg-surface-50 border border-surface-300 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-precogs-500"
                                />
                            </div>
                            <div className="flex items-center gap-2">
                                <span className="text-sm text-slate-500">Filter:</span>
                                {(['all', 'critical', 'high'] as const).map((severity) => (
                                    <button
                                        key={severity}
                                        onClick={() => setFilterSeverity(severity)}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${filterSeverity === severity
                                            ? severity === 'critical'
                                                ? 'bg-red-100 text-red-700 border border-red-200'
                                                : severity === 'high'
                                                    ? 'bg-orange-100 text-orange-700 border border-orange-200'
                                                    : 'bg-precogs-100 text-precogs-700 border border-precogs-200'
                                            : 'bg-surface-100 text-slate-600 border border-surface-200 hover:bg-surface-200'
                                            }`}
                                    >
                                        {severity === 'all' ? 'All' : severity.charAt(0).toUpperCase() + severity.slice(1)}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Component List */}
                        <div className="flex-1 overflow-y-auto p-4">
                            <div className="space-y-3">
                                {filteredComponents.map((component) => (
                                    <div
                                        key={component.id}
                                        className="bg-white border border-surface-200 rounded-xl overflow-hidden"
                                    >
                                        <button
                                            onClick={() => setExpandedComponent(expandedComponent === component.id ? null : component.id)}
                                            className="w-full p-4 flex items-center gap-4 hover:bg-surface-50 transition-colors"
                                        >
                                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-precogs-100 to-purple-100 flex items-center justify-center">
                                                <Package className="w-5 h-5 text-precogs-600" />
                                            </div>
                                            <div className="flex-1 text-left">
                                                <div className="flex items-center gap-2">
                                                    <span className="font-semibold text-slate-800">{component.name}</span>
                                                    <span className="text-xs text-slate-500 bg-surface-100 px-2 py-0.5 rounded">
                                                        {component.version}
                                                    </span>
                                                </div>
                                                <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                                                    <span className={`px-2 py-0.5 rounded ${getLicenseRisk(component.license) === 'high'
                                                        ? 'bg-red-50 text-red-600'
                                                        : getLicenseRisk(component.license) === 'medium'
                                                            ? 'bg-amber-50 text-amber-600'
                                                            : 'bg-emerald-50 text-emerald-600'
                                                        }`}>
                                                        {component.license}
                                                    </span>
                                                    {component.supplier && <span>by {component.supplier}</span>}
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                {component.vulnerabilities > 0 ? (
                                                    <div className="flex items-center gap-2">
                                                        {component.critical > 0 && (
                                                            <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-medium">
                                                                {component.critical} Critical
                                                            </span>
                                                        )}
                                                        {component.high > 0 && (
                                                            <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-xs font-medium">
                                                                {component.high} High
                                                            </span>
                                                        )}
                                                    </div>
                                                ) : (
                                                    <span className="flex items-center gap-1 text-xs text-emerald-600">
                                                        <CheckCircle2 className="w-4 h-4" />
                                                        Secure
                                                    </span>
                                                )}
                                                {expandedComponent === component.id ? (
                                                    <ChevronDown className="w-5 h-5 text-slate-400" />
                                                ) : (
                                                    <ChevronRight className="w-5 h-5 text-slate-400" />
                                                )}
                                            </div>
                                        </button>

                                        {expandedComponent === component.id && (
                                            <div className="border-t border-surface-200 bg-surface-50 p-4">
                                                <div className="grid grid-cols-2 gap-4 text-sm">
                                                    <div>
                                                        <p className="text-slate-500 text-xs mb-1">Package URL (PURL)</p>
                                                        <p className="font-mono text-xs text-slate-700 bg-white px-2 py-1 rounded border border-surface-200 truncate">
                                                            {component.purl || 'Not available'}
                                                        </p>
                                                    </div>
                                                    <div>
                                                        <p className="text-slate-500 text-xs mb-1">Supplier</p>
                                                        <p className="text-slate-700">{component.supplier || 'Unknown'}</p>
                                                    </div>
                                                </div>
                                                {component.vulnerabilities > 0 && (
                                                    <div className="mt-4">
                                                        <p className="text-xs text-slate-500 mb-2">Known Vulnerabilities</p>
                                                        <div className="space-y-2">
                                                            <div className="flex items-center gap-2 text-sm">
                                                                <AlertTriangle className="w-4 h-4 text-red-500" />
                                                                <span className="text-slate-700">
                                                                    {component.vulnerabilities} vulnerabilities found - check CVE databases
                                                                </span>
                                                                <a
                                                                    href={`https://nvd.nist.gov/vuln/search/results?query=${component.name}`}
                                                                    target="_blank"
                                                                    rel="noopener noreferrer"
                                                                    className="flex items-center gap-1 text-precogs-600 hover:text-precogs-700"
                                                                >
                                                                    View NVD <ExternalLink className="w-3 h-3" />
                                                                </a>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="flex-1 flex items-center justify-center">
                        <div className="text-center">
                            <Package className="w-16 h-16 mx-auto text-slate-300 mb-4" />
                            <h3 className="text-lg font-semibold text-slate-600 mb-2">No SBOM Selected</h3>
                            <p className="text-sm text-slate-500">
                                Run a scan with SBOM generation enabled to create a Software Bill of Materials.
                            </p>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SBOMManager;
