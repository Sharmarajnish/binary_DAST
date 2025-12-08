import React, { useState } from 'react';
import {
  Upload, Cpu, Play, FileCode, Clock, Zap, Info, ChevronDown, ChevronRight,
  CheckCircle2, AlertTriangle, Sparkles, Shield, Target, Search, Github, History,
  ToggleLeft, ToggleRight, Plus, GitBranch, Globe, Lock, Loader2
} from 'lucide-react';
import { ScanConfig } from '../types';

// GitLab icon component (lucide doesn't have one)
const GitLabIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
    <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
  </svg>
);

interface NewScanProps {
  onStart: (config: ScanConfig, file: File) => void;
  onStartGitScan?: (scanId: string, config: ScanConfig) => void;
  onCancel: () => void;
}

type SourceType = 'file' | 'github' | 'gitlab';

const ARCHITECTURES = [
  { id: 'arm', label: 'ARM', sub: 'Cortex M/R/A' },
  { id: 'arm64', label: 'ARM64', sub: 'AArch64' },
  { id: 'tricore', label: 'TriCore', sub: 'Infineon' },
  { id: 'ppc', label: 'PPC', sub: 'e200' },
  { id: 'x86', label: 'x86', sub: 'x64' },
];

const FILE_TYPES = ['.vbf', '.bin', '.elf', '.hex', '.c', '.arxml', '.a2l', '.dbc'];

const COMPLIANCE_FRAMEWORKS = [
  { id: 'misra', label: 'MISRA C:2012', default: true },
  { id: 'iso21434', label: 'ISO 21434', default: true },
  { id: 'unece155', label: 'UNECE R155', default: true },
  { id: 'iso26262', label: 'ISO 26262', default: true },
  { id: 'autosar', label: 'AUTOSAR', default: false },
];

const NewScan: React.FC<NewScanProps> = ({ onStart, onStartGitScan, onCancel }) => {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [architecture, setArchitecture] = useState('auto');
  const [autoDetect, setAutoDetect] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [symbolFile, setSymbolFile] = useState<File | null>(null);
  const [taraSearch, setTaraSearch] = useState('');

  // Source type selection
  const [sourceType, setSourceType] = useState<SourceType>('file');

  // GitHub/GitLab state
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [accessToken, setAccessToken] = useState('');
  const [isPrivate, setIsPrivate] = useState(false);
  const [isCloning, setIsCloning] = useState(false);
  const [cloneError, setCloneError] = useState<string | null>(null);
  const [repoInfo, setRepoInfo] = useState<{ name: string; owner: string; } | null>(null);

  // Module toggles
  const [modules, setModules] = useState({
    fuzzing: true,
    symbolic: true,
    protocol: false,
    sbom: true,
    ai: true,
    compliance: true,
  });

  // Compliance frameworks
  const [compliance, setCompliance] = useState({
    misra: true,
    iso21434: true,
    unece155: true,
    iso26262: true,
    autosar: false,
  });

  const toggleModule = (key: keyof typeof modules) => {
    setModules(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleCompliance = (key: keyof typeof compliance) => {
    setCompliance(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files?.[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  // Parse repo URL to extract owner/name
  const parseRepoUrl = (url: string): { owner: string; name: string; platform: 'github' | 'gitlab' } | null => {
    try {
      // Handle both full URLs and shorthand (owner/repo)
      if (url.includes('github.com')) {
        const match = url.match(/github\.com[\/:]([^\/]+)\/([^\/\.]+)/);
        if (match) return { owner: match[1], name: match[2].replace('.git', ''), platform: 'github' };
      } else if (url.includes('gitlab.com')) {
        const match = url.match(/gitlab\.com[\/:]([^\/]+)\/([^\/\.]+)/);
        if (match) return { owner: match[1], name: match[2].replace('.git', ''), platform: 'gitlab' };
      } else if (url.match(/^[^\/]+\/[^\/]+$/)) {
        // Shorthand: owner/repo
        const [owner, name] = url.split('/');
        return { owner, name: name.replace('.git', ''), platform: sourceType === 'gitlab' ? 'gitlab' : 'github' };
      }
    } catch { }
    return null;
  };

  const handleRepoUrlChange = (url: string) => {
    setRepoUrl(url);
    setCloneError(null);
    const parsed = parseRepoUrl(url);
    if (parsed) {
      setRepoInfo({ owner: parsed.owner, name: parsed.name });
    } else {
      setRepoInfo(null);
    }
  };

  const handleCloneAndScan = async () => {
    if (!repoUrl) return;

    setIsCloning(true);
    setCloneError(null);

    try {
      const response = await fetch('http://localhost:8000/scans/clone-repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl,
          branch: branch,
          access_token: isPrivate ? accessToken : undefined,
          platform: sourceType,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to clone repository');
      }

      const data = await response.json();

      // Build config for display
      const config: ScanConfig = {
        binaryName: `${repoInfo?.owner}/${repoInfo?.name}`,
        binarySize: data.files_found || 0,
        architecture: autoDetect ? 'auto' : architecture as any,
        autoDetectArch: autoDetect,
        analysisDepth: modules.ai ? 'deep' : modules.symbolic ? 'standard' : 'quick',
        enableFuzzing: modules.fuzzing,
        enableSymbolic: modules.symbolic,
        enableProtocol: modules.protocol,
        enableSbom: modules.sbom,
        enableAI: modules.ai,
        enableCompliance: modules.compliance,
        fuzzerEngine: 'aflpp',
        protocolConfig: { type: 'uds', targetIp: '', canInterface: '' },
        complianceFrameworks: compliance,
        ecuContext: { ecuType: 'Git Repository', asil: 'QM', safetyCritical: false },
        advanced: { fuzzingTimeout: 10, symbolicDepth: 50, memoryLimit: 8 },
        modules: { fuzzing: modules.fuzzing, symbolic: modules.symbolic, taint: false },
        timeout: 300,
      };

      // Use the scan_id from the clone-repo response - scan is already running!
      if (onStartGitScan) {
        onStartGitScan(data.scan_id, config);
      } else {
        // Fallback to old behavior
        const virtualFile = new File([JSON.stringify({ repo: repoUrl, scan_id: data.scan_id })], `${repoInfo?.name || 'repo'}.git`, { type: 'application/x-git' });
        onStart(config, virtualFile);
      }
    } catch (err: any) {
      setCloneError(err.message || 'Failed to clone repository');
    } finally {
      setIsCloning(false);
    }
  };

  const handleStart = () => {
    if (file) {
      const config: ScanConfig = {
        binaryName: file.name,
        binarySize: file.size,
        architecture: autoDetect ? 'auto' : architecture as any,
        autoDetectArch: autoDetect,
        analysisDepth: modules.ai ? 'deep' : modules.symbolic ? 'standard' : 'quick',
        enableFuzzing: modules.fuzzing,
        enableSymbolic: modules.symbolic,
        enableProtocol: modules.protocol,
        enableSbom: modules.sbom,
        enableAI: modules.ai,
        enableCompliance: modules.compliance,
        fuzzerEngine: 'aflpp',
        protocolConfig: { type: 'uds', targetIp: '', canInterface: '' },
        complianceFrameworks: compliance,
        ecuContext: { ecuType: 'General ECU', asil: 'QM', safetyCritical: false },
        advanced: { fuzzingTimeout: 10, symbolicDepth: 50, memoryLimit: 8 },
        modules: { fuzzing: modules.fuzzing, symbolic: modules.symbolic, taint: false },
        timeout: 300,
      };
      onStart(config, file);
    }
  };

  // Calculate estimated time
  const estimatedTime =
    (modules.fuzzing ? 10 : 0) +
    (modules.symbolic ? 20 : 0) +
    (modules.protocol ? 15 : 0) +
    (modules.sbom ? 2 : 0) +
    (modules.ai ? 3 : 0) +
    (modules.compliance ? 5 : 0);

  const canStartScan = sourceType === 'file' ? !!file : !!repoUrl && !!repoInfo;

  return (
    <div className="h-full overflow-y-auto bg-precogs-50/30">
      {/* Header with Source Tabs */}
      <div className="border-b border-surface-200 bg-white">
        <div className="flex items-center gap-2 px-6 py-3">
          <button
            onClick={() => setSourceType('file')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${sourceType === 'file'
              ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
              : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
              }`}
          >
            <Upload className="w-4 h-4" />
            File Upload
          </button>
          <button
            onClick={() => setSourceType('github')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${sourceType === 'github'
              ? 'bg-slate-800 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-800'
              }`}
          >
            <Github className="w-4 h-4" />
            GitHub
          </button>
          <button
            onClick={() => setSourceType('gitlab')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${sourceType === 'gitlab'
              ? 'bg-orange-500 text-white shadow-sm'
              : 'text-slate-600 hover:bg-orange-50 hover:text-orange-700'
              }`}
          >
            <GitLabIcon className="w-4 h-4" />
            GitLab
          </button>
          <div className="flex-1" />
          <button className="flex items-center gap-2 px-4 py-2 text-slate-600 hover:text-slate-900 text-sm transition-colors">
            <History className="w-4 h-4" />
            History
          </button>
        </div>
      </div>

      <div className="p-6">
        <div className="grid grid-cols-2 gap-8 max-w-6xl mx-auto">
          {/* Left Column - Source Input */}
          <div className="space-y-6">
            {sourceType === 'file' ? (
              <>
                {/* File Upload Mode */}
                <div className="flex items-center gap-2 text-slate-600 text-sm font-medium uppercase tracking-wider">
                  <Upload className="w-4 h-4" />
                  Binary Upload
                </div>

                <div
                  className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer ${isDragging ? 'border-precogs-500 bg-precogs-500/10' :
                    file ? 'border-emerald-500 bg-emerald-500/10' :
                      'border-surface-300 hover:border-precogs-500/50 bg-white'
                    }`}
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
                  onDrop={handleDrop}
                  onClick={() => document.getElementById('file-upload')?.click()}
                >
                  <input type="file" id="file-upload" className="hidden" onChange={handleFileChange}
                    accept=".bin,.elf,.hex,.s19,.vbf,.c,.h,.arxml,.a2l,.dbc" />

                  <div className={`w-16 h-16 mx-auto rounded-full flex items-center justify-center mb-6 ${file ? 'bg-emerald-500/20' : 'bg-precogs-50'
                    }`}>
                    {file ? (
                      <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                    ) : (
                      <Upload className="w-8 h-8 text-slate-600" />
                    )}
                  </div>

                  {file ? (
                    <>
                      <p className="text-emerald-400 font-semibold text-lg">{file.name}</p>
                      <p className="text-slate-600 text-sm mt-2">{(file.size / 1024).toFixed(1)} KB • Click to change</p>
                    </>
                  ) : (
                    <>
                      <h3 className="text-xl font-semibold text-slate-900 mb-2">Upload ECU Binary</h3>
                      <p className="text-slate-600 text-sm">
                        Drop your <span className="text-precogs-600">.vbf</span>, <span className="text-precogs-600">.bin</span>, or <span className="text-precogs-600">.elf</span> file here
                      </p>
                      <p className="text-slate-500 text-sm mt-4">or</p>
                      <button className="mt-4 px-6 py-2 bg-precogs-50 hover:bg-surface-200 border border-surface-300 rounded-lg text-slate-700 text-sm font-medium transition-colors">
                        Browse Files
                      </button>
                    </>
                  )}
                </div>

                {/* File type pills */}
                <div className="flex flex-wrap gap-2 justify-center">
                  {FILE_TYPES.map(type => (
                    <span key={type} className="px-3 py-1 bg-precogs-50 border border-surface-300 rounded-lg text-xs text-slate-600 font-mono">
                      {type}
                    </span>
                  ))}
                </div>
              </>
            ) : (
              <>
                {/* GitHub/GitLab Mode */}
                <div className="flex items-center gap-2 text-slate-600 text-sm font-medium uppercase tracking-wider">
                  {sourceType === 'github' ? <Github className="w-4 h-4" /> : <GitLabIcon className="w-4 h-4" />}
                  {sourceType === 'github' ? 'GitHub Repository' : 'GitLab Repository'}
                </div>

                <div className="bg-white border border-surface-200 rounded-xl p-6 space-y-4">
                  {/* Repo URL Input */}
                  <div>
                    <label className="text-sm font-medium text-slate-700 mb-2 block">Repository URL</label>
                    <div className="relative">
                      <input
                        type="text"
                        placeholder={sourceType === 'github' ? 'https://github.com/owner/repo or owner/repo' : 'https://gitlab.com/owner/repo'}
                        value={repoUrl}
                        onChange={(e) => handleRepoUrlChange(e.target.value)}
                        className="w-full bg-precogs-50/50 border border-surface-300 rounded-lg px-4 py-3 text-sm text-slate-900 placeholder-slate-400 focus:ring-2 focus:ring-precogs-500 focus:border-precogs-500"
                      />
                      {repoInfo && (
                        <div className="absolute right-3 top-1/2 -translate-y-1/2">
                          <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Branch Input */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-slate-700 mb-2 block">Branch</label>
                      <div className="relative">
                        <GitBranch className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                        <input
                          type="text"
                          placeholder="main"
                          value={branch}
                          onChange={(e) => setBranch(e.target.value)}
                          className="w-full bg-precogs-50/50 border border-surface-300 rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-900 placeholder-slate-400"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="text-sm font-medium text-slate-700 mb-2 block">Visibility</label>
                      <button
                        onClick={() => setIsPrivate(!isPrivate)}
                        className={`w-full flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium border transition-all ${isPrivate
                          ? 'bg-amber-50 border-amber-300 text-amber-700'
                          : 'bg-precogs-50/50 border-surface-300 text-slate-600'
                          }`}
                      >
                        {isPrivate ? <Lock className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
                        {isPrivate ? 'Private' : 'Public'}
                      </button>
                    </div>
                  </div>

                  {/* Access Token for Private Repos */}
                  {isPrivate && (
                    <div>
                      <label className="text-sm font-medium text-slate-700 mb-2 block">
                        Personal Access Token
                        <span className="text-slate-400 font-normal ml-2">(required for private repos)</span>
                      </label>
                      <input
                        type="password"
                        placeholder={sourceType === 'github' ? 'ghp_xxxxxxxxxxxx' : 'glpat-xxxxxxxxxxxx'}
                        value={accessToken}
                        onChange={(e) => setAccessToken(e.target.value)}
                        className="w-full bg-precogs-50/50 border border-surface-300 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400"
                      />
                    </div>
                  )}

                  {/* Repo Preview */}
                  {repoInfo && (
                    <div className="bg-gradient-to-r from-precogs-50 to-purple-50 border border-precogs-200 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${sourceType === 'github' ? 'bg-slate-800' : 'bg-orange-500'
                          }`}>
                          {sourceType === 'github' ? <Github className="w-5 h-5 text-white" /> : <GitLabIcon className="w-5 h-5 text-white" />}
                        </div>
                        <div>
                          <p className="font-semibold text-slate-900">{repoInfo.owner}/{repoInfo.name}</p>
                          <p className="text-xs text-slate-500 flex items-center gap-1">
                            <GitBranch className="w-3 h-3" /> {branch}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Error Message */}
                  {cloneError && (
                    <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-center gap-2 text-red-700 text-sm">
                      <AlertTriangle className="w-4 h-4" />
                      {cloneError}
                    </div>
                  )}
                </div>

                {/* What We Scan */}
                <div className="bg-white border border-surface-200 rounded-xl p-4">
                  <h4 className="font-medium text-slate-800 mb-3">What we'll analyze:</h4>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      { ext: '.c / .h', desc: 'Source code' },
                      { ext: '.bin / .elf', desc: 'Binaries' },
                      { ext: '.arxml', desc: 'AUTOSAR configs' },
                      { ext: '.dbc', desc: 'CAN databases' },
                    ].map(item => (
                      <div key={item.ext} className="flex items-center gap-2 text-slate-600">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                        <span className="font-mono text-precogs-600">{item.ext}</span>
                        <span className="text-slate-400">- {item.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>


          {/* Right Column - Configuration */}
          <div className="space-y-6">
            {/* Target Architecture */}
            <div>
              <div className="flex items-center gap-2 text-slate-600 text-sm font-medium uppercase tracking-wider mb-4">
                <Cpu className="w-4 h-4" />
                Target Architecture
              </div>

              <div className="flex flex-wrap gap-2 mb-3">
                {ARCHITECTURES.map(arch => (
                  <button
                    key={arch.id}
                    onClick={() => { setArchitecture(arch.id); setAutoDetect(false); }}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${!autoDetect && architecture === arch.id
                      ? 'bg-precogs-500/20 border-precogs-500 text-precogs-600'
                      : 'bg-white border-surface-300 text-slate-600 hover:border-surface-400'
                      }`}
                  >
                    <div className="font-semibold">{arch.label}</div>
                    <div className="text-[10px] opacity-70">{arch.sub}</div>
                  </button>
                ))}
              </div>

              <label className="flex items-center gap-2 text-sm cursor-pointer group">
                <div
                  onClick={() => setAutoDetect(!autoDetect)}
                  className={`w-5 h-5 rounded-full border-2 flex items-center justify-center transition-all ${autoDetect ? 'bg-precogs-500 border-precogs-500' : 'border-surface-400 group-hover:border-slate-500'
                    }`}
                >
                  {autoDetect && <CheckCircle2 className="w-3 h-3 text-slate-900" />}
                </div>
                <span className={autoDetect ? 'text-precogs-600' : 'text-slate-600'}>
                  Auto-detect architecture from binary
                </span>
              </label>
            </div>

            {/* Analysis Modules */}
            <div>
              <div className="flex items-center gap-2 text-slate-600 text-sm font-medium uppercase tracking-wider mb-4">
                <Target className="w-4 h-4" />
                Analysis Modules
              </div>

              <div className="space-y-3">
                {/* Fuzzing */}
                <ModuleToggle
                  enabled={modules.fuzzing}
                  onToggle={() => toggleModule('fuzzing')}
                  icon="🔨"
                  title="Fuzzing (Precogs Fuzzer)"
                  time="~10 min"
                  description="Random input mutation for crash detection"
                />

                {/* Symbolic Execution */}
                <ModuleToggle
                  enabled={modules.symbolic}
                  onToggle={() => toggleModule('symbolic')}
                  icon="🔀"
                  title="Symbolic Execution (Precogs SE)"
                  time="~20 min"
                  description="Path exploration for logic flaws"
                />

                {/* Protocol Fuzzing */}
                <ModuleToggle
                  enabled={modules.protocol}
                  onToggle={() => toggleModule('protocol')}
                  icon="📡"
                  title="Protocol Fuzzing (Precogs Protocol)"
                  time="~15 min"
                  description="Automotive protocol testing"
                />

                {/* SBOM Generation */}
                <ModuleToggle
                  enabled={modules.sbom}
                  onToggle={() => toggleModule('sbom')}
                  icon="📦"
                  title="SBOM Generation"
                  time="~2 min"
                  description="Identify OSS components (SPDX format)"
                  badge="Required for Work Package 3"
                  badgeColor="cyan"
                />

                {/* AI Enhancement */}
                <ModuleToggle
                  enabled={modules.ai}
                  onToggle={() => toggleModule('ai')}
                  icon="✨"
                  title="AI Enhancement (Precogs AI)"
                  time="~3 min"
                  description="Analysis, remediation, PoC generation"
                  badge="Reduces false positives by ~60%"
                  badgeColor="emerald"
                />

                {/* Compliance Checking */}
                <div className="bg-white border border-surface-200 rounded-xl p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <button
                        onClick={() => toggleModule('compliance')}
                        className={`mt-0.5 transition-colors ${modules.compliance ? 'text-precogs-600' : 'text-slate-500'}`}
                      >
                        {modules.compliance ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
                      </button>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-lg">✅</span>
                          <span className={`font-medium ${modules.compliance ? 'text-slate-900' : 'text-slate-600'}`}>
                            Compliance Checking
                          </span>
                          <span className="text-xs text-slate-600">~5 min</span>
                          <Info className="w-3.5 h-3.5 text-slate-500" />
                        </div>
                        <p className="text-xs text-slate-600 mt-1">Standards validation</p>
                      </div>
                    </div>
                  </div>

                  {modules.compliance && (
                    <div className="flex flex-wrap gap-2 mt-3 ml-9">
                      {COMPLIANCE_FRAMEWORKS.map(fw => (
                        <button
                          key={fw.id}
                          onClick={() => toggleCompliance(fw.id as keyof typeof compliance)}
                          className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-all ${compliance[fw.id as keyof typeof compliance]
                            ? 'text-precogs-600'
                            : 'text-slate-600'
                            }`}
                        >
                          <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${compliance[fw.id as keyof typeof compliance]
                            ? 'bg-precogs-500 border-precogs-500'
                            : 'border-surface-400'
                            }`}>
                            {compliance[fw.id as keyof typeof compliance] && (
                              <CheckCircle2 className="w-2.5 h-2.5 text-slate-900" />
                            )}
                          </div>
                          {fw.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Advanced Options */}
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 text-slate-600 hover:text-slate-900 text-sm transition-colors"
            >
              {showAdvanced ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              Advanced Options
            </button>

            {showAdvanced && (
              <div className="bg-white border border-surface-200 rounded-xl p-4 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-slate-600 mb-1 block">Fuzzing Timeout (min)</label>
                    <input type="number" defaultValue={10} className="w-full bg-precogs-50 border border-surface-300 rounded-lg px-3 py-2 text-sm text-slate-900" />
                  </div>
                  <div>
                    <label className="text-xs text-slate-600 mb-1 block">Symbolic Depth</label>
                    <input type="number" defaultValue={50} className="w-full bg-precogs-50 border border-surface-300 rounded-lg px-3 py-2 text-sm text-slate-900" />
                  </div>
                </div>
              </div>
            )}

            {/* TARA Integration */}
            <div>
              <div className="flex items-center gap-2 text-slate-600 text-sm font-medium uppercase tracking-wider mb-3">
                <Search className="w-4 h-4" />
                TARA Integration (Optional)
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Search existing TARA..."
                  value={taraSearch}
                  onChange={(e) => setTaraSearch(e.target.value)}
                  className="flex-1 bg-white border border-surface-300 rounded-lg px-4 py-2 text-sm text-slate-900 placeholder-slate-500"
                />
                <button className="px-3 py-2 bg-precogs-50 border border-surface-300 rounded-lg text-slate-600 hover:text-slate-900 transition-colors">
                  <Plus className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Symbol File Upload */}
            <div className="bg-white/30 border border-surface-200 rounded-xl p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-slate-500" />
                <span className="text-sm text-slate-600">Upload symbol file for better accuracy</span>
              </div>
              <button className="flex items-center gap-2 px-4 py-2 bg-precogs-50 hover:bg-surface-200 border border-surface-300 rounded-lg text-sm text-slate-700 transition-colors">
                <Upload className="w-4 h-4" />
                Browse
              </button>
            </div>

            {/* Start Button */}
            <button
              onClick={sourceType === 'file' ? handleStart : handleCloneAndScan}
              disabled={!canStartScan || isCloning}
              className={`w-full flex items-center justify-center gap-3 px-8 py-4 rounded-xl font-bold text-lg transition-all ${canStartScan && !isCloning
                ? 'bg-gradient-to-r from-precogs-600 to-purple-600 hover:from-precogs-700 hover:to-purple-700 text-white shadow-lg shadow-precogs-600/30 active:scale-[0.98]'
                : 'bg-surface-200 text-slate-400 cursor-not-allowed border border-surface-300'
                }`}
            >
              {isCloning ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Cloning Repository...
                </>
              ) : canStartScan ? (
                <>
                  <Play className="w-5 h-5" />
                  {sourceType === 'file' ? 'Start Scan' : `Scan ${repoInfo?.name || 'Repository'}`}
                  <span className="text-sm opacity-70">• Est. {estimatedTime} min</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-5 h-5" />
                  {sourceType === 'file' ? 'Upload a file first' : 'Enter a valid repository URL'}
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Module Toggle Component
interface ModuleToggleProps {
  enabled: boolean;
  onToggle: () => void;
  icon: string;
  title: string;
  time: string;
  description: string;
  badge?: string;
  badgeColor?: 'cyan' | 'emerald' | 'purple';
}

const ModuleToggle: React.FC<ModuleToggleProps> = ({
  enabled, onToggle, icon, title, time, description, badge, badgeColor = 'cyan'
}) => {
  const badgeColors = {
    cyan: 'bg-precogs-500/20 text-precogs-600 border-precogs-500/30',
    emerald: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    purple: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  };

  return (
    <div className="bg-white border border-surface-200 rounded-xl p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <button
            onClick={onToggle}
            className={`mt-0.5 transition-colors ${enabled ? 'text-precogs-600' : 'text-slate-500'}`}
          >
            {enabled ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg">{icon}</span>
              <span className={`font-medium ${enabled ? 'text-slate-900' : 'text-slate-600'}`}>
                {title}
              </span>
              <span className="text-xs text-slate-600">{time}</span>
              <Info className="w-3.5 h-3.5 text-slate-500 cursor-help" />
            </div>
            <p className="text-xs text-slate-600 mt-1">{description}</p>
            {badge && enabled && (
              <span className={`inline-block mt-2 px-2 py-0.5 rounded text-[10px] font-medium border ${badgeColors[badgeColor]}`}>
                {badge}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default NewScan;