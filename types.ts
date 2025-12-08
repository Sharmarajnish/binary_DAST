
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ConnectionStatus = 'connected' | 'disconnected' | 'checking';

export type AnalysisDepth = 'quick' | 'standard' | 'deep' | 'custom';

export type Architecture = 'auto' | 'arm' | 'aarch64' | 'tricore' | 'rh850' | 'v850' | 'ppc' | 'riscv' | 'x86';

export type ProtocolType = 'uds' | 'can' | 'doip' | 'flexray';

export interface ScanConfig {
  binaryName: string;
  binarySize: number;
  architecture: Architecture;
  autoDetectArch: boolean;

  // Analysis modules
  enableFuzzing: boolean;
  enableSymbolic: boolean;
  enableProtocol: boolean;
  enableSbom: boolean;
  enableAI: boolean;
  enableCompliance: boolean;

  // Fuzzer config
  fuzzerEngine: 'aflpp' | 'honggfuzz' | 'radamsa';

  // Protocol fuzzing config
  protocolConfig: {
    type: ProtocolType;
    targetIp?: string;
    canInterface?: string;
  };

  // Compliance config
  complianceFrameworks: {
    misra: boolean;
    iso21434: boolean;
    unece155: boolean;
    iso26262: boolean;
    autosar: boolean;
  };

  // ECU context for AI
  ecuContext: {
    ecuType: string;
    asil: 'ASIL-D' | 'ASIL-C' | 'ASIL-B' | 'ASIL-A' | 'QM';
    safetyCritical: boolean;
  };

  // Analysis depth
  analysisDepth: AnalysisDepth;

  // Advanced settings
  advanced: {
    fuzzingTimeout: number; // minutes
    symbolicDepth: number; // paths
    memoryLimit: number; // GB
  };

  // Symbol file
  symbolFile?: File;

  // Baseline comparison
  baselineFile?: File;

  // TARA integration
  taraId?: string;

  // Legacy (backward compat)
  modules: {
    fuzzing: boolean;
    symbolic: boolean;
    taint: boolean;
  };

  timeout: number;
}

export interface TaraAssessment {
  id: string;
  name: string;
  date: string;
  cia: {
    c: number;
    i: number;
    a: number;
  };
}

export interface Vulnerability {
  id: string;
  title: string;
  cweId: string;
  severity: Severity;
  description: string;
  detectionMethod: 'Precogs-Fuzzer' | 'Precogs-HF' | 'Precogs-Mutator' | 'Precogs-SE' | 'Precogs-Emulator' | 'Precogs-Solver' | 'Precogs-AI' | 'Precogs-Protocol';
  location?: string;
  timestamp: number;

  // AI enhancement
  aiValidated?: boolean;
  aiConfidence?: number;
  aiFixSuggestion?: string;
  automotiveSeverity?: number;
  priority?: 'P0' | 'P1' | 'P2' | 'P3';

  // Compliance
  complianceViolations?: string[];

  // Additional properties for AI CoPilot
  codeSnippet?: string;
  remediation?: string;
  line?: number;
  cvss?: number;
}

export interface LogEntry {
  id: string;
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'success';
  source: 'System' | 'Precogs-Fuzz' | 'Precogs-HF' | 'Precogs-Mutator' | 'Precogs-SE' | 'Orchestrator' | 'Precogs-AI' | 'Precogs-Protocol' | 'SBOM' | 'Compliance';
  message: string;
}

export interface ScanSession {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  progress: number;
  config: ScanConfig;
  startTime: number;
  logs: LogEntry[];
  findings: Vulnerability[];
  currentStage: string;

  // Results
  sbomPath?: string;
  complianceReport?: object;
  executiveSummary?: string;
}

export type ViewState = 'dashboard' | 'new-scan' | 'scan-details' | 'history' | 'reports' | 'compliance' | 'documentation' | 'sbom' | 'settings';
