export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ConnectionStatus = 'connected' | 'disconnected' | 'checking';

export interface ScanConfig {
  binaryName: string;
  binarySize: number;
  architecture: 'arm' | 'aarch64' | 'ppc' | 'x86';
  modules: {
    fuzzing: boolean;
    symbolic: boolean;
    taint: boolean;
  };
  timeout: number; // in seconds
}

export interface Vulnerability {
  id: string;
  title: string;
  cweId: string; // e.g., CWE-787
  severity: Severity;
  description: string;
  detectionMethod: 'AFL++' | 'Angr' | 'QEMU' | 'Triton';
  location?: string; // Memory address or function name
  timestamp: number;
}

export interface LogEntry {
  id: string;
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'success';
  source: 'System' | 'AFL-Fuzz' | 'Angr' | 'Orchestrator';
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
}

export type ViewState = 'dashboard' | 'new-scan' | 'scan-details' | 'history';