import { LogEntry, Vulnerability, ScanConfig } from '../types';

// Helper to generate a random ID
const uuid = () => Math.random().toString(36).substr(2, 9);

export const generateLog = (source: LogEntry['source'], message: string, level: LogEntry['level'] = 'info'): LogEntry => ({
  id: uuid(),
  timestamp: Date.now(),
  source,
  message,
  level,
});

export const MOCK_FINDINGS_POOL: Partial<Vulnerability>[] = [
  {
    title: 'SIGSEGV in parser_dispatch',
    cweId: 'CWE-787',
    severity: 'critical',
    description: 'Memory corruption detected via AFL++ crash. Input vector exceeds buffer allocation in main dispatch loop.',
    detectionMethod: 'AFL++',
  },
  {
    title: 'Unreachable Exit Condition',
    cweId: 'CWE-835',
    severity: 'medium',
    description: 'Loop detected with symbolic execution that cannot be exited under normal constraints.',
    detectionMethod: 'Angr',
  },
  {
    title: 'Format String Vulnerability',
    cweId: 'CWE-134',
    severity: 'high',
    description: 'User controlled input passed to printf-family function without format specifier.',
    detectionMethod: 'Angr',
  },
  {
    title: 'Integer Underflow',
    cweId: 'CWE-191',
    severity: 'high',
    description: 'Subtraction results in wrap-around causing heap overflow in subsequent allocation.',
    detectionMethod: 'Angr',
  },
  {
    title: 'Use After Free',
    cweId: 'CWE-416',
    severity: 'critical',
    description: 'Object accessed after memory deallocation in connection teardown routine.',
    detectionMethod: 'QEMU',
  },
];

export const simulateScanStep = (
  elapsedTime: number,
  config: ScanConfig,
  currentFindings: Vulnerability[]
): { logs: LogEntry[]; newFinding?: Vulnerability; progress: number; stage: string; complete: boolean } => {
  const logs: LogEntry[] = [];
  let newFinding: Vulnerability | undefined;
  let progress = 0;
  let stage = 'Initializing';
  let complete = false;

  // Simulation Logic based on time
  const totalDuration = config.timeout * 1000; // Mock scaling, actual timeout is usually longer
  const percentComplete = Math.min((elapsedTime / 15000) * 100, 100); // Scale to 15 seconds for demo
  progress = percentComplete;

  if (percentComplete < 10) {
    stage = 'Environment Setup';
    if (Math.random() > 0.7) logs.push(generateLog('System', 'Loading binary into memory space...'));
    if (Math.random() > 0.8) logs.push(generateLog('Orchestrator', `Detecting architecture: ${config.architecture.toUpperCase()}`));
  } else if (percentComplete < 40) {
    stage = config.modules.fuzzing ? 'Fuzzing (AFL++)' : 'Static Analysis';
    if (config.modules.fuzzing) {
        if (Math.random() > 0.6) logs.push(generateLog('AFL-Fuzz', `Havoc cycle ${Math.floor(elapsedTime / 100)}: bitflips done.`));
        if (Math.random() > 0.8) logs.push(generateLog('AFL-Fuzz', `Exec speed: ${Math.floor(2000 + Math.random() * 500)}/sec`));
    }
  } else if (percentComplete < 80) {
    stage = config.modules.symbolic ? 'Symbolic Execution (Angr)' : 'Deep Analysis';
    if (config.modules.symbolic) {
        if (Math.random() > 0.6) logs.push(generateLog('Angr', `Exploring path ${uuid()} constraint set size: ${Math.floor(Math.random() * 50)}`));
        if (Math.random() > 0.8) logs.push(generateLog('Angr', 'Solving constraints for branch condition...'));
    }
  } else if (percentComplete < 100) {
    stage = 'Report Generation';
    if (Math.random() > 0.7) logs.push(generateLog('Orchestrator', 'Mapping findings to CWE Top 25...'));
  } else {
    stage = 'Completed';
    complete = true;
  }

  // Randomly find a vulnerability
  if (!complete && Math.random() > 0.96 && currentFindings.length < 5) {
    const template = MOCK_FINDINGS_POOL[Math.floor(Math.random() * MOCK_FINDINGS_POOL.length)];
    newFinding = {
      id: uuid(),
      timestamp: Date.now(),
      title: template.title!,
      cweId: template.cweId!,
      severity: template.severity as any,
      description: template.description!,
      detectionMethod: template.detectionMethod as any,
      location: `0x${Math.floor(Math.random() * 0xFFFFFF).toString(16)}`,
    };
    logs.push(generateLog('Orchestrator', `VULNERABILITY DETECTED: ${newFinding.cweId} - ${newFinding.title}`, 'error'));
  }

  return { logs, newFinding, progress, stage, complete };
};