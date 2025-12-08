import { Vulnerability } from './types';

export const MOCK_RECENT_VULNS: Vulnerability[] = [
  {
    id: 'v-101',
    title: 'Buffer Overflow in CAN Handler',
    cweId: 'CWE-787',
    severity: 'critical',
    description: 'Out-of-bounds write detected during UDS 0x27 Security Access payload processing.',
    detectionMethod: 'Precogs-Fuzzer',
    location: '0x080484b6 (handle_can_frame)',
    timestamp: Date.now() - 1000000,
  },
  {
    id: 'v-102',
    title: 'Integer Overflow in Speed Calc',
    cweId: 'CWE-190',
    severity: 'medium',
    description: 'Arithmetic operation results in wrap-around, potentially causing incorrect logic flow.',
    detectionMethod: 'Precogs-SE',
    location: '0x080485c2 (calc_velocity)',
    timestamp: Date.now() - 2500000,
  },
  {
    id: 'v-103',
    title: 'Hardcoded Credentials',
    cweId: 'CWE-798',
    severity: 'high',
    description: 'Found static key comparison in debug unlock routine.',
    detectionMethod: 'Precogs-SE',
    location: '0x080482a0 (debug_auth)',
    timestamp: Date.now() - 8000000,
  },
];

// Complete automotive architecture list
export const ARCHITECTURES = [
  { id: 'auto', label: 'Auto-detect', description: 'Analyze binary headers' },
  { id: 'arm', label: 'ARM Cortex-M/R', description: '32-bit embedded' },
  { id: 'aarch64', label: 'ARM64 (AArch64)', description: 'High-performance' },
  { id: 'tricore', label: 'TriCore (Infineon)', description: 'Most common ECU', popular: true },
  { id: 'rh850', label: 'Renesas RH850', description: 'Japanese OEMs' },
  { id: 'v850', label: 'Renesas V850', description: 'Legacy Japanese' },
  { id: 'ppc', label: 'PowerPC (e200)', description: 'Legacy automotive' },
  { id: 'riscv', label: 'RISC-V', description: 'Emerging standard' },
  { id: 'x86', label: 'x86 / x64', description: 'Gateway/Telematics' },
];

// Compliance frameworks
export const COMPLIANCE_FRAMEWORKS = [
  { id: 'misra', label: 'MISRA C:2012', description: 'Coding standard', default: true },
  { id: 'iso21434', label: 'ISO 21434', description: 'Cybersecurity engineering', default: true },
  { id: 'unece155', label: 'UNECE R155', description: 'Regulatory requirement', default: true },
  { id: 'iso26262', label: 'ISO 26262', description: 'Functional safety', default: true },
  { id: 'autosar', label: 'AUTOSAR', description: 'Software guidelines', default: false },
];

// Protocol types for fuzzing
export const PROTOCOL_TYPES = [
  { id: 'uds', label: 'UDS (ISO 14229)', description: 'Diagnostic services' },
  { id: 'can', label: 'CAN Bus', description: 'Controller Area Network' },
  { id: 'doip', label: 'DoIP', description: 'Diagnostics over IP' },
  { id: 'flexray', label: 'FlexRay', description: 'High-speed backbone' },
];

// Analysis modules with full details
export const ANALYSIS_MODULES = [
  {
    id: 'fuzzing',
    name: 'Binary Fuzzing',
    engine: 'Precogs-Fuzzer',
    icon: 'Target',
    description: 'Random input mutation for crash detection',
    time: '~10 min',
    color: 'orange',
    workPackage: 'WP2',
    defaultOn: true,
  },
  {
    id: 'symbolic',
    name: 'Symbolic Execution',
    engine: 'angr',
    icon: 'Network',
    description: 'Path exploration for logic flaws',
    time: '~20 min',
    color: 'purple',
    workPackage: 'WP1',
    defaultOn: true,
  },
  {
    id: 'protocol',
    name: 'Protocol Fuzzing',
    engine: 'Precogs-Protocol',
    icon: 'Radio',
    description: 'UDS/CAN/DoIP protocol testing',
    time: '~15 min',
    color: 'cyan',
    workPackage: 'WP2',
    defaultOn: false,
  },
  {
    id: 'sbom',
    name: 'SBOM Generation',
    engine: 'Syft',
    icon: 'Package',
    description: 'Identify OSS components (SPDX format)',
    time: '~2 min',
    color: 'emerald',
    workPackage: 'WP3',
    required: true,
    defaultOn: true,
  },
  {
    id: 'ai',
    name: 'AI Enhancement',
    engine: 'Claude',
    icon: 'Sparkles',
    description: 'Analysis, remediation, PoC generation',
    time: '~3 min',
    color: 'blue',
    badge: 'Reduces false positives ~60%',
    defaultOn: true,
  },
  {
    id: 'compliance',
    name: 'Compliance Checking',
    engine: 'Multi',
    icon: 'CheckCircle',
    description: 'MISRA C, ISO 21434, UNECE R155 validation',
    time: '~5 min',
    color: 'green',
    workPackage: 'WP7',
    defaultOn: true,
  },
];

// Analysis depth presets
export const DEPTH_PRESETS = [
  {
    id: 'quick',
    name: 'Quick Scan',
    time: '10 min',
    modules: ['ai', 'fuzzing'],
    description: 'Fast feedback for CI/CD'
  },
  {
    id: 'standard',
    name: 'Standard Scan',
    time: '25 min',
    modules: ['ai', 'fuzzing', 'symbolic', 'sbom'],
    recommended: true,
    description: 'Pre-release validation'
  },
  {
    id: 'deep',
    name: 'Deep Scan',
    time: '45 min',
    modules: ['ai', 'fuzzing', 'symbolic', 'sbom', 'protocol', 'compliance'],
    description: 'Final release approval'
  },
  {
    id: 'custom',
    name: 'Custom',
    time: 'Variable',
    modules: [],
    description: 'Manual selection'
  },
];

// Mock TARA assessments for search
export const MOCK_TARA_LIST = [
  { id: 'tara-001', name: 'Engine ECU TARA v2.3', date: '2024-11-15', cia: { c: 8, i: 9, a: 7 } },
  { id: 'tara-002', name: 'BCM Security Assessment', date: '2024-10-22', cia: { c: 6, i: 7, a: 8 } },
  { id: 'tara-003', name: 'Gateway TARA Q4-2024', date: '2024-12-01', cia: { c: 9, i: 8, a: 9 } },
];

export const SEVERITY_COLORS = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/20',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};