import { Vulnerability } from './types';

export const MOCK_RECENT_VULNS: Vulnerability[] = [
  {
    id: 'v-101',
    title: 'Buffer Overflow in CAN Handler',
    cweId: 'CWE-787',
    severity: 'critical',
    description: 'Out-of-bounds write detected during UDS 0x27 Security Access payload processing.',
    detectionMethod: 'AFL++',
    location: '0x080484b6 (handle_can_frame)',
    timestamp: Date.now() - 1000000,
  },
  {
    id: 'v-102',
    title: 'Integer Overflow in Speed Calc',
    cweId: 'CWE-190',
    severity: 'medium',
    description: 'Arithmetic operation results in wrap-around, potentially causing incorrect logic flow.',
    detectionMethod: 'Angr',
    location: '0x080485c2 (calc_velocity)',
    timestamp: Date.now() - 2500000,
  },
  {
    id: 'v-103',
    title: 'Hardcoded Credentials',
    cweId: 'CWE-798',
    severity: 'high',
    description: 'Found static key comparison in debug unlock routine.',
    detectionMethod: 'Angr',
    location: '0x080482a0 (debug_auth)',
    timestamp: Date.now() - 8000000,
  },
];

export const ARCHITECTURES = [
  { id: 'arm', label: 'ARM (32-bit)' },
  { id: 'aarch64', label: 'ARM64 (AArch64)' },
  { id: 'ppc', label: 'PowerPC' },
  { id: 'x86', label: 'x86 / x64' },
];

export const SEVERITY_COLORS = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/20',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-500 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};