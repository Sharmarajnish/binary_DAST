import { ScanConfig, ScanSession } from '../types';

const API_BASE = 'http://localhost:8000';

export class DastApi {
  static async checkHealth(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${API_BASE}/health`, { signal: controller.signal });
      clearTimeout(timeoutId);
      return res.ok;
    } catch {
      return false;
    }
  }

  static async uploadBinary(file: File): Promise<{ file_id: string, filename: string }> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/scans/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
    return res.json();
  }

  static async startScan(fileId: string, config: ScanConfig): Promise<{ scan_id: string }> {
    const res = await fetch(`${API_BASE}/scans/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        file_id: fileId,
        config: {
          architecture: config.architecture || 'auto',
          analysisDepth: config.analysisDepth || 'standard',
          timeout: config.timeout || 300,
        }
      }),
    });

    if (!res.ok) throw new Error(`Failed to start scan: ${res.statusText}`);
    return res.json();
  }

  static async getScanStatus(scanId: string): Promise<Partial<ScanSession>> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`);
    if (!res.ok) throw new Error(`Failed to fetch status: ${res.statusText}`);

    const data = await res.json();
    return {
      status: data.status,
      progress: data.progress,
      currentStage: data.currentStage,
      logs: data.logs?.map((l: any) => ({
        id: l.id || Math.random().toString(36),
        timestamp: l.timestamp ? new Date(l.timestamp).getTime() : Date.now(),
        level: l.level,
        source: l.source,
        message: l.message
      })) || [],
      findings: data.findings?.map((v: any) => ({
        id: v.id || Math.random().toString(36),
        title: v.title,
        cweId: v.cweId,
        severity: v.severity,
        description: v.description,
        detectionMethod: v.detectionMethod,
        location: v.location,
        remediation: v.remediation,
        timestamp: Date.now()
      })) || []
    };
  }
}