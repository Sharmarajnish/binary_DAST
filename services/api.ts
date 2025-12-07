import { ScanConfig, ScanSession, Vulnerability, LogEntry } from '../types';

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

    const res = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
    return res.json();
  }

  static async startScan(fileId: string, config: ScanConfig): Promise<{ scan_id: string }> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_id: fileId, config }),
    });

    if (!res.ok) throw new Error(`Failed to start scan: ${res.statusText}`);
    return res.json();
  }

  static async getScanStatus(scanId: string): Promise<Partial<ScanSession>> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`);
    if (!res.ok) throw new Error(`Failed to fetch status: ${res.statusText}`);
    
    // Assume backend returns a JSON shape that matches or needs slight mapping
    // This mapping adapts the backend response to our frontend ScanSession type
    const data = await res.json();
    return {
      status: data.status,
      progress: data.progress,
      currentStage: data.current_stage || data.stage,
      logs: data.logs?.map((l: any) => ({
        id: l.id || Math.random().toString(36),
        timestamp: l.timestamp ? new Date(l.timestamp).getTime() : Date.now(),
        level: l.level,
        source: l.source,
        message: l.message
      })) || [],
      findings: data.vulnerabilities?.map((v: any) => ({
        id: v.id || Math.random().toString(36),
        title: v.title,
        cweId: v.cwe_id,
        severity: v.severity,
        description: v.description,
        detectionMethod: v.detection_method,
        location: v.location,
        timestamp: Date.now()
      })) || []
    };
  }
}