import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Shield, Search, ArrowLeft, BarChart3, List, Download, FileJson, FileCode, FileText, Sparkles, X, MessageCircle } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, ScatterChart, Scatter, ZAxis, Cell } from 'recharts';
import { ScanSession, Vulnerability } from '../types';
import { SEVERITY_COLORS } from '../constants';
import AICopilot from './AICopilot';

interface ScanDetailsProps {
  session: ScanSession;
  onBack: () => void;
}

const API_BASE = 'http://localhost:8000';


const ScanDetails: React.FC<ScanDetailsProps> = ({ session, onBack }) => {
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [viewMode, setViewMode] = useState<'list' | 'analytics'>('list');
  const [showAICopilot, setShowAICopilot] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session.logs]);

  // Data prep for Analytics
  const severityScore = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const timelineData = session.findings.map(f => ({
    time: ((f.timestamp - session.startTime) / 1000).toFixed(1), // seconds
    severity: severityScore[f.severity],
    severityLabel: f.severity,
    title: f.title,
    cwe: f.cweId,
    color: f.severity === 'critical' ? '#ef4444' :
      f.severity === 'high' ? '#f97316' :
        f.severity === 'medium' ? '#eab308' : '#3b82f6'
  })).sort((a, b) => parseFloat(a.time) - parseFloat(b.time));

  const cweCounts = session.findings.reduce((acc, curr) => {
    acc[curr.cweId] = (acc[curr.cweId] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const cweData = Object.entries(cweCounts).map(([name, count]) => ({ name, count }));

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-6 border-b border-surface-200 bg-white flex justify-between items-center shrink-0">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="p-2 hover:bg-precogs-50 rounded-lg text-slate-600 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-slate-900 flex items-center gap-3">
              {session.config.binaryName}
              <span className={`px-2 py-0.5 rounded-full text-xs border uppercase ${session.status === 'running' ? 'text-brand-400 border-brand-500/30 bg-brand-500/10' :
                session.status === 'completed' ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' :
                  'text-slate-600 border-surface-300 bg-precogs-50'
                }`}>
                {session.status}
              </span>
            </h2>
            <p className="text-sm text-slate-600 mt-1 flex items-center gap-4">
              <span>ID: {session.id}</span>
              <span className="flex items-center gap-1"><ClockIcon className="w-3 h-3" /> Started: {new Date(session.startTime).toLocaleTimeString()}</span>
            </p>
          </div>
        </div>

        {/* Progress Circle (if running) */}
        {session.status === 'running' && (
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-slate-800">{session.currentStage}</p>
              <p className="text-xs text-slate-600">{Math.round(session.progress)}% Complete</p>
            </div>
            <div className="w-12 h-12 rounded-full border-4 border-surface-200 border-t-brand-500 animate-spin"></div>
          </div>
        )}

        {/* Download Reports (if completed) */}
        {session.status === 'completed' && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-600 mr-2">Download Report:</span>
            <a
              href={`${API_BASE}/scans/${session.id}/report/json`}
              download
              className="flex items-center gap-1.5 px-3 py-1.5 bg-precogs-50 hover:bg-surface-200 border border-surface-300 rounded-lg text-xs text-slate-700 transition-colors"
              title="Download JSON Report"
            >
              <FileJson className="w-3.5 h-3.5 text-blue-400" />
              JSON
            </a>
            <a
              href={`${API_BASE}/scans/${session.id}/report/sarif`}
              download
              className="flex items-center gap-1.5 px-3 py-1.5 bg-precogs-50 hover:bg-surface-200 border border-surface-300 rounded-lg text-xs text-slate-700 transition-colors"
              title="Download SARIF for CI/CD"
            >
              <FileCode className="w-3.5 h-3.5 text-purple-400" />
              SARIF
            </a>
            <a
              href={`${API_BASE}/scans/${session.id}/report/html`}
              download
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 border border-emerald-500 rounded-lg text-xs text-slate-900 font-medium transition-colors"
              title="Download HTML Report"
            >
              <FileText className="w-3.5 h-3.5" />
              HTML
            </a>
          </div>
        )}
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Console/Logs */}
        <div className="flex-1 flex flex-col border-r border-surface-200 bg-precogs-50/30 min-w-[400px]">
          <div className="p-3 bg-white border-b border-surface-200 flex items-center gap-2 text-xs font-mono text-slate-600">
            <Terminal className="w-4 h-4" />
            <span>DAST Output Console</span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1">
            {session.logs.map((log) => (
              <div key={log.id} className="flex gap-3 animate-in fade-in duration-300">
                <span className="text-slate-500 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                <span className={`font-bold shrink-0 w-24 ${log.source === 'AFL-Fuzz' ? 'text-pink-500' :
                  log.source === 'Precogs-SE' ? 'text-precogs-600' :
                    'text-brand-500'
                  }`}>
                  [{log.source}]
                </span>
                <span className={`${log.level === 'error' ? 'text-red-400' :
                  log.level === 'success' ? 'text-emerald-400' :
                    log.level === 'warn' ? 'text-orange-300' :
                      'text-slate-700'
                  }`}>
                  {log.message}
                </span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Right: Findings Panel */}
        <div className="w-96 bg-white flex flex-col shrink-0 border-l border-surface-200">
          <div className="p-4 border-b border-surface-200 flex justify-between items-center">
            <h3 className="font-semibold text-slate-900 flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-500" />
              Findings
              <span className="bg-precogs-50 px-2 py-0.5 rounded text-xs text-slate-600">
                {session.findings.length}
              </span>
            </h3>

            {/* View Toggle */}
            <div className="flex bg-precogs-50 rounded-lg p-1">
              <button
                onClick={() => setViewMode('list')}
                className={`p-1.5 rounded transition-colors ${viewMode === 'list' ? 'bg-slate-700 text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-800'}`}
                title="List View"
              >
                <List className="w-4 h-4" />
              </button>
              <button
                onClick={() => setViewMode('analytics')}
                className={`p-1.5 rounded transition-colors ${viewMode === 'analytics' ? 'bg-slate-700 text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-800'}`}
                title="Analytics View"
              >
                <BarChart3 className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {viewMode === 'list' ? (
              // LIST VIEW
              <div className="p-4 space-y-3">
                {session.findings.length === 0 ? (
                  <div className="text-center py-10 opacity-50">
                    <Search className="w-10 h-10 mx-auto text-slate-500 mb-2" />
                    <p className="text-sm text-slate-600">Scanning for vulnerabilities...</p>
                  </div>
                ) : (
                  session.findings.map((vuln) => (
                    <div
                      key={vuln.id}
                      onClick={() => { setSelectedVuln(vuln); setShowAICopilot(true); }}
                      className="bg-precogs-50 border border-surface-300 rounded-lg p-3 hover:border-brand-500/50 transition-colors cursor-pointer group animate-in slide-in-from-right duration-500"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${SEVERITY_COLORS[vuln.severity]}`}>
                          {vuln.severity}
                        </span>
                        <span className="text-[10px] text-slate-600 font-mono">{vuln.cweId}</span>
                      </div>
                      <h4 className="text-sm font-medium text-slate-800 mb-1 group-hover:text-brand-400 transition-colors">
                        {vuln.title}
                      </h4>
                      <p className="text-xs text-slate-600 line-clamp-2 mb-2">{vuln.description}</p>
                      <div className="flex items-center gap-2 text-[10px] text-slate-600 border-t border-surface-300/50 pt-2">
                        <span className="font-mono bg-precogs-50/30 px-1 rounded">{vuln.location}</span>
                        <span className="ml-auto flex items-center gap-1">
                          <Sparkles className="w-3 h-3 text-purple-400" />
                          Ask AI
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            ) : (
              // ANALYTICS VIEW
              <div className="p-4 space-y-6 animate-in fade-in duration-300">
                {session.findings.length === 0 ? (
                  <div className="text-center py-10 text-slate-600">No data to visualize yet.</div>
                ) : (
                  <>
                    {/* Detection Timeline */}
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Detection Timeline</h4>
                      <div className="h-40 bg-white rounded-lg border border-surface-200 p-2">
                        <ResponsiveContainer width="100%" height="100%">
                          <ScatterChart margin={{ top: 10, right: 10, bottom: 0, left: -20 }}>
                            <XAxis type="number" dataKey="time" name="Time" unit="s" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                            <YAxis type="number" dataKey="severity" name="Severity" domain={[0, 5]} hide />
                            <ZAxis type="number" range={[50, 400]} />
                            <Tooltip
                              cursor={{ strokeDasharray: '3 3' }}
                              content={({ active, payload }) => {
                                if (active && payload && payload.length) {
                                  const data = payload[0].payload;
                                  return (
                                    <div className="bg-white border border-surface-300 p-2 rounded shadow-xl text-xs">
                                      <p className="font-bold text-slate-800">{data.title}</p>
                                      <p className="text-slate-600">Time: {data.time}s</p>
                                      <p className="capitalize" style={{ color: data.color }}>{data.severityLabel}</p>
                                    </div>
                                  );
                                }
                                return null;
                              }}
                            />
                            <Scatter name="Findings" data={timelineData} shape="circle">
                              {timelineData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                              ))}
                            </Scatter>
                          </ScatterChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* CWE Distribution */}
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wider">CWE Distribution</h4>
                      <div className="h-48 bg-white rounded-lg border border-surface-200 p-2">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={cweData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                            <XAxis type="number" hide />
                            <YAxis dataKey="name" type="category" width={60} stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                            <Tooltip
                              cursor={{ fill: '#1e293b' }}
                              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9', fontSize: '12px' }}
                            />
                            <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} barSize={20}>
                              {cweData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={index % 2 === 0 ? '#3b82f6' : '#6366f1'} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Summary Stats at bottom right */}
          <div className="p-4 border-t border-surface-200 bg-white grid grid-cols-2 gap-2">
            <div className="bg-precogs-50/30 p-2 rounded text-center">
              <span className="block text-xl font-bold text-red-500">
                {session.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length}
              </span>
              <span className="text-[10px] text-slate-600 uppercase">Critical/High</span>
            </div>
            <div className="bg-precogs-50/30 p-2 rounded text-center">
              <span className="block text-xl font-bold text-slate-700">
                {session.findings.length}
              </span>
              <span className="text-[10px] text-slate-600 uppercase">Total</span>
            </div>
          </div>
        </div>
      </div>

      {/* Floating AI CoPilot Button */}
      {!showAICopilot && session.findings.length > 0 && (
        <button
          onClick={() => setShowAICopilot(true)}
          className="fixed bottom-6 right-6 flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 rounded-full text-white font-medium shadow-lg shadow-purple-500/30 transition-all hover:scale-105 z-50"
        >
          <Sparkles className="w-5 h-5" />
          AI CoPilot
        </button>
      )}

      {/* AI CoPilot Slide-out Panel */}
      {showAICopilot && (
        <div className="fixed inset-y-0 right-0 w-[450px] bg-white border-l border-slate-200 shadow-2xl z-50 flex flex-col animate-in slide-in-from-right duration-300">
          <div className="flex items-center justify-between p-4 border-b border-slate-200 bg-gradient-to-r from-purple-50 to-pink-50">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-purple-600" />
              <h3 className="font-semibold text-slate-900">AI CoPilot</h3>
              {selectedVuln && (
                <span className="px-2 py-0.5 bg-purple-100 text-purple-700 text-xs rounded-full">
                  {selectedVuln.cweId}
                </span>
              )}
            </div>
            <button
              onClick={() => { setShowAICopilot(false); setSelectedVuln(null); }}
              className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-500"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="flex-1 overflow-hidden">
            <AICopilot
              scan={session}
              vulnerability={selectedVuln || undefined}
            />
          </div>
        </div>
      )}
    </div>
  );
};

// Helper component for icon
const ClockIcon = ({ className }: { className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
);

export default ScanDetails;
