import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Shield, Search, ArrowLeft, BarChart3, List } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, ScatterChart, Scatter, ZAxis, Cell } from 'recharts';
import { ScanSession, Vulnerability } from '../types';
import { SEVERITY_COLORS } from '../constants';

interface ScanDetailsProps {
  session: ScanSession;
  onBack: () => void;
}

const ScanDetails: React.FC<ScanDetailsProps> = ({ session, onBack }) => {
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [viewMode, setViewMode] = useState<'list' | 'analytics'>('list');

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
      <div className="p-6 border-b border-slate-800 bg-slate-900 flex justify-between items-center shrink-0">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-3">
              {session.config.binaryName}
              <span className={`px-2 py-0.5 rounded-full text-xs border uppercase ${
                session.status === 'running' ? 'text-brand-400 border-brand-500/30 bg-brand-500/10' :
                session.status === 'completed' ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' :
                'text-slate-400 border-slate-700 bg-slate-800'
              }`}>
                {session.status}
              </span>
            </h2>
            <p className="text-sm text-slate-500 mt-1 flex items-center gap-4">
              <span>ID: {session.id}</span>
              <span className="flex items-center gap-1"><ClockIcon className="w-3 h-3" /> Started: {new Date(session.startTime).toLocaleTimeString()}</span>
            </p>
          </div>
        </div>
        
        {/* Progress Circle (if running) */}
        {session.status === 'running' && (
             <div className="flex items-center gap-4">
                <div className="text-right">
                    <p className="text-sm font-medium text-slate-200">{session.currentStage}</p>
                    <p className="text-xs text-slate-500">{Math.round(session.progress)}% Complete</p>
                </div>
                <div className="w-12 h-12 rounded-full border-4 border-slate-800 border-t-brand-500 animate-spin"></div>
             </div>
        )}
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Console/Logs */}
        <div className="flex-1 flex flex-col border-r border-slate-800 bg-slate-950 min-w-[400px]">
          <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center gap-2 text-xs font-mono text-slate-400">
            <Terminal className="w-4 h-4" />
            <span>DAST Output Console</span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1">
            {session.logs.map((log) => (
              <div key={log.id} className="flex gap-3 animate-in fade-in duration-300">
                <span className="text-slate-600 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                <span className={`font-bold shrink-0 w-24 ${
                    log.source === 'AFL-Fuzz' ? 'text-pink-500' :
                    log.source === 'Angr' ? 'text-cyan-500' :
                    'text-brand-500'
                }`}>
                    [{log.source}]
                </span>
                <span className={`${
                    log.level === 'error' ? 'text-red-400' :
                    log.level === 'success' ? 'text-emerald-400' :
                    log.level === 'warn' ? 'text-orange-300' :
                    'text-slate-300'
                }`}>
                    {log.message}
                </span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Right: Findings Panel */}
        <div className="w-96 bg-slate-900 flex flex-col shrink-0 border-l border-slate-800">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <h3 className="font-semibold text-white flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-500" />
                Findings
                <span className="bg-slate-800 px-2 py-0.5 rounded text-xs text-slate-400">
                    {session.findings.length}
                </span>
            </h3>
            
            {/* View Toggle */}
            <div className="flex bg-slate-800 rounded-lg p-1">
              <button 
                onClick={() => setViewMode('list')}
                className={`p-1.5 rounded transition-colors ${viewMode === 'list' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                title="List View"
              >
                <List className="w-4 h-4" />
              </button>
              <button 
                onClick={() => setViewMode('analytics')}
                className={`p-1.5 rounded transition-colors ${viewMode === 'analytics' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
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
                          <Search className="w-10 h-10 mx-auto text-slate-600 mb-2" />
                          <p className="text-sm text-slate-500">Scanning for vulnerabilities...</p>
                      </div>
                  ) : (
                      session.findings.map((vuln) => (
                          <div key={vuln.id} className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 hover:border-brand-500/50 transition-colors cursor-pointer group animate-in slide-in-from-right duration-500">
                              <div className="flex justify-between items-start mb-2">
                                   <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${SEVERITY_COLORS[vuln.severity]}`}>
                                      {vuln.severity}
                                  </span>
                                  <span className="text-[10px] text-slate-500 font-mono">{vuln.cweId}</span>
                              </div>
                              <h4 className="text-sm font-medium text-slate-200 mb-1 group-hover:text-brand-400 transition-colors">
                                  {vuln.title}
                              </h4>
                              <p className="text-xs text-slate-500 line-clamp-2 mb-2">{vuln.description}</p>
                              <div className="flex items-center gap-2 text-[10px] text-slate-400 border-t border-slate-700/50 pt-2">
                                  <span className="font-mono bg-slate-950 px-1 rounded">{vuln.location}</span>
                                  <span className="ml-auto">{vuln.detectionMethod}</span>
                              </div>
                          </div>
                      ))
                  )}
                </div>
            ) : (
                // ANALYTICS VIEW
                <div className="p-4 space-y-6 animate-in fade-in duration-300">
                   {session.findings.length === 0 ? (
                       <div className="text-center py-10 text-slate-500">No data to visualize yet.</div>
                   ) : (
                       <>
                           {/* Detection Timeline */}
                           <div className="space-y-2">
                               <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detection Timeline</h4>
                               <div className="h-40 bg-slate-900/50 rounded-lg border border-slate-800 p-2">
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
                                                           <div className="bg-slate-900 border border-slate-700 p-2 rounded shadow-xl text-xs">
                                                               <p className="font-bold text-slate-200">{data.title}</p>
                                                               <p className="text-slate-400">Time: {data.time}s</p>
                                                               <p className="capitalize" style={{color: data.color}}>{data.severityLabel}</p>
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
                               <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">CWE Distribution</h4>
                               <div className="h-48 bg-slate-900/50 rounded-lg border border-slate-800 p-2">
                                   <ResponsiveContainer width="100%" height="100%">
                                       <BarChart data={cweData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                                            <XAxis type="number" hide />
                                            <YAxis dataKey="name" type="category" width={60} stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                                            <Tooltip 
                                               cursor={{fill: '#1e293b'}}
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
          <div className="p-4 border-t border-slate-800 bg-slate-900 grid grid-cols-2 gap-2">
            <div className="bg-slate-950 p-2 rounded text-center">
                <span className="block text-xl font-bold text-red-500">
                    {session.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length}
                </span>
                <span className="text-[10px] text-slate-500 uppercase">Critical/High</span>
            </div>
             <div className="bg-slate-950 p-2 rounded text-center">
                <span className="block text-xl font-bold text-slate-300">
                    {session.findings.length}
                </span>
                <span className="text-[10px] text-slate-500 uppercase">Total</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Helper component for icon
const ClockIcon = ({ className }: { className?: string }) => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
);

export default ScanDetails;
