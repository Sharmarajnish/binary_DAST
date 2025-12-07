import React, { useEffect, useRef } from 'react';
import { Terminal, Shield, AlertTriangle, CheckCircle, Clock, Search, XCircle, ArrowLeft } from 'lucide-react';
import { ScanSession, Vulnerability } from '../types';
import { SEVERITY_COLORS } from '../constants';

interface ScanDetailsProps {
  session: ScanSession;
  onBack: () => void;
}

const ScanDetails: React.FC<ScanDetailsProps> = ({ session, onBack }) => {
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session.logs]);

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
              <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> Started: {new Date(session.startTime).toLocaleTimeString()}</span>
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

        {/* Right: Findings List */}
        <div className="w-96 bg-slate-900 flex flex-col shrink-0">
          <div className="p-4 border-b border-slate-800">
            <h3 className="font-semibold text-white flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-500" />
                Findings
                <span className="ml-auto bg-slate-800 px-2 py-0.5 rounded text-xs text-slate-400">
                    {session.findings.length}
                </span>
            </h3>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
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

export default ScanDetails;