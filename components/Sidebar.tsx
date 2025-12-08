import React from 'react';
import { LayoutDashboard, ShieldAlert, Play, History, Settings, Activity, Wifi, WifiOff, FileText, Cpu, BookOpen } from 'lucide-react';
import { ViewState, ConnectionStatus } from '../types';

interface SidebarProps {
  currentView: ViewState;
  setView: (view: ViewState) => void;
  connectionStatus: ConnectionStatus;
}

const Sidebar: React.FC<SidebarProps> = ({ currentView, setView, connectionStatus }) => {
  return (
    <div className="w-64 h-screen bg-gradient-to-b from-white via-precogs-50/30 to-precogs-100/50 border-r border-precogs-200/50 flex flex-col shadow-soft">
      {/* Logo */}
      <div className="p-6 flex items-center gap-3 border-b border-precogs-100">
        <img
          src="/precogs-logo.png"
          alt="Precogs AI"
          className="w-10 h-10 object-contain"
        />
        <div>
          <h1 className="font-bold text-slate-800 tracking-tight text-lg">Precogs AI</h1>
          <p className="text-[10px] text-precogs-600 uppercase tracking-widest font-semibold">Product Security</p>
        </div>
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 px-4 py-4 space-y-1">
        <button
          onClick={() => setView('dashboard')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'dashboard'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <LayoutDashboard className="w-5 h-5" />
          Dashboard
        </button>

        <button
          onClick={() => setView('new-scan')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'new-scan' || currentView === 'scan-details'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <Cpu className="w-5 h-5" />
          Scan Centre
        </button>

        <button
          onClick={() => setView('reports')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'reports'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <FileText className="w-5 h-5" />
          Reports
        </button>

        <button
          onClick={() => setView('sbom')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'sbom'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <Activity className="w-5 h-5" />
          SBOM Manager
        </button>

        <button
          onClick={() => setView('compliance')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'compliance'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <ShieldAlert className="w-5 h-5" />
          Compliance
        </button>

        <button
          onClick={() => setView('documentation')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'documentation'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <BookOpen className="w-5 h-5" />
          Documentation
        </button>

        <button
          onClick={() => setView('settings')}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${currentView === 'settings'
            ? 'bg-precogs-100 text-precogs-700 border border-precogs-300 shadow-sm'
            : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-800'
            }`}
        >
          <Settings className="w-5 h-5" />
          Settings
        </button>
      </nav>

      {/* Status Section */}
      <div className="p-4 border-t border-precogs-100 space-y-3 bg-white/50">
        {/* Connection Status */}
        <div className="px-4 py-3 bg-white rounded-lg border border-precogs-100 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {connectionStatus === 'connected' ? (
                <>
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-xs font-semibold text-emerald-600">System Online</span>
                </>
              ) : connectionStatus === 'checking' ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-precogs-200 border-t-precogs-500 animate-spin" />
                  <span className="text-xs font-semibold text-slate-500">Connecting...</span>
                </>
              ) : (
                <>
                  <div className="w-2 h-2 rounded-full bg-amber-500" />
                  <span className="text-xs font-semibold text-amber-600">Demo Mode</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Connect ECU Button */}
        <button className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-precogs-600 to-purple-600 hover:from-precogs-700 hover:to-purple-700 rounded-lg text-sm font-semibold text-white transition-all shadow-lg shadow-precogs-600/30">
          <Wifi className="w-4 h-4" />
          Connect ECU
        </button>
      </div>
    </div>
  );
};

export default Sidebar;