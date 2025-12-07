import React from 'react';
import { LayoutDashboard, ShieldAlert, Play, History, Settings, Activity, Wifi, WifiOff } from 'lucide-react';
import { ViewState, ConnectionStatus } from '../types';

interface SidebarProps {
  currentView: ViewState;
  setView: (view: ViewState) => void;
  connectionStatus: ConnectionStatus;
}

const Sidebar: React.FC<SidebarProps> = ({ currentView, setView, connectionStatus }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'new-scan', label: 'New Scan', icon: Play },
    { id: 'history', label: 'Scan History', icon: History },
  ];

  return (
    <div className="w-64 h-screen bg-slate-900 border-r border-slate-800 flex flex-col">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 bg-brand-600 rounded-lg flex items-center justify-center shadow-lg shadow-brand-600/20">
          <Activity className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="font-bold text-white tracking-tight">ECU Sentinel</h1>
          <p className="text-xs text-slate-500">DAST Framework v2.1</p>
        </div>
      </div>

      <nav className="flex-1 px-4 py-4 space-y-2">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setView(item.id as ViewState)}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 ${
              currentView === item.id
                ? 'bg-brand-600/10 text-brand-500 border border-brand-600/20'
                : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
            }`}
          >
            <item.icon className="w-5 h-5" />
            {item.label}
          </button>
        ))}
      </nav>

      <div className="p-4 border-t border-slate-800 space-y-4">
        <div className="px-4 py-3 bg-slate-800/50 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                    {connectionStatus === 'connected' ? (
                        <Wifi className="w-4 h-4 text-emerald-500" />
                    ) : connectionStatus === 'checking' ? (
                        <div className="w-4 h-4 rounded-full border-2 border-slate-600 border-t-slate-400 animate-spin" />
                    ) : (
                        <WifiOff className="w-4 h-4 text-amber-500" />
                    )}
                    <span className="text-xs font-semibold text-slate-300">
                        {connectionStatus === 'connected' ? 'Backend Online' : 'Demo Mode'}
                    </span>
                </div>
            </div>
            <div className="flex justify-between text-xs text-slate-500">
                <span>{connectionStatus === 'connected' ? 'Live Connection' : 'Simulation Active'}</span>
            </div>
        </div>

        <button className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 transition-colors">
          <Settings className="w-5 h-5" />
          Settings
        </button>
      </div>
    </div>
  );
};

export default Sidebar;