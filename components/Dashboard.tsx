import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { AlertTriangle, Bug, Zap, CheckCircle2 } from 'lucide-react';
import { MOCK_RECENT_VULNS, SEVERITY_COLORS } from '../constants';
import { Vulnerability } from '../types';

interface DashboardProps {
  onNewScan: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onNewScan }) => {
  const stats = [
    { label: 'Total Scans', value: '124', icon: Zap, color: 'text-brand-500' },
    { label: 'Critical Vulns', value: '12', icon: AlertTriangle, color: 'text-red-500' },
    { label: 'Avg Coverage', value: '86%', icon: CheckCircle2, color: 'text-emerald-500' },
    { label: 'Issues Found', value: '485', icon: Bug, color: 'text-orange-500' },
  ];

  const pieData = [
    { name: 'Critical', value: 12, color: '#ef4444' },
    { name: 'High', value: 25, color: '#f97316' },
    { name: 'Medium', value: 45, color: '#eab308' },
    { name: 'Low', value: 30, color: '#3b82f6' },
  ];

  const barData = [
    { name: 'CWE-787', count: 45 },
    { name: 'CWE-120', count: 32 },
    { name: 'CWE-20', count: 28 },
    { name: 'CWE-190', count: 18 },
    { name: 'CWE-416', count: 12 },
  ];

  return (
    <div className="p-8 space-y-8 overflow-y-auto h-full">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-white">Security Dashboard</h2>
          <p className="text-slate-400">Overview of DAST analysis on ECU binaries</p>
        </div>
        <button
          onClick={onNewScan}
          className="bg-brand-600 hover:bg-brand-500 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg shadow-brand-600/20 transition-all active:scale-95"
        >
          Start New Scan
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-slate-900 border border-slate-800 p-6 rounded-xl flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-500 font-medium mb-1">{stat.label}</p>
              <h3 className="text-3xl font-bold text-white">{stat.value}</h3>
            </div>
            <div className={`p-3 rounded-lg bg-slate-800/50 ${stat.color}`}>
              <stat.icon className="w-6 h-6" />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl">
          <h3 className="text-lg font-semibold text-white mb-6">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0)" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 mt-4">
            {pieData.map(item => (
                <div key={item.name} className="flex items-center gap-2 text-xs text-slate-400">
                    <div className="w-2 h-2 rounded-full" style={{backgroundColor: item.color}}></div>
                    {item.name}
                </div>
            ))}
          </div>
        </div>

        {/* Top CWEs */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 p-6 rounded-xl">
          <h3 className="text-lg font-semibold text-white mb-6">Top Detected CWEs (Last 30 Days)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: '#1e293b' }}
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-slate-800">
          <h3 className="text-lg font-semibold text-white">Recent Vulnerabilities</h3>
        </div>
        <div className="divide-y divide-slate-800">
          {MOCK_RECENT_VULNS.map((vuln) => (
            <div key={vuln.id} className="p-4 flex items-center justify-between hover:bg-slate-800/50 transition-colors">
              <div className="flex items-center gap-4">
                <span className={`px-2 py-1 rounded text-xs font-medium uppercase border ${SEVERITY_COLORS[vuln.severity]}`}>
                  {vuln.severity}
                </span>
                <div>
                  <h4 className="text-sm font-medium text-slate-200">{vuln.title}</h4>
                  <p className="text-xs text-slate-500">{vuln.cweId} • {vuln.detectionMethod}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs font-mono text-slate-400">{vuln.location}</p>
                <p className="text-xs text-slate-600">{new Date(vuln.timestamp).toLocaleDateString()}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;