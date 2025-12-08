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
    { label: 'Total Scans', value: '124', icon: Zap, color: 'text-precogs-600', bg: 'bg-precogs-50' },
    { label: 'Critical Vulns', value: '12', icon: AlertTriangle, color: 'text-red-600', bg: 'bg-red-50' },
    { label: 'Avg Coverage', value: '86%', icon: CheckCircle2, color: 'text-emerald-600', bg: 'bg-emerald-50' },
    { label: 'Issues Found', value: '485', icon: Bug, color: 'text-orange-600', bg: 'bg-orange-50' },
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
          <h2 className="text-2xl font-bold text-slate-900">Security Dashboard</h2>
          <p className="text-slate-600">Overview of DAST analysis on ECU binaries</p>
        </div>
        <button
          onClick={onNewScan}
          className="bg-precogs-600 hover:bg-precogs-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg shadow-precogs-600/20 transition-all active:scale-95"
        >
          Start New Scan
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-white border border-surface-200 p-6 rounded-xl flex items-center justify-between shadow-card">
            <div>
              <p className="text-sm text-slate-600 font-medium mb-1">{stat.label}</p>
              <h3 className="text-3xl font-bold text-slate-900">{stat.value}</h3>
            </div>
            <div className={`p-3 rounded-lg ${stat.bg} ${stat.color}`}>
              <stat.icon className="w-6 h-6" />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="bg-white border border-surface-200 p-6 rounded-xl shadow-card">
          <h3 className="text-lg font-semibold text-slate-900 mb-6">Severity Distribution</h3>
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
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(255,255,255,0.8)" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', color: '#1e293b', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' }}
                  itemStyle={{ color: '#1e293b' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 mt-4">
            {pieData.map(item => (
              <div key={item.name} className="flex items-center gap-2 text-xs text-slate-700">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }}></div>
                {item.name}
              </div>
            ))}
          </div>
        </div>

        {/* Top CWEs */}
        <div className="lg:col-span-2 bg-white border border-surface-200 p-6 rounded-xl shadow-card">
          <h3 className="text-lg font-semibold text-slate-900 mb-6">Top Detected CWEs (Last 30 Days)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: '#f1f5f9' }}
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', color: '#1e293b', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="bg-white border border-surface-200 rounded-xl overflow-hidden shadow-card">
        <div className="p-6 border-b border-surface-200">
          <h3 className="text-lg font-semibold text-slate-900">Recent Vulnerabilities</h3>
        </div>
        <div className="divide-y divide-surface-100">
          {MOCK_RECENT_VULNS.map((vuln) => (
            <div key={vuln.id} className="p-4 flex items-center justify-between hover:bg-precogs-50/30 transition-colors">
              <div className="flex items-center gap-4">
                <span className={`px-2 py-1 rounded text-xs font-medium uppercase border ${SEVERITY_COLORS[vuln.severity]}`}>
                  {vuln.severity}
                </span>
                <div>
                  <h4 className="text-sm font-medium text-slate-900">{vuln.title}</h4>
                  <p className="text-xs text-slate-600">{vuln.cweId} • {vuln.detectionMethod}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs font-mono text-slate-700">{vuln.location}</p>
                <p className="text-xs text-slate-500">{new Date(vuln.timestamp).toLocaleDateString()}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;