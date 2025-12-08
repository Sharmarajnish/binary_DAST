import React, { useState } from 'react';
import {
    Settings as SettingsIcon, User, Bell, Shield, Palette, Globe, Zap,
    Server, Key, Link2, Save, ChevronRight, Check, Info,
    Github, ExternalLink, Database, Cloud, Lock, Mail, Smartphone
} from 'lucide-react';

interface SettingsProps {
    onBack?: () => void;
}

const INTEGRATION_CARDS = [
    {
        id: 'gitlab',
        name: 'GitLab',
        description: 'CI/CD pipeline integration for automated scans',
        icon: '🦊',
        connected: true,
        status: 'Connected',
    },
    {
        id: 'jira',
        name: 'Jira',
        description: 'Export vulnerabilities as tickets',
        icon: '📋',
        connected: true,
        status: 'Connected',
    },
    {
        id: 'slack',
        name: 'Slack',
        description: 'Real-time vulnerability notifications',
        icon: '💬',
        connected: false,
        status: 'Not connected',
    },
    {
        id: 'teams',
        name: 'Microsoft Teams',
        description: 'Team notifications and alerts',
        icon: '👥',
        connected: false,
        status: 'Not connected',
    },
];

const Settings: React.FC<SettingsProps> = () => {
    const [activeTab, setActiveTab] = useState('integrations');
    const [notifications, setNotifications] = useState({
        email: true,
        slack: false,
        critical: true,
        high: true,
        medium: false,
        scanComplete: true,
    });

    const tabs = [
        { id: 'integrations', label: 'Integrations', icon: Link2 },
        { id: 'notifications', label: 'Notifications', icon: Bell },
        { id: 'security', label: 'Security', icon: Shield },
        { id: 'api', label: 'API Keys', icon: Key },
        { id: 'appearance', label: 'Appearance', icon: Palette },
    ];

    return (
        <div className="h-full overflow-y-auto bg-precogs-50/30">
            {/* Header */}
            <div className="relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-indigo-900/30 via-slate-900 to-slate-950" />
                <div className="relative px-8 py-8">
                    <div className="flex items-center gap-4">
                        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                            <SettingsIcon className="w-7 h-7 text-slate-900" />
                        </div>
                        <div>
                            <h1 className="text-3xl font-bold text-slate-900">Settings</h1>
                            <p className="text-slate-600">Configure integrations, notifications, and preferences</p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="px-8 py-6 flex gap-8">
                {/* Sidebar Tabs */}
                <div className="w-64 shrink-0">
                    <nav className="space-y-1.5 sticky top-6">
                        {tabs.map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${activeTab === tab.id
                                        ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
                                        : 'text-slate-600 hover:bg-precogs-50 hover:text-slate-900'
                                    }`}
                            >
                                <tab.icon className="w-5 h-5" />
                                {tab.label}
                            </button>
                        ))}
                    </nav>
                </div>

                {/* Content */}
                <div className="flex-1 max-w-3xl">
                    {activeTab === 'integrations' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 mb-2">Integrations</h2>
                                <p className="text-slate-600">Connect external services for enhanced workflow</p>
                            </div>

                            {/* Integration Cards */}
                            <div className="grid grid-cols-2 gap-4">
                                {INTEGRATION_CARDS.map(integration => (
                                    <div
                                        key={integration.id}
                                        className={`relative bg-white border rounded-2xl p-6 transition-all hover:shadow-lg ${integration.connected
                                                ? 'border-emerald-500/30 hover:border-emerald-500/50'
                                                : 'border-surface-200 hover:border-surface-300'
                                            }`}
                                    >
                                        {integration.connected && (
                                            <div className="absolute top-4 right-4 w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center">
                                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                            </div>
                                        )}

                                        <div className="text-3xl mb-3">{integration.icon}</div>
                                        <h3 className="text-lg font-semibold text-slate-900 mb-1">{integration.name}</h3>
                                        <p className="text-sm text-slate-600 mb-4">{integration.description}</p>

                                        <div className="flex items-center justify-between">
                                            <span className={`text-xs font-medium ${integration.connected ? 'text-emerald-400' : 'text-slate-600'
                                                }`}>
                                                {integration.status}
                                            </span>
                                            <button className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${integration.connected
                                                    ? 'bg-precogs-50 hover:bg-surface-200 text-slate-700'
                                                    : 'bg-indigo-600 hover:bg-indigo-500 text-slate-900'
                                                }`}>
                                                {integration.connected ? 'Configure' : 'Connect'}
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* GitLab CI/CD Config */}
                            <div className="bg-white border border-surface-200 rounded-2xl p-6">
                                <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                                    <span className="text-2xl">🦊</span>
                                    GitLab CI/CD Configuration
                                </h3>

                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">GitLab URL</label>
                                        <input
                                            type="url"
                                            defaultValue="https://gitlab.jlrgroup.com"
                                            className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900 placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">Access Token</label>
                                        <input
                                            type="password"
                                            defaultValue="glpat-xxxxxxxxxxxx"
                                            className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900 placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                                        />
                                    </div>
                                    <div className="bg-precogs-50 rounded-xl p-4">
                                        <p className="text-xs text-slate-600 mb-2">Pipeline YAML snippet:</p>
                                        <pre className="text-xs text-precogs-600 font-mono overflow-x-auto">
                                            {`security_scan:
  stage: test
  script:
    - curl -X POST https://api.precogs.cloud/ci/scan
      -H "Authorization: Bearer $PRECOGS_TOKEN"
      -F "binary=@$CI_PROJECT_DIR/build/ecu.bin"`}
                                        </pre>
                                    </div>
                                </div>
                            </div>

                            {/* Jira Config */}
                            <div className="bg-white border border-surface-200 rounded-2xl p-6">
                                <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                                    <span className="text-2xl">📋</span>
                                    Jira Configuration
                                </h3>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">Jira URL</label>
                                        <input
                                            type="url"
                                            defaultValue="https://jlr.atlassian.net"
                                            className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">Project Key</label>
                                        <input
                                            type="text"
                                            defaultValue="ECUSEC"
                                            className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">API Token</label>
                                        <input
                                            type="password"
                                            defaultValue="••••••••••••"
                                            className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-sm font-medium text-slate-600 mb-2">Issue Type</label>
                                        <select className="w-full bg-precogs-50 border border-surface-300 rounded-xl px-4 py-3 text-slate-900">
                                            <option>Security Vulnerability</option>
                                            <option>Bug</option>
                                            <option>Task</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'notifications' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 mb-2">Notifications</h2>
                                <p className="text-slate-600">Configure how you receive alerts</p>
                            </div>

                            <div className="bg-white border border-surface-200 rounded-2xl divide-y divide-slate-800">
                                {/* Email Notifications */}
                                <div className="p-6 flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-xl bg-blue-500/20 flex items-center justify-center">
                                            <Mail className="w-5 h-5 text-blue-400" />
                                        </div>
                                        <div>
                                            <p className="font-medium text-slate-900">Email Notifications</p>
                                            <p className="text-sm text-slate-600">Receive vulnerability alerts via email</p>
                                        </div>
                                    </div>
                                    <Toggle
                                        enabled={notifications.email}
                                        onChange={() => setNotifications(prev => ({ ...prev, email: !prev.email }))}
                                    />
                                </div>

                                {/* Critical Alerts */}
                                <div className="p-6 flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center">
                                            <Shield className="w-5 h-5 text-red-400" />
                                        </div>
                                        <div>
                                            <p className="font-medium text-slate-900">Critical Vulnerability Alerts</p>
                                            <p className="text-sm text-slate-600">Immediate notification for critical findings</p>
                                        </div>
                                    </div>
                                    <Toggle
                                        enabled={notifications.critical}
                                        onChange={() => setNotifications(prev => ({ ...prev, critical: !prev.critical }))}
                                    />
                                </div>

                                {/* Scan Complete */}
                                <div className="p-6 flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                                            <Check className="w-5 h-5 text-emerald-400" />
                                        </div>
                                        <div>
                                            <p className="font-medium text-slate-900">Scan Completion</p>
                                            <p className="text-sm text-slate-600">Notify when scans finish</p>
                                        </div>
                                    </div>
                                    <Toggle
                                        enabled={notifications.scanComplete}
                                        onChange={() => setNotifications(prev => ({ ...prev, scanComplete: !prev.scanComplete }))}
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'api' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 mb-2">API Keys</h2>
                                <p className="text-slate-600">Manage API access for CI/CD integration</p>
                            </div>

                            <div className="bg-white border border-surface-200 rounded-2xl p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <div>
                                        <h3 className="font-semibold text-slate-900">Production API Key</h3>
                                        <p className="text-sm text-slate-600">Created Dec 1, 2024</p>
                                    </div>
                                    <span className="px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-full text-xs font-medium">Active</span>
                                </div>

                                <div className="flex gap-3">
                                    <div className="flex-1 bg-precogs-50 rounded-xl px-4 py-3 font-mono text-sm text-slate-700">
                                        psk_live_••••••••••••••••••••••••••••
                                    </div>
                                    <button className="px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl text-slate-900 transition-colors">
                                        Copy
                                    </button>
                                    <button className="px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl text-slate-900 transition-colors">
                                        Regenerate
                                    </button>
                                </div>
                            </div>

                            <button className="flex items-center gap-2 px-5 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-slate-900 font-medium transition-colors">
                                <Key className="w-4 h-4" />
                                Generate New API Key
                            </button>
                        </div>
                    )}

                    {activeTab === 'security' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 mb-2">Security</h2>
                                <p className="text-slate-600">Manage authentication and access</p>
                            </div>

                            <div className="bg-white border border-surface-200 rounded-2xl p-6 space-y-4">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <Lock className="w-5 h-5 text-slate-600" />
                                        <div>
                                            <p className="font-medium text-slate-900">Two-Factor Authentication</p>
                                            <p className="text-sm text-slate-600">Add an extra layer of security</p>
                                        </div>
                                    </div>
                                    <button className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-slate-900 text-sm font-medium transition-colors">
                                        Enable 2FA
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'appearance' && (
                        <div className="space-y-6">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 mb-2">Appearance</h2>
                                <p className="text-slate-600">Customize the look and feel</p>
                            </div>

                            <div className="bg-white border border-surface-200 rounded-2xl p-6">
                                <h3 className="font-semibold text-slate-900 mb-4">Theme</h3>
                                <div className="grid grid-cols-3 gap-4">
                                    <button className="p-4 bg-precogs-50/30 border-2 border-precogs-500 rounded-xl text-center">
                                        <div className="w-full h-8 bg-white rounded mb-2" />
                                        <span className="text-sm text-slate-900">Dark</span>
                                    </button>
                                    <button className="p-4 bg-slate-100 border border-slate-300 rounded-xl text-center opacity-50">
                                        <div className="w-full h-8 bg-white rounded mb-2" />
                                        <span className="text-sm text-slate-500">Light</span>
                                    </button>
                                    <button className="p-4 bg-gradient-to-br from-slate-900 to-slate-800 border border-surface-300 rounded-xl text-center opacity-50">
                                        <div className="w-full h-8 bg-precogs-50 rounded mb-2" />
                                        <span className="text-sm text-slate-600">System</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Save Button */}
                    <div className="flex justify-end pt-6 border-t border-surface-200 mt-8">
                        <button className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 rounded-xl text-slate-900 font-semibold shadow-lg shadow-indigo-500/20 transition-all">
                            <Save className="w-4 h-4" />
                            Save Changes
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

// Toggle component
const Toggle: React.FC<{ enabled: boolean; onChange: () => void }> = ({ enabled, onChange }) => (
    <button
        onClick={onChange}
        className={`relative w-14 h-8 rounded-full transition-colors ${enabled ? 'bg-indigo-600' : 'bg-slate-700'
            }`}
    >
        <div
            className={`absolute top-1 w-6 h-6 rounded-full bg-white shadow-lg transition-transform ${enabled ? 'left-7' : 'left-1'
                }`}
        />
    </button>
);

export default Settings;
