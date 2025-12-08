import React, { useState, useRef, useEffect } from 'react';
import {
    MessageSquare, Send, Sparkles, Loader2, Bot, User, Copy, Check,
    ChevronDown, Shield, Bug, Lightbulb, Code, FileCode, AlertTriangle,
    Zap, BookOpen, Target, RefreshCw
} from 'lucide-react';
import { Vulnerability, ScanSession } from '../types';

interface AICopilotProps {
    scan?: ScanSession | null;
    vulnerability?: Vulnerability | null;
    onClose?: () => void;
}

interface Message {
    id: string;
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: Date;
    isLoading?: boolean;
}

const QUICK_PROMPTS = [
    { icon: Bug, label: 'Explain this vulnerability', prompt: 'Explain this vulnerability in detail and its potential impact on automotive ECU systems.' },
    { icon: Code, label: 'Generate PoC', prompt: 'Generate a proof of concept exploit for this vulnerability with safe testing considerations.' },
    { icon: Shield, label: 'Remediation steps', prompt: 'Provide detailed remediation steps with code examples to fix this vulnerability.' },
    { icon: Target, label: 'Attack vectors', prompt: 'What are the potential attack vectors for exploiting this vulnerability in an automotive context?' },
    { icon: Lightbulb, label: 'Best practices', prompt: 'What secure coding best practices would prevent this type of vulnerability?' },
    { icon: BookOpen, label: 'Compliance impact', prompt: 'How does this vulnerability affect ISO 21434, UNECE R155, and ISO 26262 compliance?' },
];

const AICopilot: React.FC<AICopilotProps> = ({ scan, vulnerability, onClose }) => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLTextAreaElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Initialize with context
    useEffect(() => {
        if (vulnerability) {
            const contextMessage: Message = {
                id: 'context',
                role: 'system',
                content: `**Analyzing ${vulnerability.cweId}: ${vulnerability.title}**\n\nI'm your AI Security CoPilot. I can help you understand this vulnerability, generate remediation code, create proof-of-concept exploits for testing, or explain its compliance implications.\n\nSelect a quick action below or ask me anything!`,
                timestamp: new Date(),
            };
            setMessages([contextMessage]);
        } else if (scan) {
            const findingsCount = scan.findings?.length || 0;
            const criticalCount = scan.findings?.filter(f => f.severity === 'critical').length || 0;
            const contextMessage: Message = {
                id: 'context',
                role: 'system',
                content: `**Scan Analysis Ready**\n\nI've analyzed your scan with **${findingsCount} findings** (${criticalCount} critical). I can help you:\n\n• Prioritize which vulnerabilities to fix first\n• Generate bulk remediation guidance\n• Explain patterns across findings\n• Create a security improvement roadmap\n\nWhat would you like to explore?`,
                timestamp: new Date(),
            };
            setMessages([contextMessage]);
        }
    }, [vulnerability, scan]);

    const handleSend = async (prompt?: string) => {
        const messageText = prompt || input.trim();
        if (!messageText) return;

        const userMessage: Message = {
            id: Date.now().toString(),
            role: 'user',
            content: messageText,
            timestamp: new Date(),
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        // Add loading message
        const loadingMessage: Message = {
            id: 'loading',
            role: 'assistant',
            content: '',
            timestamp: new Date(),
            isLoading: true,
        };
        setMessages(prev => [...prev, loadingMessage]);

        try {
            // Build context
            const context = vulnerability
                ? `Vulnerability: ${vulnerability.cweId} - ${vulnerability.title}\nSeverity: ${vulnerability.severity}\nDescription: ${vulnerability.description}\nCode: ${vulnerability.codeSnippet}\nRemediation: ${vulnerability.remediation}`
                : scan
                    ? `Scan summary: ${scan.findings?.length || 0} findings, ECU firmware analysis`
                    : '';

            const response = await fetch('http://localhost:8000/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: messageText,
                    context: context,
                    vulnerability: vulnerability ? {
                        cweId: vulnerability.cweId,
                        title: vulnerability.title,
                        severity: vulnerability.severity,
                        description: vulnerability.description,
                        codeSnippet: vulnerability.codeSnippet,
                    } : null,
                }),
            });

            const data = await response.json();

            // Replace loading message with response
            setMessages(prev => prev.filter(m => m.id !== 'loading').concat({
                id: Date.now().toString(),
                role: 'assistant',
                content: data.response || data.message || 'I apologize, but I could not generate a response. Please try again.',
                timestamp: new Date(),
            }));
        } catch (error) {
            // Replace loading with error
            setMessages(prev => prev.filter(m => m.id !== 'loading').concat({
                id: Date.now().toString(),
                role: 'assistant',
                content: '⚠️ Unable to connect to AI service. Please ensure the backend is running and try again.',
                timestamp: new Date(),
            }));
        } finally {
            setIsLoading(false);
        }
    };

    const handleCopy = (content: string, id: string) => {
        navigator.clipboard.writeText(content);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    return (
        <div className="flex flex-col h-full bg-white border-l border-surface-200">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-surface-200 bg-gradient-to-r from-precogs-50 to-purple-50">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-precogs-500 to-purple-600 flex items-center justify-center">
                        <Sparkles className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h3 className="font-semibold text-slate-900">AI Security CoPilot</h3>
                        <p className="text-xs text-slate-500">Powered by Precogs AI</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setMessages([])}
                        className="p-2 text-slate-400 hover:text-slate-600 hover:bg-surface-100 rounded-lg transition-colors"
                        title="Clear conversation"
                    >
                        <RefreshCw className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.length === 0 && (
                    <div className="text-center py-12">
                        <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-precogs-100 to-purple-100 flex items-center justify-center mb-4">
                            <Bot className="w-8 h-8 text-precogs-600" />
                        </div>
                        <h3 className="text-lg font-semibold text-slate-800 mb-2">AI Security CoPilot</h3>
                        <p className="text-sm text-slate-500 max-w-xs mx-auto">
                            Ask me about vulnerabilities, get remediation guidance, or generate proof-of-concept exploits for testing.
                        </p>
                    </div>
                )}

                {messages.map((message) => (
                    <div
                        key={message.id}
                        className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                        {message.role !== 'user' && (
                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${message.role === 'system' ? 'bg-precogs-100' : 'bg-gradient-to-br from-precogs-500 to-purple-600'
                                }`}>
                                {message.role === 'system' ? (
                                    <Zap className="w-4 h-4 text-precogs-600" />
                                ) : (
                                    <Bot className="w-4 h-4 text-white" />
                                )}
                            </div>
                        )}

                        <div className={`max-w-[80%] ${message.role === 'user' ? 'order-first' : ''}`}>
                            <div className={`rounded-2xl px-4 py-3 ${message.role === 'user'
                                    ? 'bg-gradient-to-r from-precogs-600 to-purple-600 text-white rounded-br-md'
                                    : message.role === 'system'
                                        ? 'bg-gradient-to-r from-precogs-50 to-purple-50 border border-precogs-200 text-slate-800 rounded-bl-md'
                                        : 'bg-surface-100 text-slate-800 rounded-bl-md'
                                }`}>
                                {message.isLoading ? (
                                    <div className="flex items-center gap-2">
                                        <Loader2 className="w-4 h-4 animate-spin text-precogs-600" />
                                        <span className="text-sm text-slate-500">Analyzing...</span>
                                    </div>
                                ) : (
                                    <div className="text-sm whitespace-pre-wrap leading-relaxed">
                                        {message.content.split('**').map((part, i) =>
                                            i % 2 === 1 ? <strong key={i}>{part}</strong> : part
                                        )}
                                    </div>
                                )}
                            </div>

                            {message.role === 'assistant' && !message.isLoading && (
                                <div className="flex items-center gap-2 mt-1 ml-1">
                                    <button
                                        onClick={() => handleCopy(message.content, message.id)}
                                        className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600 transition-colors"
                                    >
                                        {copiedId === message.id ? (
                                            <>
                                                <Check className="w-3 h-3" />
                                                Copied
                                            </>
                                        ) : (
                                            <>
                                                <Copy className="w-3 h-3" />
                                                Copy
                                            </>
                                        )}
                                    </button>
                                </div>
                            )}
                        </div>

                        {message.role === 'user' && (
                            <div className="w-8 h-8 rounded-lg bg-slate-200 flex items-center justify-center flex-shrink-0">
                                <User className="w-4 h-4 text-slate-600" />
                            </div>
                        )}
                    </div>
                ))}
                <div ref={messagesEndRef} />
            </div>

            {/* Quick Prompts */}
            {messages.length <= 1 && (
                <div className="px-4 py-3 border-t border-surface-100">
                    <p className="text-xs text-slate-500 mb-2 font-medium">Quick Actions</p>
                    <div className="grid grid-cols-2 gap-2">
                        {QUICK_PROMPTS.slice(0, 4).map((item, idx) => (
                            <button
                                key={idx}
                                onClick={() => handleSend(item.prompt)}
                                disabled={isLoading}
                                className="flex items-center gap-2 px-3 py-2 bg-surface-50 hover:bg-surface-100 border border-surface-200 rounded-lg text-xs text-slate-600 hover:text-slate-800 transition-colors text-left disabled:opacity-50"
                            >
                                <item.icon className="w-3.5 h-3.5 text-precogs-500 flex-shrink-0" />
                                <span className="truncate">{item.label}</span>
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {/* Input */}
            <div className="p-4 border-t border-surface-200 bg-surface-50">
                <div className="flex items-end gap-2">
                    <textarea
                        ref={inputRef}
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ask about vulnerabilities, remediation, or compliance..."
                        rows={1}
                        className="flex-1 resize-none bg-white border border-surface-300 rounded-xl px-4 py-3 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-precogs-500 focus:border-precogs-500"
                    />
                    <button
                        onClick={() => handleSend()}
                        disabled={!input.trim() || isLoading}
                        className="p-3 bg-gradient-to-r from-precogs-600 to-purple-600 hover:from-precogs-700 hover:to-purple-700 disabled:from-slate-300 disabled:to-slate-300 text-white rounded-xl transition-all disabled:cursor-not-allowed"
                    >
                        {isLoading ? (
                            <Loader2 className="w-5 h-5 animate-spin" />
                        ) : (
                            <Send className="w-5 h-5" />
                        )}
                    </button>
                </div>
                <p className="text-xs text-slate-400 mt-2 text-center">
                    AI responses are for guidance only. Always verify security recommendations.
                </p>
            </div>
        </div>
    );
};

export default AICopilot;
