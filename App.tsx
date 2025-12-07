import React, { useState, useEffect, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import NewScan from './components/NewScan';
import ScanDetails from './components/ScanDetails';
import { ViewState, ScanSession, ScanConfig, ConnectionStatus } from './types';
import { simulateScanStep } from './services/simulationService';
import { DastApi } from './services/api';

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewState>('dashboard');
  const [activeSession, setActiveSession] = useState<ScanSession | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('checking');
  
  // Polling ref to manage intervals
  const pollingRef = useRef<number | null>(null);

  // Check backend health on mount
  useEffect(() => {
    const checkBackend = async () => {
      const isHealthy = await DastApi.checkHealth();
      setConnectionStatus(isHealthy ? 'connected' : 'disconnected');
    };
    checkBackend();
  }, []);

  // Main Effect: Polling or Simulation
  useEffect(() => {
    if (activeSession && activeSession.status === 'running') {
      
      if (connectionStatus === 'connected') {
        // --- REAL MODE: Poll Backend ---
        pollingRef.current = window.setInterval(async () => {
           try {
             const update = await DastApi.getScanStatus(activeSession.id);
             setActiveSession(prev => {
                if (!prev) return null;
                // Merge logs to avoid duplicates if necessary, or just replace if backend sends full history
                // Assuming backend sends full object for now
                return { ...prev, ...update } as ScanSession;
             });

             if (update.status === 'completed' || update.status === 'failed') {
               if (pollingRef.current) clearInterval(pollingRef.current);
             }
           } catch (e) {
             console.error("Polling failed", e);
             // Optionally handle connection loss
           }
        }, 1000);

      } else {
        // --- DEMO MODE: Local Simulation ---
        pollingRef.current = window.setInterval(() => {
            setActiveSession(prevSession => {
                if (!prevSession) return null;
                
                const elapsed = Date.now() - prevSession.startTime;
                const result = simulateScanStep(elapsed, prevSession.config, prevSession.findings);

                const updatedSession: ScanSession = {
                    ...prevSession,
                    logs: [...prevSession.logs, ...result.logs],
                    findings: result.newFinding ? [result.newFinding, ...prevSession.findings] : prevSession.findings,
                    progress: result.progress,
                    currentStage: result.stage,
                    status: result.complete ? 'completed' : 'running',
                };
                
                if (result.complete && pollingRef.current) {
                    clearInterval(pollingRef.current);
                }
                return updatedSession;
            });
        }, 500);
      }
    }

    return () => {
        if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [activeSession?.status, connectionStatus]);

  const startScan = async (config: ScanConfig, file: File) => {
    let newSession: ScanSession;

    if (connectionStatus === 'connected') {
        try {
            // 1. Upload
            const uploadRes = await DastApi.uploadBinary(file);
            
            // 2. Start Scan
            const startRes = await DastApi.startScan(uploadRes.file_id, config);
            
            // 3. Init Session
            newSession = {
                id: startRes.scan_id,
                status: 'running',
                progress: 0,
                config,
                startTime: Date.now(),
                logs: [],
                findings: [],
                currentStage: 'Initializing Backend...',
            };
        } catch (e) {
            console.error("Failed to start backend scan", e);
            alert("Backend error. Falling back to local mode.");
            // Fallback to local
            setConnectionStatus('disconnected');
            startScan(config, file);
            return;
        }
    } else {
        // Local Simulation
        newSession = {
            id: `sim-${Math.floor(Math.random() * 10000)}`,
            status: 'running',
            progress: 0,
            config,
            startTime: Date.now(),
            logs: [],
            findings: [],
            currentStage: 'Initializing Environment',
        };
    }

    setActiveSession(newSession);
    setCurrentView('scan-details');
  };

  const renderContent = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard onNewScan={() => setCurrentView('new-scan')} />;
      case 'new-scan':
        return <NewScan onStart={startScan} onCancel={() => setCurrentView('dashboard')} />;
      case 'scan-details':
        if (!activeSession) return <Dashboard onNewScan={() => setCurrentView('new-scan')} />;
        return <ScanDetails session={activeSession} onBack={() => setCurrentView('dashboard')} />;
      default:
        return <Dashboard onNewScan={() => setCurrentView('new-scan')} />;
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-200">
      <Sidebar 
        currentView={currentView} 
        setView={setCurrentView} 
        connectionStatus={connectionStatus}
      />
      <main className="flex-1 overflow-hidden relative">
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>
        {renderContent()}
      </main>
    </div>
  );
};

export default App;