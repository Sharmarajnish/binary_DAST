import React, { useState } from 'react';
import { Upload, Cpu, Play, Settings2, FileCode, AlertCircle } from 'lucide-react';
import { ARCHITECTURES } from '../constants';
import { ScanConfig } from '../types';

interface NewScanProps {
  onStart: (config: ScanConfig, file: File) => void;
  onCancel: () => void;
}

const NewScan: React.FC<NewScanProps> = ({ onStart, onCancel }) => {
  const [file, setFile] = useState<File | null>(null);
  const [config, setConfig] = useState<ScanConfig>({
    binaryName: '',
    binarySize: 0,
    architecture: 'arm',
    modules: {
      fuzzing: true,
      symbolic: true,
      taint: false,
    },
    timeout: 300,
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      setConfig({
        ...config,
        binaryName: selectedFile.name,
        binarySize: selectedFile.size,
      });
    }
  };

  const handleStart = () => {
    if (file) {
      onStart(config, file);
    }
  };

  return (
    <div className="p-8 h-full overflow-y-auto flex justify-center">
      <div className="max-w-3xl w-full space-y-8">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Configure DAST Scan</h2>
          <p className="text-slate-400">Upload an ECU binary and configure analysis modules.</p>
        </div>

        {/* File Upload Section */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
            <FileCode className="w-5 h-5 text-brand-500" />
            Binary Selection
          </h3>
          
          <div className="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center hover:bg-slate-800/50 hover:border-brand-500/50 transition-all">
            <input 
              type="file" 
              id="binary-upload" 
              className="hidden" 
              onChange={handleFileChange}
              accept=".bin,.elf,.hex,.s19,.vbf" 
            />
            <label htmlFor="binary-upload" className="cursor-pointer flex flex-col items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center">
                <Upload className="w-6 h-6 text-slate-400" />
              </div>
              <div>
                {file ? (
                    <span className="text-brand-400 font-medium text-lg">{file.name}</span>
                ) : (
                    <span className="text-slate-300 font-medium">Click to upload firmware</span>
                )}
                <p className="text-sm text-slate-500 mt-1">
                  {file ? `${(file.size / 1024).toFixed(2)} KB` : 'Supports .bin, .elf, .vbf'}
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Configuration Section */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
           <h3 className="text-lg font-medium text-white mb-6 flex items-center gap-2">
            <Settings2 className="w-5 h-5 text-brand-500" />
            Scan Parameters
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Architecture */}
            <div className="space-y-3">
                <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                    <Cpu className="w-4 h-4" />
                    Target Architecture
                </label>
                <div className="grid grid-cols-2 gap-3">
                    {ARCHITECTURES.map((arch) => (
                        <button
                            key={arch.id}
                            onClick={() => setConfig({ ...config, architecture: arch.id as any })}
                            className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${
                                config.architecture === arch.id
                                    ? 'bg-brand-600/20 border-brand-500 text-brand-400'
                                    : 'bg-slate-950 border-slate-700 text-slate-400 hover:border-slate-600'
                            }`}
                        >
                            {arch.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Modules */}
            <div className="space-y-3">
                <label className="text-sm font-medium text-slate-300">Analysis Modules</label>
                <div className="space-y-3">
                    <label className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-700 cursor-pointer hover:border-slate-600">
                        <div className="flex flex-col">
                            <span className="text-sm font-medium text-slate-200">Fuzzing (AFL++)</span>
                            <span className="text-xs text-slate-500">Random input mutation for crash detection</span>
                        </div>
                        <input 
                            type="checkbox" 
                            checked={config.modules.fuzzing}
                            onChange={(e) => setConfig({...config, modules: {...config.modules, fuzzing: e.target.checked}})}
                            className="w-4 h-4 rounded border-slate-600 text-brand-600 focus:ring-offset-slate-900"
                        />
                    </label>
                    <label className="flex items-center justify-between p-3 bg-slate-950 rounded-lg border border-slate-700 cursor-pointer hover:border-slate-600">
                         <div className="flex flex-col">
                            <span className="text-sm font-medium text-slate-200">Symbolic Execution (Angr)</span>
                            <span className="text-xs text-slate-500">Path exploration for logic flaws</span>
                        </div>
                        <input 
                            type="checkbox" 
                            checked={config.modules.symbolic}
                            onChange={(e) => setConfig({...config, modules: {...config.modules, symbolic: e.target.checked}})}
                            className="w-4 h-4 rounded border-slate-600 text-brand-600 focus:ring-offset-slate-900"
                        />
                    </label>
                </div>
            </div>
          </div>

           {/* Info Box */}
           <div className="mt-8 p-4 bg-slate-950/50 rounded-lg border border-slate-800 flex gap-3">
                <AlertCircle className="w-5 h-5 text-slate-400 shrink-0" />
                <p className="text-sm text-slate-400">
                    A full scan with Symbolic Execution may take up to 45 minutes for binaries larger than 2MB. 
                    Fuzzing will run for the default timeout of 5 minutes unless configured otherwise.
                </p>
           </div>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-end gap-4">
            <button 
                onClick={onCancel}
                className="px-6 py-3 rounded-lg text-slate-400 hover:text-white font-medium hover:bg-slate-800 transition-colors"
            >
                Cancel
            </button>
            <button 
                onClick={handleStart}
                disabled={!file}
                className={`flex items-center gap-2 px-8 py-3 rounded-lg font-bold shadow-lg transition-all ${
                    file 
                    ? 'bg-brand-600 hover:bg-brand-500 text-white shadow-brand-600/20 active:scale-95' 
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                }`}
            >
                <Play className="w-5 h-5" />
                Start DAST Analysis
            </button>
        </div>
      </div>
    </div>
  );
};

export default NewScan;