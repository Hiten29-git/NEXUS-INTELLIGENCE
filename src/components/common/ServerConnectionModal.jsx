import React, { useState, useEffect } from 'react';
import { Server, Wifi, WifiOff, CheckCircle2, AlertCircle, RefreshCw, X, Globe, ArrowRight } from 'lucide-react';
import { getServerBaseUrl, setServerBaseUrl, testServerConnection, normalizeServerUrl } from '../../services/api';

export const ServerConnectionModal = ({ isOpen, onClose, onConnected }) => {
  const [inputUrl, setInputUrl] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [currentUrl, setCurrentUrl] = useState('');

  useEffect(() => {
    if (isOpen) {
      const active = getServerBaseUrl();
      setCurrentUrl(active);
      setInputUrl(active);
      setTestResult(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleTest = async () => {
    if (!inputUrl.trim()) return;
    setTesting(true);
    setTestResult(null);
    const result = await testServerConnection(inputUrl);
    setTestResult(result);
    setTesting(false);
  };

  const handleSave = () => {
    const saved = setServerBaseUrl(inputUrl);
    setCurrentUrl(saved);
    if (onConnected) onConnected(saved);
    onClose();
  };

  const handleReset = () => {
    const defaultUrl = 'http://localhost:8000/api/v1';
    setInputUrl(defaultUrl);
    setTestResult(null);
  };

  const applyPreset = (url) => {
    setInputUrl(url);
    setTestResult(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl text-slate-100 font-sans">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-600/10 p-2 text-blue-400 border border-blue-500/20">
              <Server className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Server Connection Settings</h3>
              <p className="text-xs text-slate-400">Configure your live backend server IP address and port</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Current Active Server */}
        <div className="mt-4 rounded-lg bg-slate-950 p-3.5 border border-slate-800">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">Current Target Server:</span>
            <span className="font-mono text-blue-400 font-medium truncate max-w-xs">{currentUrl}</span>
          </div>
        </div>

        {/* Input Section */}
        <div className="mt-5 space-y-3">
          <label className="block text-xs font-medium text-slate-300">
            Server IP Address / Hostname
          </label>
          <div className="relative">
            <Globe className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => {
                setInputUrl(e.target.value);
                setTestResult(null);
              }}
              placeholder="e.g. 192.168.1.50:8000 or http://10.0.0.5:8000"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-9 pr-3 text-sm text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none font-mono"
            />
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            Enter the IP and port of your backend server. Standard endpoints (<code className="text-slate-400">/api/v1</code>) are automatically mapped.
          </p>

          {/* Quick Presets */}
          <div className="flex items-center gap-2 pt-1 text-xs">
            <span className="text-slate-400">Quick presets:</span>
            <button
              type="button"
              onClick={() => applyPreset('http://localhost:8000/api/v1')}
              className="rounded bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            >
              localhost:8000
            </button>
            <button
              type="button"
              onClick={() => applyPreset('http://127.0.0.1:8000/api/v1')}
              className="rounded bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            >
              127.0.0.1:8000
            </button>
            <button
              type="button"
              onClick={() => applyPreset('http://10.172.180.14:8000/api/v1')}
              className="rounded bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            >
              Host LAN IP
            </button>
          </div>
        </div>

        {/* Test Result Feedback */}
        {testResult && (
          <div className={`mt-4 rounded-lg p-3.5 text-xs flex items-start gap-2.5 border ${
            testResult.success
              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
          }`}>
            {testResult.success ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="font-semibold">
                {testResult.success ? `Connected Successfully (${testResult.latency}ms)` : 'Connection Failed'}
              </div>
              <div className="text-[11px] opacity-80 mt-0.5 font-mono">
                {testResult.success 
                  ? `Server responded at ${testResult.url}` 
                  : `${testResult.error}. Make sure the server at ${testResult.url} is running and reachable.`}
              </div>
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div className="mt-6 flex items-center justify-between border-t border-slate-800 pt-4 text-xs">
          <button
            type="button"
            onClick={handleReset}
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            Reset Default
          </button>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={handleTest}
              disabled={testing || !inputUrl.trim()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 font-medium text-slate-200 hover:bg-slate-750 hover:text-white transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${testing ? 'animate-spin' : ''}`} />
              {testing ? 'Testing...' : 'Test Connection'}
            </button>

            <button
              type="button"
              onClick={handleSave}
              disabled={!inputUrl.trim()}
              className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
            >
              Save & Connect
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ServerConnectionModal;
