import React, { useState, useEffect } from 'react';
import { Shield, Server, RefreshCw, Clock, CheckCircle2, AlertCircle } from 'lucide-react';
import { getServerBaseUrl, nexusApi } from '../../services/api';

export const Navbar = ({ onRefresh, isRefreshing, onOpenServerModal }) => {
  const [serverUrl, setServerUrl] = useState(getServerBaseUrl());
  const [serverStatus, setServerStatus] = useState('checking'); // 'online' | 'offline' | 'checking'
  const [time, setTime] = useState(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));

  const checkConnectivity = async () => {
    try {
      await nexusApi.checkHealth();
      setServerStatus('online');
    } catch {
      setServerStatus('offline');
    }
  };

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    checkConnectivity();
    const interval = setInterval(checkConnectivity, 12000);

    const handleUrlChange = (e) => {
      setServerUrl(e.detail || getServerBaseUrl());
      checkConnectivity();
    };

    window.addEventListener('nexus_server_url_changed', handleUrlChange);
    return () => {
      clearInterval(interval);
      window.removeEventListener('nexus_server_url_changed', handleUrlChange);
    };
  }, []);

  // Parse a friendly server host label
  let serverDisplayHost = 'Server';
  try {
    const parsed = new URL(serverUrl);
    serverDisplayHost = parsed.host;
  } catch {
    serverDisplayHost = serverUrl.replace(/^https?:\/\//, '').split('/')[0];
  }

  return (
    <header className="sticky top-0 z-40 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-slate-900/95 px-6 backdrop-blur font-sans">
      {/* Brand Identity */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-bold tracking-tight text-white">NEXUS</span>
          </div>
          <p className="text-[11px] text-slate-400 font-normal">Threat Intelligence & Attack Path Platform</p>
        </div>
      </div>

      {/* Right Controls & Server IP Status */}
      <div className="flex items-center gap-3">
        {/* Live Server IP Button */}
        <button
          onClick={onOpenServerModal}
          title="Click to configure or change backend server IP"
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-750 hover:border-slate-600 transition-colors"
        >
          <Server className="h-3.5 w-3.5 text-blue-400" />
          <span className="hidden sm:inline font-mono text-[11px] text-slate-300">{serverDisplayHost}</span>
          <span className="flex items-center gap-1">
            {serverStatus === 'online' ? (
              <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Online
              </span>
            ) : serverStatus === 'offline' ? (
              <span className="flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                <span className="h-2 w-2 rounded-full bg-rose-500" />
                Offline
              </span>
            ) : (
              <span className="h-2 w-2 rounded-full bg-slate-500 animate-pulse" />
            )}
          </span>
        </button>

        {/* Live Clock */}
        <div className="hidden md:flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-400 font-mono">
          <Clock className="h-3.5 w-3.5 text-slate-500" />
          <span>{time}</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-colors active:scale-95 disabled:opacity-50"
          title="Refresh dashboard data"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </div>
    </header>
  );
};

export default Navbar;
