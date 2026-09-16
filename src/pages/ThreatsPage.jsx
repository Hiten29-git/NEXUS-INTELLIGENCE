import React, { useState, useEffect, useCallback } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  Radio, 
  Filter, 
  Clock, 
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  WifiOff,
  AlertCircle
} from 'lucide-react';
import { nexusApi } from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export const ThreatsPage = () => {
  const [alerts, setAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [mitigatedAlerts, setMitigatedAlerts] = useState(new Set());

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await nexusApi.getAlerts();
      setAlerts(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error("Failed to load alerts from API:", err);
      setError(
        err.response?.data?.message || 
        err.message || 
        "Unable to fetch threat alerts from backend API."
      );
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const handleMitigate = (alertId) => {
    setMitigatedAlerts(prev => new Set(prev).add(alertId));
  };

  const filteredAlerts = alerts.filter(a => {
    const sev = a.severity || '';
    return filterSeverity === 'ALL' || sev.toUpperCase() === filterSeverity.toUpperCase();
  });

  const mitreTactics = [
    { id: 'T1190', name: 'Exploit Public-Facing Application', phase: 'Initial Access', status: 'Active Telemetry' },
    { id: 'T1059', name: 'Command & Scripting Interpreter', phase: 'Execution', status: 'Monitored' },
    { id: 'T1021.002', name: 'SMB / Windows Admin Shares', phase: 'Lateral Movement', status: 'Monitored' },
    { id: 'T1003.006', name: 'DCSync / Kerberoasting', phase: 'Credential Access', status: 'High Alert' },
    { id: 'T1567', name: 'Exfiltration to Cloud Storage', phase: 'Exfiltration', status: 'Guarded' },
  ];

  const apiUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-rose-400">
            <Radio className="h-4 w-4 animate-pulse" />
            LIVE SECURITY INCIDENT & ALERT FEED
          </div>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-white">Threat Detection & MITRE ATT&CK</h2>
          <p className="text-xs text-slate-400 font-mono">
            Correlated attack telemetry mapped directly to MITRE ATT&CK tactics and killchains.
          </p>
        </div>

        {/* Severity filter & Refresh */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">SEVERITY:</span>
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`rounded-lg px-2.5 py-1 transition-all ${
                filterSeverity.toUpperCase() === sev.toUpperCase()
                  ? 'bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/40'
                  : 'text-slate-400 hover:text-white bg-cyber-900'
              }`}
            >
              {sev}
            </button>
          ))}

          <button
            onClick={loadAlerts}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyber-900 px-3 py-1 text-cyan-300 hover:bg-cyan-950/40 ml-2"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            REFRESH
          </button>
        </div>
      </div>

      {/* Backend Disconnected Warning Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-rose-500/40 bg-rose-950/80 p-3 font-mono text-xs text-rose-300 shadow-neon-rose">
          <div className="flex items-center gap-2">
            <WifiOff className="h-4 w-4 text-rose-400 shrink-0" />
            <span>Backend API Offline ({apiUrl}): {error}</span>
          </div>
          <button onClick={loadAlerts} className="text-rose-200 underline font-bold hover:text-white ml-3 shrink-0">
            Retry
          </button>
        </div>
      )}

      {/* MITRE ATT&CK Matrix Banner */}
      <div className="rounded-xl border border-white/10 bg-cyber-900/80 p-5 backdrop-blur-md">
        <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3">
          MITRE ATT&CK ENTERPRISE KILLCHAIN COVERAGE
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 font-mono text-xs">
          {mitreTactics.map((t) => (
            <div
              key={t.id}
              className="rounded-lg border border-white/5 bg-cyber-950 p-3 flex flex-col justify-between"
            >
              <div>
                <span className="text-[10px] text-slate-500 block uppercase">{t.phase}</span>
                <span className="font-bold text-rose-300 mt-1 block">{t.id}</span>
                <span className="text-[11px] text-slate-300 mt-1 block font-sans leading-snug">{t.name}</span>
              </div>
              <div className="mt-3 pt-2 border-t border-white/5">
                <span className="inline-block text-[10px] text-cyan-400 font-bold">● {t.status}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {loading ? (
          <div className="flex h-64 items-center justify-center rounded-xl border border-white/10 bg-cyber-950 font-mono text-xs text-cyan-400">
            <RefreshCw className="h-5 w-5 animate-spin mr-2" />
            STREAMING INCIDENTS FROM REST API...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/10 bg-cyber-950/70 p-12 text-center font-mono">
            <AlertCircle className="h-10 w-10 text-slate-600 mx-auto mb-3" />
            <h3 className="text-sm font-bold text-slate-300">No Security Incidents Detected</h3>
            <p className="mt-1 text-xs text-slate-500 font-sans max-w-sm mx-auto">
              {error ? `Backend API is offline at ${apiUrl}. Launch your backend service to stream live detections.` : "No alerts matched the selected severity level."}
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isMitigated = mitigatedAlerts.has(alert.id);

            return (
              <div
                key={alert.id}
                className={`rounded-xl border p-5 backdrop-blur-md transition-all font-mono text-xs ${
                  isMitigated
                    ? 'border-emerald-500/30 bg-emerald-950/20 opacity-75'
                    : alert.severity?.toUpperCase() === 'CRITICAL'
                    ? 'border-rose-500/40 bg-cyber-900/90 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
                    : 'border-white/10 bg-cyber-900/80'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-1.5 rounded-lg ${isMitigated ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'}`}>
                      {isMitigated ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                    </div>
                    <div>
                      <span className="font-bold text-white text-sm">{alert.title}</span>
                      <div className="text-[10px] text-slate-400 flex items-center gap-3 mt-0.5">
                        <span>ID: {alert.id}</span>
                        {alert.timestamp && (
                          <>
                            <span>•</span>
                            <span>Detected: {alert.timestamp}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={isMitigated ? 'Mitigated' : alert.severity || 'HIGH'} />
                    {alert.mitre && (
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-cyan-300">
                        {alert.mitre}
                      </span>
                    )}
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  <div className="rounded-lg bg-cyber-950 p-2.5">
                    <span className="text-slate-500 text-[10px] block">SOURCE IP</span>
                    <span className="text-cyan-300">{alert.source || 'N/A'}</span>
                  </div>
                  <div className="rounded-lg bg-cyber-950 p-2.5">
                    <span className="text-slate-500 text-[10px] block">TARGET ASSET</span>
                    <span className="text-rose-300">{alert.target || 'N/A'}</span>
                  </div>
                  <div className="rounded-lg bg-cyber-950 p-2.5">
                    <span className="text-slate-500 text-[10px] block">STATUS</span>
                    <span className="text-slate-200">{isMitigated ? 'Mitigated by Operator' : alert.status || 'Active'}</span>
                  </div>
                </div>

                <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-white/5">
                  <div className="text-slate-300 font-sans text-xs">
                    <strong className="font-mono text-cyan-300">Action Plan: </strong>
                    {alert.actionRequired || `Isolate target asset (${alert.target || 'host'}) and inspect recent network sessions.`}
                  </div>

                  {!isMitigated ? (
                    <button
                      onClick={() => handleMitigate(alert.id)}
                      className="rounded-lg border border-rose-500/50 bg-rose-950/60 px-3.5 py-1.5 font-mono text-xs font-bold text-rose-300 hover:bg-rose-500 hover:text-black transition-colors"
                    >
                      TRIGGER CONTAINMENT
                    </button>
                  ) : (
                    <span className="text-emerald-400 font-mono text-xs flex items-center gap-1">
                      <CheckCircle2 className="h-3.5 w-3.5" /> CONTAINMENT EXECUTED
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default ThreatsPage;
