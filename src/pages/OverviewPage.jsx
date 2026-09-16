import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  Server, 
  AlertTriangle, 
  ArrowRight, 
  Radio, 
  Layers, 
  CheckCircle,
  ExternalLink,
  Flame,
  GitFork,
  RefreshCw,
  WifiOff,
  AlertCircle
} from 'lucide-react';
import { nexusApi } from '../services/api';
import StatCard from '../components/common/StatCard';
import SeverityBadge from '../components/common/SeverityBadge';

export const OverviewPage = () => {
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [attackChains, setAttackChains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [mRes, aRes, cRes] = await Promise.all([
        nexusApi.getMetrics(),
        nexusApi.getAlerts(),
        nexusApi.getAttackChains()
      ]);
      setMetrics(mRes.data || null);
      setAlerts(Array.isArray(aRes.data) ? aRes.data : []);
      setAttackChains(Array.isArray(cRes.data) ? cRes.data : []);
    } catch (err) {
      console.error("Failed to load overview data from API:", err);
      setError(
        err.response?.data?.message || 
        err.message || 
        "Unable to establish connection to the backend REST API."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex items-center gap-3 font-mono text-cyan-400">
          <Radio className="h-5 w-5 animate-spin" />
          <span>QUERYING LIVE NEXUS API ENDPOINTS...</span>
        </div>
      </div>
    );
  }

  const apiUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

  return (
    <div className="space-y-6">
      {/* Backend Disconnected Warning Banner if API fails */}
      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-4 backdrop-blur-xl shadow-[0_0_20px_rgba(244,63,94,0.15)] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="rounded-lg bg-rose-900/60 p-2 text-rose-400 ring-1 ring-rose-500/30 shrink-0">
              <WifiOff className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-rose-300">
                <span>BACKEND API OFFLINE</span>
                <span className="text-slate-400">({apiUrl})</span>
              </div>
              <p className="mt-1 text-xs text-rose-200/80 font-sans">
                {error}. Ensure your backend server is running and CORS is enabled.
              </p>
            </div>
          </div>
          <button
            onClick={loadDashboardData}
            className="flex items-center justify-center gap-2 rounded-lg border border-rose-400/40 bg-rose-950 px-4 py-2 font-mono text-xs font-bold text-rose-200 transition-all hover:bg-rose-900 active:scale-95 shrink-0"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            RETRY CONNECTION
          </button>
        </div>
      )}

      {/* Top Welcome & Mission Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyber-900 via-cyber-850 to-cyan-950/40 p-6 backdrop-blur-xl shadow-[0_0_30px_rgba(0,240,255,0.08)]">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping"></span>
              NEXUS INTELLIGENCE // SOC COMMAND ENGINE
            </div>
            <h1 className="mt-1 text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Cyber Attack Path Analysis & Graph Intelligence
            </h1>
            <p className="mt-1 text-xs text-slate-300 max-w-2xl font-sans leading-relaxed">
              Real-time multi-stage attack graph mapping, lateral movement detection, and proactive remediation modeling using Cytoscape.js and graph algorithms.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              to="/graph"
              className="flex items-center gap-2 rounded-lg border border-cyan-400 bg-cyan-500 px-4 py-2 font-mono text-xs font-bold text-black shadow-neon-cyan transition-all hover:bg-cyan-400 active:scale-95"
            >
              <GitFork className="h-4 w-4" />
              EXPLORE ATTACK GRAPH
            </Link>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Posture Score"
          value={metrics?.securityPostureScore != null ? `${metrics.securityPostureScore} / 100` : '—'}
          subtitle="Enterprise Defense Rating"
          color="amber"
          trend={metrics?.threatLevel ? `Threat Level: ${metrics.threatLevel}` : 'Awaiting Telemetry'}
          icon={ShieldAlert}
        />
        <StatCard
          title="Active Attack Paths"
          value={metrics?.activeAttackPaths != null ? metrics.activeAttackPaths : '—'}
          subtitle="Direct paths to Crown Jewels"
          color="rose"
          trend={metrics?.activeAttackPaths ? `${metrics.activeAttackPaths} High Risk Vectors` : 'No Critical Paths'}
          icon={Flame}
        />
        <StatCard
          title="Compromised Hosts"
          value={metrics?.compromisedNodes != null ? metrics.compromisedNodes : '—'}
          subtitle="Quarantine Required"
          color="rose"
          trend={metrics?.compromisedNodes ? `${metrics.compromisedNodes} Hosts In Quarantine Queue` : 'All Hosts Secure'}
          icon={Activity}
        />
        <StatCard
          title="Critical CVEs"
          value={metrics?.criticalVulnerabilities != null ? metrics.criticalVulnerabilities : '—'}
          subtitle="CVSS score >= 9.0"
          color="cyan"
          trend={metrics?.criticalVulnerabilities ? `${metrics.criticalVulnerabilities} Require Patching` : '0 Critical CVEs'}
          icon={Server}
        />
      </div>

      {/* Main Content Grid: Critical Attack Chain & Live Alerts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left 2 Cols: High Risk Attack Killchain */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-xl border border-white/10 bg-cyber-900/80 p-5 backdrop-blur-md">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="rounded-lg bg-rose-950/60 p-2 text-rose-400 ring-1 ring-rose-500/30">
                  <Flame className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-mono text-sm font-bold text-white uppercase">PRIMARY ACTIVE ATTACK KILLCHAIN</h3>
                  <p className="text-xs text-slate-400">Shortest path from Threat Actor to Crown Jewels</p>
                </div>
              </div>
              {attackChains[0] && (
                <span className="rounded bg-rose-950 px-2.5 py-1 font-mono text-xs font-bold text-rose-300 border border-rose-500/40">
                  {attackChains[0].likelihood ? `LIKELIHOOD ${attackChains[0].likelihood}` : 'ACTIVE KILLCHAIN'}
                </span>
              )}
            </div>

            {attackChains.length > 0 ? (
              <>
                {/* Stepper Visualization */}
                <div className="mt-5 space-y-3">
                  {attackChains[0].steps?.map((step, idx) => (
                    <div key={idx} className="flex items-center gap-3">
                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-rose-500/40 bg-rose-950/70 font-mono text-xs font-bold text-rose-300 shadow-neon-rose">
                        {idx + 1}
                      </div>
                      <div className="flex-1 rounded-lg border border-white/5 bg-cyber-950/80 px-3.5 py-2 text-xs font-mono text-slate-200">
                        {step}
                      </div>
                    </div>
                  ))}
                </div>

                {attackChains[0].mitigation && (
                  <div className="mt-5 rounded-lg border border-cyan-500/20 bg-cyan-950/30 p-3.5 flex items-start gap-3">
                    <CheckCircle className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-mono text-xs font-bold text-cyan-300">RECOMMENDED REMEDIATION:</span>
                      <p className="mt-0.5 text-xs text-slate-300">
                        {attackChains[0].mitigation}
                      </p>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="mt-8 mb-4 flex flex-col items-center justify-center text-center p-6 border border-dashed border-white/10 rounded-lg">
                <CheckCircle className="h-8 w-8 text-emerald-400/80 mb-2" />
                <p className="font-mono text-xs text-slate-300 font-bold">No Active Attack Killchains Detected</p>
                <p className="text-[11px] text-slate-500 mt-1 max-w-sm">
                  {error ? "Connect your live backend API to stream active killchain paths." : "All critical attack paths are currently mitigated or inactive."}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Right 1 Col: Live Alert Stream */}
        <div className="space-y-4">
          <div className="rounded-xl border border-white/10 bg-cyber-900/80 p-5 backdrop-blur-md">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 text-slate-200 font-mono text-xs font-bold uppercase">
                <Radio className="h-4 w-4 text-rose-400 animate-pulse" />
                <span>LIVE THREAT ALERTS</span>
              </div>
              <Link to="/threats" className="text-xs font-mono text-cyan-400 hover:underline">
                VIEW ALL
              </Link>
            </div>

            <div className="mt-4 space-y-3">
              {alerts.length > 0 ? (
                alerts.slice(0, 4).map((alert) => (
                  <div
                    key={alert.id}
                    className="rounded-lg border border-white/5 bg-cyber-950/80 p-3 transition-all hover:border-white/15"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="font-mono text-[11px] font-bold text-slate-200 leading-snug">
                        {alert.title}
                      </span>
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>Target: {alert.target}</span>
                      <span className="text-cyan-400">{alert.mitre}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-8 text-center text-xs font-mono text-slate-500">
                  <AlertCircle className="h-6 w-6 mx-auto mb-2 text-slate-600" />
                  <span>No security alerts reported.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OverviewPage;
