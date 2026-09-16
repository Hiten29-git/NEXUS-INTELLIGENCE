import React, { useState, useEffect, useCallback } from 'react';
import { 
  Server, 
  Search, 
  Filter, 
  ShieldAlert, 
  AlertTriangle, 
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  Cpu,
  Lock,
  RefreshCw,
  WifiOff,
  AlertCircle
} from 'lucide-react';
import { nexusApi } from '../services/api';
import SeverityBadge from '../components/common/SeverityBadge';

export const AssetInventoryPage = () => {
  const [assets, setAssets] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCriticality, setFilterCriticality] = useState('ALL');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAssets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await nexusApi.getAssets();
      setAssets(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error("Failed to load assets from API:", err);
      setError(
        err.response?.data?.message || 
        err.message || 
        "Unable to fetch asset inventory from backend."
      );
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const filteredAssets = assets.filter((asset) => {
    const hostname = asset.hostname || '';
    const ip = asset.ip || '';
    const role = asset.role || '';
    const criticality = asset.criticality || '';

    const matchesSearch =
      hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      role.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesCriticality =
      filterCriticality === 'ALL' || criticality.toUpperCase() === filterCriticality.toUpperCase();

    return matchesSearch && matchesCriticality;
  });

  const apiUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400">
            <Server className="h-4 w-4" />
            ENTERPRISE ASSET & VULNERABILITY MATRIX
          </div>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-white">Host Security Posture</h2>
          <p className="text-xs text-slate-400 font-mono">
            Direct inventory of scanned infrastructure, discovered CVEs, and blast radius calculations
          </p>
        </div>

        <button
          onClick={loadAssets}
          className="flex items-center gap-2 self-start rounded-lg border border-cyan-500/30 bg-cyber-900 px-3 py-1.5 font-mono text-xs text-cyan-300 transition-all hover:bg-cyan-950/40 active:scale-95"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          REFRESH INVENTORY
        </button>
      </div>

      {/* Backend Disconnected Warning Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-rose-500/40 bg-rose-950/80 p-3 font-mono text-xs text-rose-300 shadow-neon-rose">
          <div className="flex items-center gap-2">
            <WifiOff className="h-4 w-4 text-rose-400 shrink-0" />
            <span>Backend API Offline ({apiUrl}): {error}</span>
          </div>
          <button onClick={loadAssets} className="text-rose-200 underline font-bold hover:text-white ml-3 shrink-0">
            Retry
          </button>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-white/10 bg-cyber-900/60 p-3.5 backdrop-blur-md">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Filter by hostname, IP address, or server role..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-cyber-950 py-2 pl-9 pr-3 font-mono text-xs text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <span className="font-mono text-xs text-slate-400">Criticality:</span>
          {['ALL', 'Crown Jewel', 'HIGH', 'MEDIUM'].map((crit) => (
            <button
              key={crit}
              onClick={() => setFilterCriticality(crit)}
              className={`rounded px-2.5 py-1 font-mono text-xs transition-all ${
                filterCriticality === crit
                  ? 'bg-cyan-500 font-bold text-black shadow-neon-cyan'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {crit}
            </button>
          ))}
        </div>
      </div>

      {/* Assets Table */}
      <div className="overflow-hidden rounded-xl border border-white/10 bg-cyber-900/80 backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="border-b border-white/10 bg-cyber-950/80 text-[11px] text-slate-400 uppercase">
              <tr>
                <th className="px-4 py-3">Host & IP</th>
                <th className="px-4 py-3">Role / OS</th>
                <th className="px-4 py-3">Criticality</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Vulnerabilities</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-cyan-400">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto mb-2" />
                    <span>FETCHING ASSET TELEMETRY FROM API...</span>
                  </td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-slate-500">
                    <AlertCircle className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <p className="font-bold text-slate-300">No Assets Found</p>
                    <p className="text-[11px] mt-1 text-slate-500">
                      {error ? "Backend API is currently offline. Connect your API to load assets." : "No assets match your search or filter criteria."}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => {
                  const vulns = asset.vulnerabilities || [];
                  return (
                    <tr
                      key={asset.id || asset.hostname}
                      className="transition-colors hover:bg-slate-800/40 cursor-pointer"
                      onClick={() => setSelectedAsset(asset)}
                    >
                      <td className="px-4 py-3">
                        <div className="font-bold text-white">{asset.hostname}</div>
                        <div className="text-[11px] text-cyan-400">{asset.ip}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-slate-200">{asset.role}</div>
                        <div className="text-[11px] text-slate-500 font-sans">{asset.os}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                            asset.criticality === 'Crown Jewel'
                              ? 'bg-amber-950 text-amber-300 border border-amber-500/40 shadow-neon-amber'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {asset.criticality}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-bold ${asset.riskScore >= 9.0 ? 'text-rose-400' : 'text-amber-400'}`}>
                          {asset.riskScore != null ? `${asset.riskScore} / 10` : '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={asset.status || 'UNKNOWN'} size="sm" />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {vulns.map((v, idx) => {
                            const cveTag = v.cve || v.id || `CVE-${idx}`;
                            return (
                              <span
                                key={cveTag}
                                className="rounded border border-rose-500/30 bg-rose-950/40 px-1.5 py-0.5 text-[10px] text-rose-300"
                              >
                                {cveTag}
                              </span>
                            );
                          })}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAsset(asset);
                          }}
                          className="rounded border border-cyan-500/30 bg-cyan-950/40 px-2.5 py-1 text-[11px] text-cyan-300 hover:bg-cyan-500 hover:text-black transition-colors"
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset Detail Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl rounded-2xl border border-cyan-500/40 bg-cyber-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div>
                <span className="font-mono text-[10px] text-cyan-400 uppercase tracking-widest">ASSET DEEP PROFILE</span>
                <h3 className="font-mono text-xl font-bold text-white">{selectedAsset.hostname}</h3>
                <span className="font-mono text-xs text-slate-400">{selectedAsset.ip}</span>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="rounded-lg border border-white/10 bg-cyber-950 p-2 text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-4 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-white/5 bg-cyber-950 p-3">
                  <span className="text-slate-500 block text-[10px]">OPERATING SYSTEM</span>
                  <span className="text-slate-200">{selectedAsset.os || 'N/A'}</span>
                </div>
                <div className="rounded-lg border border-white/5 bg-cyber-950 p-3">
                  <span className="text-slate-500 block text-[10px]">SECURITY ROLE</span>
                  <span className="text-slate-200">{selectedAsset.role || 'N/A'}</span>
                </div>
              </div>

              {/* Vulnerabilities */}
              <div>
                <span className="font-bold text-slate-300 block mb-2">DETECTED EXPLOITS & VULNERABILITIES</span>
                <div className="space-y-2">
                  {(selectedAsset.vulnerabilities || []).length > 0 ? (
                    selectedAsset.vulnerabilities.map((vuln, idx) => (
                      <div
                        key={vuln.cve || vuln.id || idx}
                        className="flex items-center justify-between rounded-lg border border-rose-500/30 bg-rose-950/30 p-3"
                      >
                        <div>
                          <div className="font-bold text-rose-300">
                            {vuln.cve || vuln.id}: {vuln.name || 'Vulnerability'}
                          </div>
                          <span className="text-[10px] text-slate-400">Severity: {vuln.severity || 'HIGH'}</span>
                        </div>
                        {vuln.cvss != null && (
                          <span className="rounded bg-rose-500 px-2 py-1 text-[11px] font-bold text-black">
                            CVSS {vuln.cvss}
                          </span>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-3 text-slate-500 bg-cyber-950 rounded-lg">No vulnerabilities reported on this host.</div>
                  )}
                </div>
              </div>

              {/* Open Ports */}
              <div>
                <span className="font-bold text-slate-300 block mb-1">OPEN LISTENING PORTS</span>
                <div className="flex flex-wrap gap-2">
                  {(selectedAsset.openPorts || []).length > 0 ? (
                    selectedAsset.openPorts.map((port) => (
                      <span key={port} className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-cyan-300">
                        Port {port}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500 text-xs">No open listening ports detected.</span>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2 border-t border-white/10 pt-4 font-mono text-xs">
              <button
                onClick={() => setSelectedAsset(null)}
                className="rounded-lg border border-white/10 px-4 py-2 text-slate-300 hover:bg-slate-800"
              >
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetInventoryPage;
