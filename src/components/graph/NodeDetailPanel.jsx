import React from 'react';
import { 
  X, 
  ShieldAlert, 
  Radio, 
  Terminal, 
  Lock, 
  ExternalLink, 
  AlertTriangle,
  Server,
  Zap,
  CheckCircle2
} from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export const NodeDetailPanel = ({
  selectedNode,
  selectedEdge,
  onClose,
  onSimulateIsolate
}) => {
  if (!selectedNode && !selectedEdge) {
    return (
      <div className="flex h-full flex-col items-center justify-center rounded-xl border border-white/10 bg-cyber-900/60 p-6 text-center backdrop-blur-md">
        <div className="rounded-full border border-cyan-500/20 bg-cyan-950/40 p-4 text-cyan-400 mb-3 shadow-neon-cyan">
          <Radio className="h-6 w-6 animate-pulse" />
        </div>
        <h4 className="font-mono text-sm font-bold text-slate-200">INTERACTIVE GRAPH INSPECTOR</h4>
        <p className="mt-1.5 text-xs text-slate-400 max-w-xs leading-relaxed">
          Select any node or attack vector in the Cytoscape graph to inspect vulnerability metrics, CVE tags, and blast radius.
        </p>
      </div>
    );
  }

  // If an Edge is selected
  if (selectedEdge) {
    return (
      <div className="flex h-full flex-col justify-between rounded-xl border border-cyan-500/30 bg-cyber-900/90 p-5 backdrop-blur-md">
        <div>
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center gap-2 text-cyan-400">
              <Zap className="h-4 w-4" />
              <span className="font-mono text-xs font-bold uppercase">ATTACK VECTOR TELEMETRY</span>
            </div>
            <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="mt-4 space-y-4">
            <div>
              <h3 className="font-mono text-base font-bold text-white">{selectedEdge.label}</h3>
              <p className="font-mono text-xs text-slate-400 mt-1">Technique: {selectedEdge.technique || 'N/A'}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 font-mono text-xs">
              <div className="rounded-lg border border-white/5 bg-cyber-950 p-2.5">
                <span className="text-slate-500 block text-[10px]">PROTOCOL</span>
                <span className="text-cyan-300 font-semibold">{selectedEdge.protocol || 'TCP'}</span>
              </div>
              <div className="rounded-lg border border-white/5 bg-cyber-950 p-2.5">
                <span className="text-slate-500 block text-[10px]">RISK SEVERITY</span>
                <span className="text-rose-400 font-semibold">{selectedEdge.risk || 'High'}</span>
              </div>
            </div>

            <div className="rounded-lg border border-white/5 bg-cyber-950 p-3 space-y-2 text-xs font-mono">
              <div className="flex justify-between items-center text-slate-400">
                <span>Origin:</span>
                <span className="text-white font-bold">{selectedEdge.source}</span>
              </div>
              <div className="flex justify-between items-center text-slate-400">
                <span>Destination:</span>
                <span className="text-rose-400 font-bold">{selectedEdge.target}</span>
              </div>
              <div className="flex justify-between items-center text-slate-400">
                <span>Chain Weight:</span>
                <span className="text-amber-400 font-bold">{selectedEdge.weight || 5} / 10</span>
              </div>
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-white/10">
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-ping"></span>
            Vector Active in Current Killchain
          </div>
        </div>
      </div>
    );
  }

  // If a Node is selected
  const isCompromised = selectedNode.status === 'compromised';
  const isCrownJewel = selectedNode.type === 'crown_jewel';

  return (
    <div className="flex h-full flex-col justify-between rounded-xl border border-white/10 bg-cyber-900/90 p-5 backdrop-blur-md">
      <div className="overflow-y-auto pr-1">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            <Server className={`h-4 w-4 ${isCrownJewel ? 'text-amber-400' : 'text-cyan-400'}`} />
            <span className="font-mono text-xs font-bold uppercase text-slate-300">{selectedNode.category || 'Asset'}</span>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Node Identity */}
        <div className="mt-4">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-mono text-base font-bold text-white">{selectedNode.label}</h3>
            <SeverityBadge severity={selectedNode.status} size="sm" />
          </div>
          <p className="mt-1 font-mono text-xs text-cyan-400">{selectedNode.ip || 'Virtual / Gateway'}</p>
          <p className="mt-2 text-xs text-slate-300 leading-relaxed font-sans">{selectedNode.description}</p>
        </div>

        {/* Risk Score Meter */}
        <div className="mt-4 rounded-lg border border-white/5 bg-cyber-950 p-3">
          <div className="flex justify-between items-center font-mono text-xs mb-1.5">
            <span className="text-slate-400">EXPLOITABILITY SCORE:</span>
            <span className={`font-bold ${selectedNode.risk >= 8 ? 'text-rose-400' : 'text-amber-400'}`}>
              {selectedNode.risk} / 10.0
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full rounded-full ${
                selectedNode.risk >= 8.5 ? 'bg-rose-500 shadow-neon-rose' : 'bg-amber-500'
              }`}
              style={{ width: `${(selectedNode.risk / 10) * 100}%` }}
            ></div>
          </div>
        </div>

        {/* Vulnerabilities & CVEs */}
        {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 && (
          <div className="mt-4">
            <span className="font-mono text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
              EXPLOITABLE CVEs ({selectedNode.vulnerabilities.length})
            </span>
            <div className="space-y-1.5">
              {selectedNode.vulnerabilities.map((vuln, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between rounded-md border border-rose-500/20 bg-rose-950/30 px-2.5 py-1.5 font-mono text-xs text-rose-300"
                >
                  <div className="flex items-center gap-1.5">
                    <AlertTriangle className="h-3 w-3 text-rose-400 shrink-0" />
                    <span>{vuln}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Ports */}
        {selectedNode.ports && selectedNode.ports.length > 0 && (
          <div className="mt-4">
            <span className="font-mono text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
              LISTENING NETWORK PORTS
            </span>
            <div className="flex flex-wrap gap-1.5 font-mono text-xs">
              {selectedNode.ports.map((port) => (
                <span
                  key={port}
                  className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-slate-300"
                >
                  :{port}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Action Footer */}
      {selectedNode.type !== 'attacker' && (
        <div className="mt-5 pt-3 border-t border-white/10">
          <button
            onClick={() => onSimulateIsolate && onSimulateIsolate(selectedNode.id)}
            className="w-full flex items-center justify-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-950/60 py-2 font-mono text-xs font-bold text-cyan-300 transition-all hover:bg-cyan-500 hover:text-black shadow-neon-cyan active:scale-95"
          >
            <ShieldAlert className="h-4 w-4" />
            SIMULATE HOST ISOLATION / PATCH
          </button>
        </div>
      )}
    </div>
  );
};

export default NodeDetailPanel;
