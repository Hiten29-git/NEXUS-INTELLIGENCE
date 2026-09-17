import React, { useEffect, useState } from "react";
import {
  Shield,
  Network,
  Target,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
} from "lucide-react";
import { nexusApi } from "../../services/api";

const BlastRadiusPanel = ({ selectedNode }) => {
  const [maxHops, setMaxHops] = useState(3);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const nodeId =
    selectedNode?.id ||
    selectedNode?.data?.id ||
    selectedNode?.data?.nodeId ||
    null;

  const nodeLabel =
    selectedNode?.label ||
    selectedNode?.data?.label ||
    selectedNode?.data?.name ||
    selectedNode?.data?.id ||
    "No entity selected";

  const runSimulation = async () => {
    if (!nodeId) {
      setError("Select a graph entity first.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await nexusApi.getBlastRadius(nodeId, maxHops);

      setResult(response?.data || null);
    } catch (err) {
      console.error("Blast radius request failed:", err);

      setResult(null);

      setError(
        err?.response?.data?.detail ||
          err?.response?.data?.message ||
          err?.message ||
          "Unable to calculate blast radius."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setResult(null);
    setError(null);
  }, [nodeId]);

  const reachable =
    result?.reachable_assets ??
    result?.reachable_entities ??
    result?.reachable ??
    [];

  const critical =
    result?.critical_assets ??
    result?.critical_entities ??
    result?.critical ??
    [];

  const paths =
    result?.paths ??
    result?.attack_paths ??
    [];

  if (!selectedNode) {
    return (
      <div className="rounded-xl border border-white/10 bg-cyber-950/80 p-4">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyan-400" />

          <div>
            <h3 className="font-mono text-xs font-bold text-slate-200">
              WHAT-IF IMPACT SIMULATOR
            </h3>

            <p className="mt-1 text-[11px] text-slate-500">
              Select a graph entity to calculate its potential blast radius.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyber-950/90 p-4 shadow-lg shadow-cyan-950/20">

      {/* Header */}
      <div className="flex items-start justify-between gap-3">

        <div className="flex items-start gap-2">

          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-2">
            <Shield className="h-4 w-4 text-cyan-400" />
          </div>

          <div>
            <h3 className="font-mono text-xs font-bold tracking-wide text-slate-200">
              WHAT-IF IMPACT SIMULATOR
            </h3>

            <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
              Estimates graph-reachable assets without performing an attack.
            </p>
          </div>

        </div>

        <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[9px] font-mono text-emerald-400">
          READ ONLY
        </span>

      </div>

      {/* Selected entity */}
      <div className="mt-4 rounded-lg border border-white/10 bg-black/20 p-3">

        <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500">
          Selected Entity
        </div>

        <div className="mt-1 flex items-center gap-2">

          <Network className="h-3.5 w-3.5 text-cyan-400" />

          <span className="truncate font-mono text-xs text-cyan-300">
            {nodeLabel}
          </span>

        </div>

      </div>

      {/* Controls */}
      <div className="mt-3 grid grid-cols-[1fr_auto] gap-2">

        <div className="relative">

          <select
            value={maxHops}
            onChange={(event) =>
              setMaxHops(Number(event.target.value))
            }
            className="w-full appearance-none rounded-lg border border-white/10 bg-black/30 px-3 py-2 pr-8 text-xs font-mono text-slate-300 outline-none focus:border-cyan-500/40"
          >
            <option value={1}>1 hop</option>
            <option value={2}>2 hops</option>
            <option value={3}>3 hops</option>
            <option value={4}>4 hops</option>
            <option value={5}>5 hops</option>
          </select>

          <ChevronDown className="pointer-events-none absolute right-2 top-2.5 h-3.5 w-3.5 text-slate-500" />

        </div>

        <button
          onClick={runSimulation}
          disabled={loading || !nodeId}
          className="flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs font-mono font-bold text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? (
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Target className="h-3.5 w-3.5" />
          )}

          {loading ? "CALCULATING" : "SIMULATE"}
        </button>

      </div>

      {/* Error */}
      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/5 p-3">

          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />

          <div className="text-[11px] leading-relaxed text-red-300">
            {error}
          </div>

        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="mt-4 space-y-3">

          {/* Metrics */}
          <div className="grid grid-cols-3 gap-2">

            <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-center">
              <div className="text-lg font-mono font-bold text-cyan-300">
                {Array.isArray(reachable) ? reachable.length : 0}
              </div>

              <div className="mt-1 text-[9px] font-mono uppercase text-slate-500">
                Reachable
              </div>
            </div>

            <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-center">
              <div className="text-lg font-mono font-bold text-amber-300">
                {Array.isArray(critical) ? critical.length : 0}
              </div>

              <div className="mt-1 text-[9px] font-mono uppercase text-slate-500">
                Critical
              </div>
            </div>

            <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-center">
              <div className="text-lg font-mono font-bold text-violet-300">
                {Array.isArray(paths) ? paths.length : 0}
              </div>

              <div className="mt-1 text-[9px] font-mono uppercase text-slate-500">
                Paths
              </div>
            </div>

          </div>

          {/* Interpretation */}
          <div className="rounded-lg border border-emerald-500/15 bg-emerald-500/5 p-3">

            <div className="flex items-start gap-2">

              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />

              <p className="text-[10px] leading-relaxed text-slate-400">
                This simulation uses observed graph relationships to estimate
                potentially reachable entities. It does not execute network
                actions, exploit systems, or modify the environment.
              </p>

            </div>

          </div>

          {/* Reachable entities */}
          {Array.isArray(reachable) && reachable.length > 0 && (
            <div>

              <div className="mb-2 text-[9px] font-mono uppercase tracking-wider text-slate-500">
                Reachable Entities
              </div>

              <div className="max-h-32 space-y-1 overflow-y-auto">

                {reachable.slice(0, 20).map((item, index) => {

                  const value =
                    typeof item === "string"
                      ? item
                      : item?.id ||
                        item?.name ||
                        item?.label ||
                        JSON.stringify(item);

                  return (
                    <div
                      key={`${value}-${index}`}
                      className="rounded border border-white/5 bg-black/20 px-2 py-1.5 font-mono text-[10px] text-slate-400"
                    >
                      {value}
                    </div>
                  );
                })}

              </div>

            </div>
          )}

          {/* Critical entities */}
          {Array.isArray(critical) && critical.length > 0 && (
            <div>

              <div className="mb-2 text-[9px] font-mono uppercase tracking-wider text-amber-400">
                Critical Reachable Entities
              </div>

              <div className="max-h-28 space-y-1 overflow-y-auto">

                {critical.slice(0, 20).map((item, index) => {

                  const value =
                    typeof item === "string"
                      ? item
                      : item?.id ||
                        item?.name ||
                        item?.label ||
                        JSON.stringify(item);

                  return (
                    <div
                      key={`${value}-${index}`}
                      className="rounded border border-amber-500/10 bg-amber-500/5 px-2 py-1.5 font-mono text-[10px] text-amber-300"
                    >
                      {value}
                    </div>
                  );
                })}

              </div>

            </div>
          )}

        </div>
      )}

    </div>
  );
};

export default BlastRadiusPanel;
