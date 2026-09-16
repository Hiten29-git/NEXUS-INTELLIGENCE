import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  GitFork, 
  Search, 
  RefreshCw, 
  ShieldAlert, 
  Info, 
  SlidersHorizontal,
  CheckCircle,
  AlertCircle,
  WifiOff
} from 'lucide-react';
import { nexusApi } from '../services/api';
import AttackGraph from '../components/graph/AttackGraph';
import GraphControls from '../components/graph/GraphControls';
import GraphLegend from '../components/graph/GraphLegend';
import NodeDetailPanel from '../components/graph/NodeDetailPanel';

export const AttackGraphPage = () => {
  const [elements, setElements] = useState([]);
  const [layout, setLayout] = useState('dagre');
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [filterCriticalOnly, setFilterCriticalOnly] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notification, setNotification] = useState(null);
  const cyRef = useRef(null);

  // Load graph topology from real REST API
  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await nexusApi.getGraphTopology();
      const data = Array.isArray(res.data) ? res.data : [];
      setElements(data);
    } catch (err) {
      console.error("Failed to load graph data from API:", err);
      setError(
        err.response?.data?.message || 
        err.message || 
        "Unable to fetch graph topology from the backend API."
      );
      setElements([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Handle node selection
  const handleSelectNode = (nodeData) => {
    setSelectedNode(nodeData);
    setSelectedEdge(null);
  };

  // Handle edge selection
  const handleSelectEdge = (edgeData) => {
    setSelectedEdge(edgeData);
    setSelectedNode(null);
  };

  // Reset viewport
  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 40);
      cyRef.current.center();
    }
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  // Search node by label or IP and zoom in
  const handleSearch = (e) => {
    e.preventDefault();
    if (!cyRef.current || !searchTerm.trim()) return;

    const term = searchTerm.toLowerCase();
    const matchedNode = cyRef.current.nodes().filter((n) => {
      const label = (n.data('label') || '').toLowerCase();
      const ip = (n.data('ip') || '').toLowerCase();
      return label.includes(term) || ip.includes(term);
    });

    if (matchedNode.length > 0) {
      const target = matchedNode[0];
      cyRef.current.nodes().unselect();
      target.select();
      cyRef.current.animate({
        center: { eles: target },
        zoom: 1.6,
        duration: 500
      });
      setSelectedNode(target.data());
      setSelectedEdge(null);
    }
  };

  // Real backend remediation call
  const handleSimulateIsolate = async (nodeId) => {
    try {
      const res = await nexusApi.simulateRemediation(nodeId);
      if (res.data?.elements) {
        setElements(res.data.elements);
      }
      setNotification({
        type: 'success',
        message: res.data?.message || `Node [${nodeId}] successfully isolated via backend.`
      });
      setSelectedNode(null);
      setTimeout(() => setNotification(null), 6000);
    } catch (err) {
      console.error("Remediation simulation API call failed:", err);
      setNotification({
        type: 'error',
        message: `Remediation API error: ${err.response?.data?.message || err.message}`
      });
      setTimeout(() => setNotification(null), 6000);
    }
  };

  const apiUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

  return (
    <div className="flex h-[calc(100vh-6rem)] flex-col space-y-3">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400">
            <GitFork className="h-4 w-4" />
            CYTOSCAPE.JS ATTACK GRAPH CANVAS
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Interactive multi-stage exploit mapping & lateral movement telemetry
          </p>
        </div>

        {/* Search Host / IP */}
        <div className="flex items-center gap-2">
          <form onSubmit={handleSearch} className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search host or IP (e.g. 10.0.1.10)..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-64 rounded-lg border border-white/10 bg-cyber-900 py-1.5 pl-8 pr-3 font-mono text-xs text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              className="rounded-lg border border-cyan-500/40 bg-cyan-950/60 px-3 py-1.5 font-mono text-xs text-cyan-300 hover:bg-cyan-500 hover:text-black transition-colors"
            >
              LOCATE
            </button>
          </form>

          <button
            onClick={loadGraph}
            className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-cyber-900 px-3 py-1.5 font-mono text-xs text-slate-300 hover:text-white hover:border-cyan-500/30"
            title="Reload topology from API"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            REFRESH
          </button>
        </div>
      </div>

      {/* Error Alert Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-rose-500/40 bg-rose-950/80 p-3 font-mono text-xs text-rose-300 shadow-neon-rose">
          <div className="flex items-center gap-2">
            <WifiOff className="h-4 w-4 text-rose-400 shrink-0" />
            <span>Backend API Offline ({apiUrl}): {error}</span>
          </div>
          <button onClick={loadGraph} className="text-rose-200 underline font-bold hover:text-white ml-3 shrink-0">
            Retry
          </button>
        </div>
      )}

      {/* Notification Toast */}
      {notification && (
        <div className={`flex items-center justify-between rounded-lg border p-3 font-mono text-xs ${
          notification.type === 'error' 
            ? 'border-rose-500/40 bg-rose-950/90 text-rose-300 shadow-neon-rose' 
            : 'border-emerald-500/40 bg-emerald-950/90 text-emerald-300 shadow-neon-emerald'
        }`}>
          <div className="flex items-center gap-2">
            {notification.type === 'error' ? (
              <AlertCircle className="h-4 w-4 text-rose-400" />
            ) : (
              <CheckCircle className="h-4 w-4 text-emerald-400" />
            )}
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* Controls Bar */}
      <GraphControls
        cy={cyRef.current}
        layout={layout}
        onLayoutChange={setLayout}
        filterCriticalOnly={filterCriticalOnly}
        onToggleFilterCritical={() => setFilterCriticalOnly(!filterCriticalOnly)}
        onReset={handleReset}
      />

      {/* Main Graph & Inspector Grid */}
      <div className="relative flex-1 grid grid-cols-1 lg:grid-cols-4 gap-3 min-h-0">
        {/* Cytoscape Canvas (3 cols) */}
        <div className="lg:col-span-3 relative h-full flex flex-col">
          {loading ? (
            <div className="flex h-full items-center justify-center rounded-xl border border-white/10 bg-cyber-950 font-mono text-xs text-cyan-400">
              <RefreshCw className="h-5 w-5 animate-spin mr-2" />
              FETCHING TOPOLOGY FROM REST API...
            </div>
          ) : elements.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-cyber-950/70 p-8 text-center">
              <AlertCircle className="h-10 w-10 text-slate-500 mb-3" />
              <h3 className="font-mono text-sm font-bold text-slate-300">No Graph Topology Received</h3>
              <p className="mt-1 text-xs text-slate-500 max-w-md font-sans">
                {error 
                  ? `Backend API at ${apiUrl} is currently offline. Start the backend service to stream attack nodes and lateral vectors.`
                  : "The backend returned an empty topology array. Populate network elements via the graph API endpoint."}
              </p>
              <button
                onClick={loadGraph}
                className="mt-4 flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950 px-4 py-2 font-mono text-xs font-bold text-cyan-300 hover:bg-cyan-900 transition-colors"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                CHECK API AGAIN
              </button>
            </div>
          ) : (
            <AttackGraph
              elements={elements}
              layout={layout}
              onSelectNode={handleSelectNode}
              onSelectEdge={handleSelectEdge}
              filterCriticalOnly={filterCriticalOnly}
              onCyReady={(cy) => { cyRef.current = cy; }}
            />
          )}

          {/* Bottom Graph Legend Overlay */}
          <div className="mt-2">
            <GraphLegend />
          </div>
        </div>

        {/* Right Inspector Panel (1 col) */}
        <div className="lg:col-span-1 h-full min-h-[300px]">
          <NodeDetailPanel
            selectedNode={selectedNode}
            selectedEdge={selectedEdge}
            onClose={() => { setSelectedNode(null); setSelectedEdge(null); }}
            onSimulateIsolate={handleSimulateIsolate}
          />
        </div>
      </div>
    </div>
  );
};

export default AttackGraphPage;
