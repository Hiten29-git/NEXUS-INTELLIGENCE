import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  GitFork,
  Search,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  WifiOff
} from 'lucide-react';

import { nexusApi } from '../services/api';
import AttackGraph from '../components/graph/AttackGraph';
import GraphControls from '../components/graph/GraphControls';
import GraphLegend from '../components/graph/GraphLegend';
import NodeDetailPanel from '../components/graph/NodeDetailPanel';
import BlastRadiusPanel from '../components/graph/BlastRadiusPanel';

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

  /*
   * Convert the backend Neo4j topology response into the
   * Cytoscape element format expected by the frontend.
   *
   * Supported backend formats:
   *
   * 1. Direct Cytoscape array:
   * [
   *   { data: {...} },
   *   { data: {...} }
   * ]
   *
   * 2. NEXUS topology object:
   * {
   *   nodes: [...],
   *   relationships: [...]
   * }
   */
  const normalizeGraphData = (payload) => {
    if (Array.isArray(payload)) {
      return payload;
    }

    if (!payload || typeof payload !== 'object') {
      return [];
    }

    const rawNodes = Array.isArray(payload.nodes)
      ? payload.nodes
      : [];

    const rawRelationships = Array.isArray(payload.relationships)
      ? payload.relationships
      : [];

    const nodes = rawNodes.map((node, index) => {
      const data = node?.data || node || {};

      return {
        data: {
          ...data,
          id: String(
            data.id ||
            node.id ||
            `node-${index}`
          ),
          label:
            data.label ||
            data.name ||
            data.hostname ||
            data.address ||
            data.id ||
            `Node ${index + 1}`,

          type:
            data.type ||
            data.label_type ||
            data.entity_type ||
            'unknown'
        }
      };
    });

    const relationships = rawRelationships.map((relationship, index) => {
      const data = relationship?.data || relationship || {};

      return {
        data: {
          ...data,
          id: String(
            data.id ||
            relationship.id ||
            `edge-${index}`
          ),
          source: String(
            data.source ||
            relationship.source ||
            ''
          ),
          target: String(
            data.target ||
            relationship.target ||
            ''
          ),
          type:
            data.type ||
            relationship.type ||
            'RELATED',
          label:
            data.label ||
            relationship.label ||
            data.type ||
            relationship.type ||
            'RELATED'
        }
      };
    });

    return [...nodes, ...relationships];
  };

  /*
   * Load real topology from FastAPI.
   */
  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await nexusApi.getGraphTopology();

      console.log(
        'NEXUS raw graph API response:',
        response.data
      );

      const normalized = normalizeGraphData(response.data);

      console.log(
        'NEXUS Cytoscape elements:',
        normalized.length
      );

      if (normalized.length === 0) {
        setError(
          'The backend is online, but no graph nodes or relationships were returned.'
        );
      }

      setElements(normalized);
    } catch (err) {
      console.error(
        'NEXUS graph API error:',
        err
      );

      setError(
        err.response?.data?.message ||
        err.message ||
        'Unable to fetch graph topology from the backend API.'
      );

      setElements([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  /*
   * Node selection.
   */
  const handleSelectNode = (nodeData) => {
    setSelectedNode(nodeData);
    setSelectedEdge(null);
  };

  /*
   * Edge selection.
   */
  const handleSelectEdge = (edgeData) => {
    setSelectedEdge(edgeData);
    setSelectedNode(null);
  };

  /*
   * Reset graph viewport.
   */
  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 40);
      cyRef.current.center();
    }

    setSelectedNode(null);
    setSelectedEdge(null);
  };

  /*
   * Search host / IP / process.
   */
  const handleSearch = (event) => {
    event.preventDefault();

    if (!cyRef.current || !searchTerm.trim()) {
      return;
    }

    const term = searchTerm
      .trim()
      .toLowerCase();

    const matchedNodes = cyRef.current
      .nodes()
      .filter((node) => {
        const label = String(
          node.data('label') || ''
        ).toLowerCase();

        const ip = String(
          node.data('ip') ||
          node.data('address') ||
          ''
        ).toLowerCase();

        const hostname = String(
          node.data('hostname') || ''
        ).toLowerCase();

        return (
          label.includes(term) ||
          ip.includes(term) ||
          hostname.includes(term)
        );
      });

    if (matchedNodes.length === 0) {
      setNotification({
        type: 'error',
        message: `No graph node found for "${searchTerm}".`
      });

      setTimeout(() => {
        setNotification(null);
      }, 4000);

      return;
    }

    const target = matchedNodes[0];

    cyRef.current
      .nodes()
      .unselect();

    target.select();

    cyRef.current.animate({
      center: {
        eles: target
      },
      zoom: 1.6,
      duration: 500
    });

    setSelectedNode(target.data());
    setSelectedEdge(null);
  };

  /*
   * Remediation simulation.
   */
  const handleSimulateIsolate = async (nodeId) => {
    try {
      const response =
        await nexusApi.simulateRemediation(nodeId);

      if (response.data?.elements) {
        const normalized = normalizeGraphData(
          response.data.elements
        );

        setElements(normalized);
      }

      setNotification({
        type: 'success',
        message:
          response.data?.message ||
          `Node [${nodeId}] isolation simulation completed.`
      });

      setSelectedNode(null);

      setTimeout(() => {
        setNotification(null);
      }, 6000);

    } catch (err) {
      console.error(
        'Remediation simulation failed:',
        err
      );

      setNotification({
        type: 'error',
        message:
          `Remediation API error: ${
            err.response?.data?.message ||
            err.message ||
            'Unknown error'
          }`
      });

      setTimeout(() => {
        setNotification(null);
      }, 6000);
    }
  };

  const apiUrl =
    import.meta.env.VITE_API_BASE_URL ||
    '/api/v1';

  return (
    <div className="flex h-[calc(100vh-6rem)] flex-col space-y-3">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">

        <div>
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400">
            <GitFork className="h-4 w-4" />

            NEXUS SECURITY RELATIONSHIP GRAPH
          </div>

          <p className="text-xs text-slate-400 font-mono">
            Interactive security relationship mapping & observed attack-path telemetry
          </p>
        </div>

        {/* Search + Refresh */}
        <div className="flex items-center gap-2">

          <form
            onSubmit={handleSearch}
            className="flex items-center gap-2"
          >

            <div className="relative">

              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />

              <input
                type="text"
                placeholder="Search host, process or IP..."
                value={searchTerm}
                onChange={(event) =>
                  setSearchTerm(event.target.value)
                }
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
            <RefreshCw
              className={`h-3.5 w-3.5 ${
                loading ? 'animate-spin' : ''
              }`}
            />

            REFRESH
          </button>

        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-rose-500/40 bg-rose-950/80 p-3 font-mono text-xs text-rose-300 shadow-neon-rose">

          <div className="flex items-center gap-2">

            <WifiOff className="h-4 w-4 text-rose-400 shrink-0" />

            <span>
              Graph API ({apiUrl}): {error}
            </span>

          </div>

          <button
            onClick={loadGraph}
            className="text-rose-200 underline font-bold hover:text-white ml-3 shrink-0"
          >
            Retry
          </button>

        </div>
      )}

      {/* Notification */}
      {notification && (
        <div
          className={`flex items-center justify-between rounded-lg border p-3 font-mono text-xs ${
            notification.type === 'error'
              ? 'border-rose-500/40 bg-rose-950/90 text-rose-300 shadow-neon-rose'
              : 'border-emerald-500/40 bg-emerald-950/90 text-emerald-300 shadow-neon-emerald'
          }`}
        >

          <div className="flex items-center gap-2">

            {notification.type === 'error' ? (
              <AlertCircle className="h-4 w-4 text-rose-400" />
            ) : (
              <CheckCircle className="h-4 w-4 text-emerald-400" />
            )}

            <span>
              {notification.message}
            </span>

          </div>

          <button
            onClick={() =>
              setNotification(null)
            }
            className="text-slate-400 hover:text-white"
          >
            Dismiss
          </button>

        </div>
      )}

      {/* Graph Controls */}
      <GraphControls
        cy={cyRef.current}
        layout={layout}
        onLayoutChange={setLayout}
        filterCriticalOnly={filterCriticalOnly}
        onToggleFilterCritical={() =>
          setFilterCriticalOnly(
            !filterCriticalOnly
          )
        }
        onReset={handleReset}
      />

      {/* Main Grid */}
      <div className="relative flex-1 grid grid-cols-1 lg:grid-cols-4 gap-3 min-h-0">

        {/* Graph */}
        <div className="lg:col-span-3 relative h-full flex flex-col">

          {loading ? (

            <div className="flex h-full items-center justify-center rounded-xl border border-white/10 bg-cyber-950 font-mono text-xs text-cyan-400">

              <RefreshCw className="h-5 w-5 animate-spin mr-2" />

              FETCHING LIVE SECURITY GRAPH...

            </div>

          ) : elements.length === 0 ? (

            <div className="flex h-full flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-cyber-950/70 p-8 text-center">

              <AlertCircle className="h-10 w-10 text-slate-500 mb-3" />

              <h3 className="font-mono text-sm font-bold text-slate-300">
                No Graph Topology Received
              </h3>

              <p className="mt-1 text-xs text-slate-500 max-w-md font-sans">
                {error
                  ? error
                  : 'The backend returned no graph elements. Verify Neo4j ingestion and the graph API.'}
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
              onCyReady={(cy) => {
                cyRef.current = cy;
              }}
            />

          )}

          <div className="mt-2">
            <GraphLegend />
          </div>

        </div>

        {/* Inspector */}
        <div className="lg:col-span-1 h-full min-h-[300px]">

<div className="space-y-3">

  <NodeDetailPanel
    selectedNode={selectedNode}
    selectedEdge={selectedEdge}
    onClose={() => {
      setSelectedNode(null);
      setSelectedEdge(null);
    }}
    onSimulateIsolate={
      handleSimulateIsolate
    }
  />

  <BlastRadiusPanel
    selectedNode={selectedNode}
  />

</div>
        </div>

      </div>
    </div>
  );
};

export default AttackGraphPage;
