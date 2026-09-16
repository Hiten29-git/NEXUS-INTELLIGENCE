import React from 'react';
import { 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  RotateCcw, 
  GitBranch, 
  CircleDot, 
  Share2, 
  Filter, 
  Flame,
  ShieldAlert
} from 'lucide-react';

export const GraphControls = ({
  cy,
  layout,
  onLayoutChange,
  filterCriticalOnly,
  onToggleFilterCritical,
  onReset
}) => {
  const handleZoomIn = () => {
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * 1.25,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleZoomOut = () => {
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * 0.8,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  };

  const handleFit = () => {
    if (!cy) return;
    cy.fit(undefined, 40);
  };

  const handleCenter = () => {
    if (!cy) return;
    cy.center();
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-cyber-900/90 p-3 backdrop-blur-md">
      {/* Layout Selection */}
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs font-semibold text-slate-400">LAYOUT:</span>
        <div className="flex rounded-lg bg-cyber-950 p-1 border border-white/5">
          {[
            { id: 'dagre', label: 'Hierarchical (Dagre)' },
            { id: 'cose', label: 'Force (CoSE)' },
            { id: 'concentric', label: 'Concentric' },
            { id: 'breadthfirst', label: 'Breadthfirst' }
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => onLayoutChange(item.id)}
              className={`rounded-md px-2.5 py-1 font-mono text-xs font-medium transition-all ${
                layout === item.id
                  ? 'bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Filters and View Controls */}
      <div className="flex items-center gap-2">
        {/* Toggle Critical Path */}
        <button
          onClick={onToggleFilterCritical}
          className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-xs transition-all ${
            filterCriticalOnly
              ? 'border-rose-500/60 bg-rose-950/60 text-rose-300 shadow-neon-rose'
              : 'border-white/10 bg-cyber-950 text-slate-400 hover:border-white/20 hover:text-white'
          }`}
          title="Show Only Active Attack Chains"
        >
          <Flame className={`h-3.5 w-3.5 ${filterCriticalOnly ? 'text-rose-400 animate-pulse' : ''}`} />
          <span>CRITICAL PATH ONLY</span>
        </button>

        <div className="h-5 w-px bg-white/10 mx-1"></div>

        {/* Zoom and Fit buttons */}
        <button
          onClick={handleZoomIn}
          className="rounded-lg border border-white/10 bg-cyber-950 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          title="Zoom In"
        >
          <ZoomIn className="h-4 w-4" />
        </button>

        <button
          onClick={handleZoomOut}
          className="rounded-lg border border-white/10 bg-cyber-950 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          title="Zoom Out"
        >
          <ZoomOut className="h-4 w-4" />
        </button>

        <button
          onClick={handleFit}
          className="rounded-lg border border-white/10 bg-cyber-950 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          title="Fit to Screen"
        >
          <Maximize2 className="h-4 w-4" />
        </button>

        <button
          onClick={onReset}
          className="rounded-lg border border-white/10 bg-cyber-950 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          title="Reset View"
        >
          <RotateCcw className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};

export default GraphControls;
