import React, { useRef, useEffect, useCallback } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { cytoscapeStyles, graphLayoutConfigs } from '../../utils/cytoscapeStyles';

// Register extensions with Cytoscape once
if (!cytoscape.prototype._dagreRegistered) {
  cytoscape.use(dagre);
  cytoscape.prototype._dagreRegistered = true;
}

export const AttackGraph = ({
  elements,
  layout = 'dagre',
  onSelectNode,
  onSelectEdge,
  filterCriticalOnly = false,
  highlightCrownJewels = false,
  onCyReady
}) => {
  const cyRef = useRef(null);

  // Filter elements if critical only is toggled
  const filteredElements = React.useMemo(() => {
    if (!filterCriticalOnly) return elements;

    // Collect critical edges
    const criticalEdges = elements.filter(el => el.data.source && el.data.isCriticalPath);
    const criticalNodeIds = new Set();
    criticalEdges.forEach(e => {
      criticalNodeIds.add(e.data.source);
      criticalNodeIds.add(e.data.target);
    });

    return elements.filter(el => {
      if (el.data.source) {
        return el.data.isCriticalPath;
      }
      return criticalNodeIds.has(el.data.id) || el.data.type === 'crown_jewel' || el.data.type === 'attacker';
    });
  }, [elements, filterCriticalOnly]);

  const handleCy = useCallback((cy) => {
    cyRef.current = cy;
    if (onCyReady) onCyReady(cy);

    // Event listeners
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      if (onSelectNode) {
        onSelectNode(node.data());
      }
    });

    cy.on('tap', 'edge', (evt) => {
      const edge = evt.target;
      if (onSelectEdge) {
        onSelectEdge(edge.data());
      }
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        // Clicked background
        if (onSelectNode) onSelectNode(null);
        if (onSelectEdge) onSelectEdge(null);
      }
    });
  }, [onSelectNode, onSelectEdge, onCyReady]);

  // Update layout when layout prop changes
  useEffect(() => {
    if (cyRef.current) {
      const config = graphLayoutConfigs[layout] || graphLayoutConfigs.dagre;
      const cyLayout = cyRef.current.layout(config);
      cyLayout.run();
    }
  }, [layout, filteredElements]);

  return (
    <div className="relative w-full h-full min-h-[500px] overflow-hidden rounded-xl border border-white/10 bg-cyber-950">
      <CytoscapeComponent
        elements={filteredElements}
        stylesheet={cytoscapeStyles}
        style={{ width: '100%', height: '100%' }}
        cy={handleCy}
        wheelSensitivity={0.25}
        boxSelectionEnabled={false}
      />
    </div>
  );
};

export default AttackGraph;
