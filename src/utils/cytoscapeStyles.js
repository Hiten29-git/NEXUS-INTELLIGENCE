// Cytoscape.js Stylesheet for NEXUS Cybersecurity Attack Graph

export const cytoscapeStyles = [
  // Core Node Styles
  {
    selector: 'node',
    style: {
      'label': 'data(label)',
      'color': '#f8fafc',
      'font-family': 'Inter, sans-serif',
      'font-size': '11px',
      'font-weight': 600,
      'text-valign': 'bottom',
      'text-margin-y': 8,
      'text-background-color': '#0b1120',
      'text-background-opacity': 0.85,
      'text-background-padding': '3px 6px',
      'text-background-shape': 'roundrectangle',
      'text-border-opacity': 0.3,
      'text-border-color': '#00f0ff',
      'text-border-width': 1,
      'width': 48,
      'height': 48,
      'background-color': '#1e293b',
      'border-width': 2,
      'border-color': '#00f0ff',
      'transition-property': 'background-color, border-color, width, height',
      'transition-duration': '0.25s',
      'z-index': 10
    }
  },

  // Attacker Node
  {
    selector: 'node[type = "attacker"]',
    style: {
      'shape': 'octagon',
      'background-color': '#4c0519',
      'border-color': '#f43f5e',
      'border-width': 3,
      'width': 54,
      'height': 54,
      'text-border-color': '#f43f5e'
    }
  },

  // Crown Jewel Assets (e.g. Domain Controller, Financial DB)
  {
    selector: 'node[type = "crown_jewel"]',
    style: {
      'shape': 'diamond',
      'background-color': '#3b2003',
      'border-color': '#fbbf24',
      'border-width': 3.5,
      'width': 58,
      'height': 58,
      'text-border-color': '#fbbf24',
      'z-index': 15
    }
  },

  // Firewall / Perimeter Node
  {
    selector: 'node[type = "firewall"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#064e3b',
      'border-color': '#10b981',
      'border-width': 2.5,
      'width': 50,
      'height': 42
    }
  },

  // Gateway Node
  {
    selector: 'node[type = "gateway"]',
    style: {
      'shape': 'hexagon',
      'background-color': '#311042',
      'border-color': '#a855f7',
      'border-width': 2.5
    }
  },

  // Cloud Nodes
  {
    selector: 'node[type = "cloud"]',
    style: {
      'shape': 'ellipse',
      'background-color': '#082f49',
      'border-color': '#38bdf8',
      'border-width': 2.5
    }
  },

  // Compromised State
  {
    selector: 'node[status = "compromised"]',
    style: {
      'border-color': '#e11d48',
      'border-width': 4,
      'background-color': '#881337',
      'shadow-blur': 25,
      'shadow-color': '#f43f5e',
      'shadow-opacity': 0.8
    }
  },

  // Targeted State
  {
    selector: 'node[status = "targeted"]',
    style: {
      'border-color': '#f59e0b',
      'border-width': 3.5,
      'shadow-blur': 20,
      'shadow-color': '#f59e0b',
      'shadow-opacity': 0.7
    }
  },

  // Mitigated / Quarantined State
  {
    selector: 'node[status = "mitigated"]',
    style: {
      'border-color': '#10b981',
      'background-color': '#064e3b',
      'border-style': 'dashed',
      'opacity': 0.85
    }
  },

  // Selected Node Highlight
  {
    selector: 'node:selected',
    style: {
      'border-width': 4,
      'border-color': '#ffffff',
      'shadow-blur': 30,
      'shadow-color': '#00f0ff',
      'shadow-opacity': 1.0,
      'width': 62,
      'height': 62
    }
  },

  // Core Edge Styles
  {
    selector: 'edge',
    style: {
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      'target-arrow-color': '#64748b',
      'line-color': '#334155',
      'width': 2,
      'opacity': 0.8,
      'arrow-scale': 1.2,
      'label': 'data(label)',
      'font-family': 'Fira Code, monospace',
      'font-size': '9px',
      'color': '#cbd5e1',
      'text-rotation': 'autorotate',
      'text-background-color': '#070a13',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px 5px',
      'text-background-shape': 'roundrectangle',
      'text-border-color': '#1e293b',
      'text-border-width': 1,
      'text-border-opacity': 0.8
    }
  },

  // Critical Attack Path Edges
  {
    selector: 'edge[?isCriticalPath]',
    style: {
      'line-color': '#f43f5e',
      'target-arrow-color': '#f43f5e',
      'width': 3.5,
      'opacity': 0.95,
      'line-style': 'solid',
      'shadow-blur': 12,
      'shadow-color': '#f43f5e',
      'shadow-opacity': 0.6,
      'color': '#fda4af',
      'text-border-color': '#f43f5e'
    }
  },

  // Selected Edge
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#00f0ff',
      'target-arrow-color': '#00f0ff',
      'width': 4.5,
      'shadow-blur': 16,
      'shadow-color': '#00f0ff',
      'shadow-opacity': 0.9,
      'color': '#00f0ff'
    }
  }
];

export const graphLayoutConfigs = {
  dagre: {
    name: 'dagre',
    rankDir: 'LR',
    nodeSep: 60,
    rankSep: 110,
    animate: true,
    animationDuration: 500,
    padding: 30
  },
  breadthfirst: {
    name: 'breadthfirst',
    directed: true,
    padding: 30,
    spacingFactor: 1.3,
    animate: true,
    animationDuration: 500
  },
  concentric: {
    name: 'concentric',
    minNodeSpacing: 60,
    concentric: (node) => (node.data('type') === 'crown_jewel' ? 3 : node.data('type') === 'attacker' ? 1 : 2),
    levelWidth: () => 1,
    animate: true,
    animationDuration: 500
  },
  cose: {
    name: 'cose',
    idealEdgeLength: 120,
    nodeOverlap: 20,
    refresh: 20,
    fit: true,
    padding: 30,
    randomize: false,
    componentSpacing: 100,
    nodeRepulsion: 400000,
    edgeElasticity: 100,
    nestingFactor: 5,
    gravity: 80,
    numIter: 1000,
    initialTemp: 200,
    coolingFactor: 0.95,
    minTemp: 1.0,
    animate: true
  }
};
