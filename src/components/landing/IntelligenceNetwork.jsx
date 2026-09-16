import React from 'react';
import { Globe2, LockKeyhole, RadioTower, ShieldAlert } from 'lucide-react';

const iconForType = (type) => {
  if (type === 'domain') return Globe2;
  if (type === 'asset') return LockKeyhole;
  if (type === 'actor') return ShieldAlert;
  return RadioTower;
};

export const IntelligenceNetwork = ({ nodes = [], edges = [], compact = false }) => {
  const lookup = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const height = compact ? 220 : 430;

  return (
    <div className={`network-stage ${compact ? 'network-stage-compact' : ''}`}>
      <div className="network-grid" />
      <svg className="network-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="Animated intelligence network">
        <defs>
          <linearGradient id="network-line" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#2563eb" stopOpacity=".18" />
            <stop offset="50%" stopColor="#06b6d4" stopOpacity=".82" />
            <stop offset="100%" stopColor="#7c3aed" stopOpacity=".18" />
          </linearGradient>
        </defs>
        {edges.map(([fromId, toId], index) => {
          const from = lookup[fromId];
          const to = lookup[toId];
          if (!from || !to) return null;
          return (
            <line
              key={`${fromId}-${toId}`}
              className="network-edge"
              style={{ animationDelay: `${index * 0.45}s` }}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              stroke="url(#network-line)"
              strokeWidth=".35"
              vectorEffect="non-scaling-stroke"
            />
          );
        })}
      </svg>

      {nodes.map((node, index) => {
        const Icon = iconForType(node.type);
        return (
          <div
            className="network-node"
            key={node.id}
            style={{ left: `${node.x}%`, top: `${node.y}%`, '--node-color': node.color, animationDelay: `${index * 0.3}s` }}
          >
            <span className="network-node-ring" />
            <span className="network-node-core"><Icon size={compact ? 13 : 15} /></span>
            {!compact && <span className="network-node-label">{node.label}</span>}
          </div>
        );
      })}

      {!compact && nodes.length > 0 && (
        <>
          <div className="network-float-card network-float-card-top">
            <span className="status-dot status-dot-cyan" />
            <span><strong>Live correlation</strong><small>{nodes.length} entities connected</small></span>
          </div>
          <div className="network-float-card network-float-card-bottom">
            <span className="network-card-score">LIVE</span>
            <span><strong>Graph telemetry</strong><small>Relationship data received</small></span>
          </div>
        </>
      )}
      {nodes.length === 0 && <div className="network-empty">Waiting for live graph telemetry</div>}
      <div className="network-caption">NEXUS / RELATIONSHIP ENGINE <span>● STREAMING</span></div>
      <div style={{ height }} aria-hidden="true" />
    </div>
  );
};

export default IntelligenceNetwork;
