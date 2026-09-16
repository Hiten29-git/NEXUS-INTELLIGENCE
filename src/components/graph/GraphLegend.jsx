import React from 'react';

export const GraphLegend = () => {
  const items = [
    { label: 'Attacker (APT)', shape: 'Octagon', color: 'bg-rose-900 border-rose-500' },
    { label: 'Crown Jewel', shape: 'Diamond', color: 'bg-amber-900 border-amber-400' },
    { label: 'Server / Workstation', shape: 'Square', color: 'bg-slate-800 border-cyan-400' },
    { label: 'API Gateway', shape: 'Hexagon', color: 'bg-purple-900 border-purple-400' },
    { label: 'Firewall', shape: 'Rectangle', color: 'bg-emerald-900 border-emerald-400' },
    { label: 'Critical Path Edge', shape: 'Line', color: 'bg-rose-500 shadow-neon-rose' },
  ];

  return (
    <div className="flex flex-wrap items-center gap-4 rounded-xl border border-white/5 bg-cyber-950/80 px-4 py-2.5 backdrop-blur-sm text-xs font-mono">
      <span className="text-slate-500 font-bold uppercase tracking-wider text-[10px]">LEGEND:</span>
      {items.map((item, idx) => (
        <div key={idx} className="flex items-center gap-1.5 text-slate-300">
          <span className={`inline-block h-3 w-3 rounded-sm border ${item.color}`}></span>
          <span className="text-[11px]">{item.label}</span>
        </div>
      ))}
    </div>
  );
};

export default GraphLegend;
