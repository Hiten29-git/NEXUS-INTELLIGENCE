import React from 'react';

export const SeverityBadge = ({ severity, size = 'md' }) => {
  const normalized = (severity || 'low').toLowerCase();

  const styles = {
    critical: 'bg-rose-950/80 text-rose-300 border-rose-500/60 shadow-[0_0_10px_rgba(244,63,94,0.3)]',
    high: 'bg-amber-950/80 text-amber-300 border-amber-500/60 shadow-[0_0_10px_rgba(245,158,11,0.25)]',
    medium: 'bg-yellow-950/70 text-yellow-300 border-yellow-500/50',
    low: 'bg-emerald-950/70 text-emerald-300 border-emerald-500/50',
    info: 'bg-cyan-950/70 text-cyan-300 border-cyan-500/50',
    compromised: 'bg-red-950/90 text-red-200 border-red-500 shadow-[0_0_12px_rgba(239,68,68,0.4)] animate-pulse',
    targeted: 'bg-amber-950/80 text-amber-200 border-amber-500',
    healthy: 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40',
    normal: 'bg-slate-900 text-slate-300 border-slate-700',
    mitigated: 'bg-teal-950/80 text-teal-300 border-teal-500/60'
  };

  const currentStyle = styles[normalized] || styles.normal;
  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-xs px-2.5 py-1';

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-md border uppercase tracking-wider ${sizeClasses} ${currentStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {severity}
    </span>
  );
};

export default SeverityBadge;
