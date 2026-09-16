import React from 'react';

export const StatCard = ({ title, value, subtitle, icon: Icon, color = 'cyan', trend }) => {
  const colorMap = {
    cyan: 'border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-neon-cyan',
    rose: 'border-rose-500/30 text-rose-400 group-hover:border-rose-400 group-hover:shadow-neon-rose',
    amber: 'border-amber-500/30 text-amber-400 group-hover:border-amber-400 group-hover:shadow-neon-amber',
    emerald: 'border-emerald-500/30 text-emerald-400 group-hover:border-emerald-400 group-hover:shadow-neon-emerald',
    purple: 'border-purple-500/30 text-purple-400 group-hover:border-purple-400'
  };

  const activeColor = colorMap[color] || colorMap.cyan;

  return (
    <div className={`group relative overflow-hidden rounded-xl border bg-cyber-900/80 p-5 backdrop-blur-md transition-all duration-300 hover:-translate-y-0.5 ${activeColor}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
        {Icon && (
          <div className="rounded-lg bg-slate-800/80 p-2.5 text-current ring-1 ring-white/10 transition-colors">
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="font-mono text-3xl font-bold tracking-tight text-white">{value}</span>
        {trend && (
          <span className={`text-xs font-medium font-mono ${trend.startsWith('+') ? 'text-rose-400' : 'text-emerald-400'}`}>
            {trend}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-1 text-xs text-slate-400 font-sans">{subtitle}</p>
      )}

      {/* Decorative corner accent */}
      <div className="absolute top-0 right-0 h-4 w-4 border-t-2 border-r-2 border-current opacity-30"></div>
    </div>
  );
};

export default StatCard;
