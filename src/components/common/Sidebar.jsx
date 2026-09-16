import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Network, 
  Server, 
  AlertTriangle, 
  SlidersHorizontal,
  ShieldCheck,
  Radio,
  Wifi,
  WifiOff
} from 'lucide-react';
import { nexusApi } from '../../services/api';

export const Sidebar = () => {
  const [apiStatus, setApiStatus] = useState('checking'); // 'online' | 'offline' | 'checking'

  useEffect(() => {
    let isMounted = true;
    async function testBackend() {
      try {
        await nexusApi.checkHealth();
        if (isMounted) setApiStatus('online');
      } catch (err) {
        if (isMounted) setApiStatus('offline');
      }
    }

    testBackend();
    const interval = setInterval(testBackend, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    {
      name: 'Overview',
      path: '/',
      icon: LayoutDashboard,
      badge: 'Live'
    },
    {
      name: 'Attack Graph',
      path: '/graph',
      icon: Network,
      badge: 'Cytoscape'
    },
    {
      name: 'Asset Matrix',
      path: '/assets',
      icon: Server,
      badge: 'Matrix'
    },
    {
      name: 'Threat Alerts',
      path: '/threats',
      icon: AlertTriangle,
      badge: 'Feed'
    },
    {
      name: 'Remediation Simulator',
      path: '/simulate',
      icon: SlidersHorizontal,
      badge: 'Sandbox'
    }
  ];

  return (
    <aside className="flex w-64 flex-col justify-between border-r border-white/10 bg-cyber-950/80 p-4 backdrop-blur-xl shrink-0">
      <div>
        <div className="mb-6 px-3 pt-2">
          <p className="font-mono text-[10px] font-bold tracking-wider text-slate-500 uppercase">
            NAVIGATION CONSOLE
          </p>
        </div>

        <nav className="space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `group flex items-center justify-between rounded-lg px-3.5 py-2.5 text-xs font-medium transition-all ${
                    isActive
                      ? 'border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.15)] font-semibold'
                      : 'text-slate-400 hover:bg-slate-900/80 hover:text-slate-200'
                  }`
                }
              >
                <div className="flex items-center gap-3">
                  <Icon className="h-4 w-4 transition-transform group-hover:scale-110" />
                  <span>{item.name}</span>
                </div>
                {item.badge && (
                  <span className="rounded bg-slate-800/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 group-hover:text-cyan-300">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* System Status & Backend Connectivity Box */}
      <div className="rounded-xl border border-white/5 bg-cyber-900/60 p-3.5 text-xs font-mono">
        <div className="flex items-center gap-2 text-cyan-400 mb-2">
          <ShieldCheck className="h-4 w-4" />
          <span className="font-bold">NEXUS Intelligence</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Autonomous Attack Path Analysis & Graph Defense Engine.
        </p>
        <div className="mt-2.5 pt-2.5 border-t border-white/5 flex items-center justify-between text-[10px]">
          <span className="text-slate-500">API Connection:</span>
          {apiStatus === 'online' ? (
            <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
              API: Online
            </span>
          ) : apiStatus === 'offline' ? (
            <span className="flex items-center gap-1.5 text-rose-400 font-bold" title="Backend not reachable at VITE_API_BASE_URL">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
              API: Offline
            </span>
          ) : (
            <span className="text-slate-400 animate-pulse">Connecting...</span>
          )}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
