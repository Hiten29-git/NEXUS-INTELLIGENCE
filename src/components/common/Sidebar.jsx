import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Network, 
  Server, 
  AlertTriangle, 
  SlidersHorizontal
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
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    {
      name: 'Attack Graph',
      path: '/graph',
      icon: Network,
    },
    {
      name: 'Asset Matrix',
      path: '/assets',
      icon: Server,
    },
    {
      name: 'Threat Alerts',
      path: '/threats',
      icon: AlertTriangle,
    },
    {
      name: 'Remediation Simulator',
      path: '/simulate',
      icon: SlidersHorizontal,
    }
  ];

  return (
    <aside className="hidden w-60 shrink-0 flex-col justify-between border-r border-slate-800 bg-[#080B12] p-4 sm:flex">
      <div>
        <p className="mb-4 px-3 text-xs font-medium text-slate-500">Workspace</p>

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
                      ? 'border border-red-500/30 bg-red-950/40 text-red-300 font-semibold'
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-100'
                  }`
                }
              >
                <div className="flex items-center gap-3">
                  <Icon className="h-4 w-4 transition-transform group-hover:scale-110" />
                  <span>{item.name}</span>
                </div>
              </NavLink>
            );
          })}
        </nav>
      </div>

      <div className="rounded-lg border border-slate-800 bg-[#0D111A] p-3 text-xs">
        <div className="mb-2 flex items-center gap-2 text-blue-400">
          <img className="nexus-sidebar-logo" src="/nexus-logo.png" alt="NEXUS Intelligence" />
        </div>
        <div className="flex items-center justify-between border-t border-slate-800 pt-2 text-[11px]">
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
