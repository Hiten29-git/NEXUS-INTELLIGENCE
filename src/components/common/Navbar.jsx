import React, { useState, useEffect } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { Menu, Server, RefreshCw, X } from 'lucide-react';
import { getServerBaseUrl, nexusApi } from '../../services/api';

export const Navbar = ({ onRefresh, isRefreshing, onOpenServerModal }) => {
  const [serverUrl, setServerUrl] = useState(getServerBaseUrl());
  const [serverStatus, setServerStatus] = useState('checking'); // 'online' | 'offline' | 'checking'
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const navigation = [
    { label: 'Platform', path: '/' },
    { label: 'Intelligence', path: '/threats' },
    { label: 'Threat Graph', path: '/graph' },
    { label: 'Attack Paths', path: '/simulate' },
    { label: 'AI Analysis', path: '/assets' },
  ];

  const checkConnectivity = async () => {
    try {
      await nexusApi.checkHealth();
      setServerStatus('online');
    } catch {
      setServerStatus('offline');
    }
  };

  useEffect(() => {
    checkConnectivity();
    const interval = setInterval(checkConnectivity, 12000);

    const handleUrlChange = (e) => {
      setServerUrl(e.detail || getServerBaseUrl());
      checkConnectivity();
    };

    window.addEventListener('nexus_server_url_changed', handleUrlChange);
    const handleScroll = () => setIsScrolled(window.scrollY > 8);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => {
      clearInterval(interval);
      window.removeEventListener('nexus_server_url_changed', handleUrlChange);
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  // Parse a friendly server host label
  let serverDisplayHost = 'Server';
  try {
    const parsed = new URL(serverUrl);
    serverDisplayHost = parsed.host;
  } catch {
    serverDisplayHost = serverUrl.replace(/^https?:\/\//, '').split('/')[0];
  }

  return (
    <header className={`nexus-navbar sticky top-0 z-40 flex h-16 w-full items-center justify-between border-b px-4 font-sans transition-all sm:px-6 ${isScrolled ? 'nexus-navbar-scrolled' : ''}`}>
      <Link to="/" className="flex items-center gap-3" onClick={() => setIsMenuOpen(false)}>
        <img className="nexus-brand-logo" src="/nexus-logo.png" alt="NEXUS Intelligence" />
        <div>
          <span className="sr-only">NEXUS-INTELLIGENCE</span>
        </div>
      </Link>

      <nav className="nexus-navbar-links hidden items-center gap-1 lg:flex" aria-label="Primary navigation">
        {navigation.map((item) => <NavLink key={item.path} to={item.path} end={item.path === '/'} className={({ isActive }) => `nexus-navbar-link ${isActive ? 'nexus-navbar-link-active' : ''}`}>{item.label}</NavLink>)}
      </nav>

      <div className="flex items-center gap-3">
        <a className="hidden text-xs font-semibold text-slate-400 transition-colors hover:text-blue-400 md:inline" href="#documentation">Documentation</a>
        <button
          onClick={onOpenServerModal}
          title="Click to configure or change backend server IP"
          className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-50 transition-colors"
        >
          <Server className="h-3.5 w-3.5 text-blue-400" />
          <span className="hidden sm:inline font-mono text-[11px] text-slate-500">{serverDisplayHost}</span>
          <span className="flex items-center gap-1">
            {serverStatus === 'online' ? (
              <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                Online
              </span>
            ) : serverStatus === 'offline' ? (
              <span className="flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                <span className="h-2 w-2 rounded-full bg-rose-500" />
                Offline
              </span>
            ) : (
              <span className="h-2 w-2 rounded-full bg-slate-400 animate-pulse" />
            )}
          </span>
        </button>

        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-colors active:scale-95 disabled:opacity-50"
          title="Refresh dashboard data"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Refresh</span>
        </button>

        <button type="button" aria-label={isMenuOpen ? 'Close navigation menu' : 'Open navigation menu'} aria-expanded={isMenuOpen} onClick={() => setIsMenuOpen((open) => !open)} className="nexus-menu-button lg:hidden">
          {isMenuOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      {isMenuOpen && <nav className="nexus-mobile-menu lg:hidden" aria-label="Mobile navigation">{navigation.map((item) => <NavLink key={item.path} to={item.path} end={item.path === '/'} onClick={() => setIsMenuOpen(false)} className="nexus-mobile-link">{item.label}<span>↗</span></NavLink>)}<a href="#documentation" onClick={() => setIsMenuOpen(false)} className="nexus-mobile-link">Documentation<span>↗</span></a></nav>}
    </header>
  );
};

export default Navbar;
