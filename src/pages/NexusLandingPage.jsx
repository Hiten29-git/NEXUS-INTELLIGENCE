import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, ArrowRight, Bot, BrainCircuit, CheckCircle2, CircleDot, ExternalLink, GitFork, Globe2, Network, RefreshCw, ScanSearch, Sparkles, Target, WifiOff } from 'lucide-react';
import { nexusApi } from '../services/api';
import IntelligenceNetwork from '../components/landing/IntelligenceNetwork';

const features = [
  { icon: BrainCircuit, eyebrow: '01 / AI PIPELINE', title: 'AI intelligence', text: 'Normalize security events, surface context, and turn noisy telemetry into explainable signals.', accent: 'blue' },
  { icon: Network, eyebrow: '02 / KNOWLEDGE GRAPH', title: 'See the relationships', text: 'Connect entities, infrastructure, indicators, and identities in one continuously evolving graph.', accent: 'cyan' },
  { icon: ScanSearch, eyebrow: '03 / IOC ENRICHMENT', title: 'Investigate with confidence', text: 'Enrich IPs, domains, hashes, URLs, and threat actors with evidence you can trace.', accent: 'purple' },
  { icon: GitFork, eyebrow: '04 / ATTACK PATHS', title: 'Find the shortest route', text: 'Move from initial access to critical assets with a clear, prioritized path to action.', accent: 'teal' },
  { icon: Activity, eyebrow: '05 / ANOMALY CORRELATION', title: 'Separate signal from noise', text: 'Correlate events across time and entities so meaningful anomalies rise above routine activity.', accent: 'amber' },
  { icon: Bot, eyebrow: '06 / NEXUS AI', title: 'Explain every decision', text: 'Turn connected evidence into concise investigation guidance your team can act on.', accent: 'ink' },
];

const pathStages = ['ENTRY POINT', 'IDENTITY', 'INFRASTRUCTURE', 'COMMAND & CONTROL', 'TARGET'];

export const NexusLandingPage = () => {
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [attackChains, setAttackChains] = useState([]);
  const [graphNodes, setGraphNodes] = useState([]);
  const [graphEdges, setGraphEdges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [metricsResponse, alertsResponse, chainsResponse, graphResponse] = await Promise.all([nexusApi.getMetrics(), nexusApi.getAlerts(), nexusApi.getAttackChains(), nexusApi.getGraphTopology()]);
      setMetrics(metricsResponse.data || null);
      setAlerts(Array.isArray(alertsResponse.data) ? alertsResponse.data : []);
      setAttackChains(Array.isArray(chainsResponse.data) ? chainsResponse.data : []);
      const topology = Array.isArray(graphResponse.data) ? graphResponse.data : [];
      const topologyNodes = topology.filter((item) => item.group === 'nodes' || item.data?.source == null).map((item, index) => ({
        id: item.data?.id || `node-${index}`,
        label: item.data?.label || item.data?.name || 'ENTITY',
        type: item.data?.type || 'entity',
        x: 12 + ((index * 29) % 76),
        y: 18 + ((index * 43) % 66),
        color: '#2563eb',
      }));
      const nodeIds = new Set(topologyNodes.map((node) => node.id));
      const topologyEdges = topology.filter((item) => item.group === 'edges' || item.data?.source != null).map((item) => [item.data?.source, item.data?.target]).filter(([source, target]) => nodeIds.has(source) && nodeIds.has(target));
      setGraphNodes(topologyNodes);
      setGraphEdges(topologyEdges);
    } catch (requestError) {
      console.error('Failed to load NEXUS intelligence:', requestError);
      setError(requestError.response?.data?.message || requestError.message || 'Connect a backend to stream live intelligence.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDashboardData(); }, [loadDashboardData]);

  const liveAlerts = alerts.slice(0, 4).map((alert, index) => ({
    type: index === 0 ? 'THREAT DETECTED' : 'INTELLIGENCE SIGNAL',
    entity: alert.title || alert.target || 'Security event',
    detail: alert.mitre || alert.severity || 'correlated event',
    tone: alert.severity?.toLowerCase() === 'critical' ? 'rose' : 'blue',
    time: 'live',
  }));

  return (
    <div className="nexus-landing">
      {error && <div className="connection-banner"><div className="flex items-start gap-3"><WifiOff className="mt-0.5 h-5 w-5 shrink-0 text-rose-500" /><div><strong>Live intelligence is paused.</strong><span>{error}</span></div></div><button type="button" onClick={loadDashboardData} className="button button-small button-light"><RefreshCw size={14} /> Retry</button></div>}

      <section className="nexus-hero">
        <div className="hero-copy"><div className="eyebrow"><span className="eyebrow-pulse" /> NEXUS-INTELLIGENCE / SIGNAL LAYER</div><h1>Connect the signals.<br /><em>Understand the threat.</em></h1><p className="hero-lede">NEXUS combines AI-powered threat intelligence, entity relationships, IOC enrichment, anomaly detection, and attack-path analysis into one intelligence platform.</p><div className="hero-actions"><Link to="/graph" className="button button-primary">Explore intelligence <ArrowRight size={16} /></Link><Link to="/simulate" className="button button-quiet">Launch NEXUS <Sparkles size={16} /></Link></div><div className="hero-proof"><CheckCircle2 size={15} /> Explainable analysis <span /> <CheckCircle2 size={15} /> Real-time graph intelligence</div></div>
        <div className="hero-visual"><IntelligenceNetwork nodes={graphNodes} edges={graphEdges} /></div>
      </section>

      <div className="signal-strip">{['AI-POWERED', 'REAL-TIME', 'GRAPH INTELLIGENCE', 'IOC ENRICHMENT', 'EXPLAINABLE ANALYSIS'].map((signal) => <span key={signal}><i />{signal}</span>)}</div>

      <section className="section-block"><div className="section-heading"><div><div className="eyebrow">THE NEXUS APPROACH</div><h2>One intelligence layer<br /><span>for every signal.</span></h2></div><p>From the first anomaly to the final remediation, NEXUS gives your team a shared language for understanding what is happening and why.</p></div><div className="feature-grid">{features.map(({ icon: Icon, eyebrow, title, text, accent }) => <article className={`feature-card feature-${accent}`} key={title}><div className="feature-icon"><Icon size={20} /></div><span className="card-eyebrow">{eyebrow}</span><h3>{title}</h3><p>{text}</p><span className="feature-arrow"><ArrowRight size={16} /></span></article>)}</div></section>

      <section className="intelligence-section"><div className="section-heading section-heading-tight"><div><div className="eyebrow">RELATIONSHIP ENGINE</div><h2>See the connections<br /><span>others miss.</span></h2></div><Link to="/graph" className="text-link">Open full graph <ArrowRight size={15} /></Link></div><div className="graph-shell"><IntelligenceNetwork compact nodes={graphNodes} edges={graphEdges} /><div className="graph-legend"><span><i className="legend-blue" /> Entity</span><span><i className="legend-purple" /> Threat actor</span><span><i className="legend-red" /> Risk signal</span><button type="button" className="graph-search"><ScanSearch size={14} /> Search graph</button></div></div></section>

      <section className="live-grid"><div className="live-panel"><div className="panel-heading"><div><div className="eyebrow">LIVE INTELLIGENCE</div><h2>Signals, as they happen.</h2></div><span className="live-pill"><i /> STREAMING</span></div><div className="feed-list">{liveAlerts.length > 0 ? liveAlerts.map((event, index) => <div className="feed-row" key={`${event.entity}-${index}`}><span className={`feed-icon feed-${event.tone}`}><CircleDot size={16} /></span><div className="feed-content"><div><strong>{event.type}</strong><span>{event.time}</span></div><p>{event.entity}</p><small>{event.detail}</small></div><ArrowRight className="feed-arrow" size={16} /></div>) : <div className="feed-empty">No live intelligence signals received.</div>}</div><Link to="/threats" className="panel-link">View threat stream <ArrowRight size={15} /></Link></div><div className="ai-panel"><div className="ai-orb"><Bot size={25} /></div><div className="eyebrow">NEXUS AI</div><h2>Turn complex signals<br /><span>into clear action.</span></h2><p>{metrics ? `Live analysis reports ${metrics.activeAttackPaths ?? 0} active attack paths and ${metrics.compromisedNodes ?? 0} compromised entities.` : 'Connect the backend to generate live, explainable analysis.'}</p><div className="ai-actions"><Link to="/graph" className="button button-dark">View graph</Link><Link to="/simulate" className="button button-outline">Investigate</Link></div></div></section>

      <section className="path-section"><div className="section-heading section-heading-tight"><div><div className="eyebrow">ATTACK PATH ANALYSIS</div><h2>From entry point<br /><span>to impact.</span></h2></div><div className="path-score"><strong>{metrics?.securityPostureScore ?? '-'}</strong><span>confidence score</span></div></div><div className="path-track">{pathStages.map((stage, index) => <React.Fragment key={stage}><div className={`path-stage ${index === pathStages.length - 1 ? 'path-target' : ''}`}><span>{String(index + 1).padStart(2, '0')}</span><strong>{stage}</strong><small>{index === 0 ? 'external signal' : index === pathStages.length - 1 ? 'critical asset' : 'correlated node'}</small></div>{index < pathStages.length - 1 && <div className="path-line"><i /></div>}</React.Fragment>)}</div></section>

      <section className="metrics-row"><div className="metric-intro"><div className="eyebrow">AT A GLANCE</div><h2>Intelligence you<br /><span>can act on.</span></h2><p>Every score is grounded in connected evidence from your environment.</p></div><div className="metric-value"><span className="metric-number">{metrics?.activeAttackPaths ?? '-'}</span><span>active attack paths</span><div className="metric-bar"><i style={{ width: `${Math.min(Number(metrics?.activeAttackPaths ?? 0), 100)}%` }} /></div></div><div className="metric-value"><span className="metric-number">{metrics?.criticalVulnerabilities ?? '-'}</span><span>critical vulnerabilities</span><div className="metric-bar metric-bar-purple"><i style={{ width: `${Math.min(Number(metrics?.criticalVulnerabilities ?? 0), 100)}%` }} /></div></div><div className="metric-value"><span className="metric-number">{metrics?.compromisedNodes ?? '-'}</span><span>compromised entities</span><div className="metric-bar metric-bar-teal"><i style={{ width: `${Math.min(Number(metrics?.compromisedNodes ?? 0), 100)}%` }} /></div></div></section>

      {loading && <div className="loading-note"><Activity size={15} /> Syncing live NEXUS signals...</div>}
      {attackChains.length > 0 && <div className="chain-note"><Target size={17} /><span><strong>Active path detected:</strong> {attackChains[0].mitigation || 'Review the attack graph for recommended remediation.'}</span><Link to="/simulate">Review path <ArrowRight size={14} /></Link></div>}

      <section className="final-cta"><div><div className="eyebrow">BUILD THE SIGNAL LAYER</div><h2>Build intelligence<br /><em>from the noise.</em></h2><p>NEXUS connects events, entities, indicators, and relationships into one continuously evolving intelligence layer.</p><div className="hero-actions"><Link to="/" className="button button-dark">Explore NEXUS <ArrowRight size={16} /></Link><Link to="/graph" className="button button-outline">View intelligence graph <Network size={16} /></Link></div></div><div className="cta-mini-network"><IntelligenceNetwork compact /></div></section>

      <footer id="documentation" className="nexus-footer"><div><img className="nexus-footer-logo" src="/nexus-logo.png" alt="NEXUS Intelligence" /><p>AI-powered cyber intelligence platform.</p></div><div className="footer-links"><Link to="/">Platform</Link><Link to="/threats">Threat intelligence</Link><Link to="/graph">Knowledge graph</Link><Link to="/simulate">Attack paths</Link><a href="https://github.com" target="_blank" rel="noreferrer">GitHub <ExternalLink size={12} /></a></div><span className="footer-mark"><Globe2 size={15} /> 2026 / Intelligence layer online</span></footer>
    </div>
  );
};

export default NexusLandingPage;
