import React, { useState, useEffect } from 'react';
import { 
  SlidersHorizontal, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle, 
  Flame, 
  RotateCcw,
  Sparkles,
  ArrowRight,
  ZapOff,
  RefreshCw,
  WifiOff
} from 'lucide-react';
import StatCard from '../components/common/StatCard';
import { nexusApi } from '../services/api';

export const SimulationPage = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [controls, setControls] = useState({
    patchLog4j: false,
    isolateAdminWs: false,
    kerberosArmoring: false,
    blockS3Exfil: false
  });

  useEffect(() => {
    async function loadInitialMetrics() {
      try {
        const res = await nexusApi.getMetrics();
        setMetrics(res.data);
      } catch (err) {
        // Backend offline, fallback to standard neutral baseline
        setError(err.response?.data?.message || err.message);
      } finally {
        setLoading(false);
      }
    }
    loadInitialMetrics();
  }, []);

  const toggleControl = (key) => {
    setControls(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const resetAll = () => {
    setControls({
      patchLog4j: false,
      isolateAdminWs: false,
      kerberosArmoring: false,
      blockS3Exfil: false
    });
  };

  // Calculate simulated metrics based on live or baseline telemetry
  const activeCount = Object.values(controls).filter(Boolean).length;
  const basePosture = metrics?.securityPostureScore != null ? metrics.securityPostureScore : 70;
  const initialPaths = metrics?.activeAttackPaths != null ? metrics.activeAttackPaths : 3;

  const postureIncrease = activeCount * 7;
  const simulatedPosture = Math.min(98, basePosture + postureIncrease);
  const activeAttackPaths = Math.max(0, initialPaths - (controls.patchLog4j ? 2 : 0) - (controls.isolateAdminWs ? 1 : 0));
  const protectedCrownJewels = controls.isolateAdminWs && controls.patchLog4j ? 'Fully Shielded' : 'Vulnerable';

  const controlDefinitions = [
    {
      key: 'patchLog4j',
      title: 'Apply Patch to Log4j (CVE-2021-44228) on DMZ Web Portal',
      description: 'Upgrades Apache Log4j to >= 2.17.1, completely eliminating remote JNDI exploit injection from internet attackers.',
      impact: 'Severed 2 attack paths directly from threat actor (198.51.100.44)',
      scoreGain: '+8 Posture'
    },
    {
      key: 'isolateAdminWs',
      title: 'Quarantine Admin Workstation IT-04 (10.0.5.88)',
      description: 'Isolates compromised IT workstation from internal subnet via 802.1X NAC, preventing SMB lateral pivot and credential harvesting.',
      impact: 'Blocked DCSync and Kerberoasting path to Domain Controller',
      scoreGain: '+8 Posture'
    },
    {
      key: 'kerberosArmoring',
      title: 'Enforce Kerberos Armoring & FAST Authentication on DC',
      description: 'Hardens Active Directory against offline Kerberoast hash cracking and Ticket Granting Service ticket spoofing.',
      impact: 'Mitigates lateral privilege escalation to Domain Admin',
      scoreGain: '+6 Posture'
    },
    {
      key: 'blockS3Exfil',
      title: 'Restrict Cloud S3 Egress & Enforce IAM Least Privilege',
      description: 'Revokes wildcards on BackupRole and configures AWS VPC endpoint policy to prevent unauthorized database dump uploads.',
      impact: 'Stops automated data exfiltration to external cloud bucket',
      scoreGain: '+6 Posture'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400">
            <SlidersHorizontal className="h-4 w-4" />
            WHAT-IF REMEDIATION & POSTURE SIMULATOR
          </div>
          <h2 className="mt-1 text-2xl font-bold tracking-tight text-white">Proactive Security Engineering</h2>
          <p className="text-xs text-slate-400 font-mono">
            Model the risk reduction of zero-trust host isolations, CVE patches, and network micro-segmentation before applying changes.
          </p>
        </div>

        <button
          onClick={resetAll}
          className="flex items-center gap-2 self-start rounded-lg border border-white/10 bg-cyber-900 px-3.5 py-2 font-mono text-xs text-slate-300 transition-all hover:bg-slate-800 hover:text-white active:scale-95"
        >
          <RotateCcw className="h-3.5 w-3.5 text-cyan-400" />
          RESET SIMULATION
        </button>
      </div>

      {/* Simulated Outcomes KPI Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Simulated Posture"
          value={`${simulatedPosture} / 100`}
          subtitle={`Baseline: ${basePosture}/100 (+${postureIncrease} gain)`}
          color="emerald"
          trend={`+${postureIncrease}% Projected Gain`}
          icon={ShieldCheck}
        />
        <StatCard
          title="Residual Attack Paths"
          value={activeAttackPaths}
          subtitle={`Reduced from ${initialPaths} baseline paths`}
          color={activeAttackPaths === 0 ? 'emerald' : 'rose'}
          trend={activeAttackPaths === 0 ? 'All Attack Vectors Neutralized' : `${activeAttackPaths} Vectors Still Open`}
          icon={Flame}
        />
        <StatCard
          title="Crown Jewel Status"
          value={protectedCrownJewels}
          subtitle="Domain Controller & Financial DB"
          color={protectedCrownJewels === 'Fully Shielded' ? 'emerald' : 'amber'}
          trend={protectedCrownJewels === 'Fully Shielded' ? 'Attack Paths Broken' : 'Exposure Detected'}
          icon={ShieldAlert}
        />
        <StatCard
          title="Active Interventions"
          value={`${activeCount} / ${controlDefinitions.length}`}
          subtitle="Remediation controls engaged"
          color="cyan"
          trend={`${activeCount} Controls Simulated`}
          icon={Sparkles}
        />
      </div>

      {/* Simulation Controls Matrix */}
      <div className="rounded-xl border border-white/10 bg-cyber-900/80 p-6 backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-5">
          <div>
            <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
              PROPOSED MITIGATION ACTIONS
            </h3>
            <p className="text-xs text-slate-400">
              Toggle actions to evaluate real-time attack graph severance and risk score improvement
            </p>
          </div>
          <span className="font-mono text-xs text-cyan-400">
            {activeCount} Active Interventions
          </span>
        </div>

        <div className="space-y-3">
          {controlDefinitions.map((ctrl) => {
            const isChecked = controls[ctrl.key];

            return (
              <div
                key={ctrl.key}
                onClick={() => toggleControl(ctrl.key)}
                className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border p-4 transition-all cursor-pointer ${
                  isChecked
                    ? 'border-emerald-500/40 bg-emerald-950/20 shadow-[0_0_15px_rgba(16,185,129,0.1)]'
                    : 'border-white/5 bg-cyber-950/60 hover:border-white/15'
                }`}
              >
                <div className="flex items-start gap-3.5">
                  <div className="pt-0.5">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => {}} // handled by parent div
                      className="h-4 w-4 rounded border-slate-700 bg-cyber-900 text-emerald-500 focus:ring-emerald-400 focus:ring-offset-0 cursor-pointer"
                    />
                  </div>
                  <div>
                    <h4 className="font-mono text-xs font-bold text-white leading-snug">
                      {ctrl.title}
                    </h4>
                    <p className="mt-1 text-xs text-slate-400 font-sans max-w-2xl leading-relaxed">
                      {ctrl.description}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px]">
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">
                        <CheckCircle className="h-3.5 w-3.5" />
                        {ctrl.impact}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex sm:flex-col items-center sm:items-end justify-between gap-2 shrink-0">
                  <span
                    className={`rounded px-2.5 py-1 font-mono text-xs font-bold ${
                      isChecked
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {ctrl.scoreGain}
                  </span>
                  <span className="font-mono text-[10px] text-slate-500">
                    {isChecked ? 'SIMULATED' : 'DISABLED'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default SimulationPage;
