'use client';

import { Activity, Archive, ArrowRight, Clock, Cpu, Database, EyeOff, Lock, Radar, Sparkles, UnfoldVertical } from 'lucide-react';
import { useLiveQuery } from 'dexie-react-hooks';
import { fmtBytes, fmtClock } from '@/lib/format';
import { db } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import type { TabId } from '@/components/layout/Sidebar';

export function DashboardTab({ onTab }: { onTab: (t: TabId) => void }) {
  const vault = useVault();
  const recent = useLiveQuery(async () => (await db().operations.orderBy('ts').reverse().limit(5).toArray()).slice(), []);

  const quick: { id: TabId; label: string; desc: string; icon: typeof EyeOff; tone: string }[] = [
    { id: 'hide', label: 'Hide a payload', desc: 'AES-256-GCM → LSB scatter → lossless PNG', icon: EyeOff, tone: 'text-emerald-400' },
    { id: 'extract', label: 'Extract a payload', desc: 'SBV2 sweep + GCM tag verification', icon: UnfoldVertical, tone: 'text-sky-400' },
    { id: 'scan', label: 'Scan a suspect', desc: 'Chi-square / entropy / signature suite', icon: Radar, tone: 'text-amber-400' },
    { id: 'clean', label: 'Sanitize media', desc: 'Strip EXIF, re-noise the LSB floor', icon: Sparkles, tone: 'text-fuchsia-400' },
  ];

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-4">
        <div className="card p-4 lg:col-span-2">
          <p className="flex items-center text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <Lock size={11} className="mr-1 text-emerald-400" /> Session
          </p>
          <div className="mt-2 flex items-end justify-between">
            <div>
              <p className="text-[22px] font-bold tracking-tight text-slate-100">
                {vault.status === 'unlocked' ? 'Vault open' : 'Vault locked'}
              </p>
              <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">
                AES-256-GCM key {vault.status === 'unlocked' ? 'held in RAM' : 'flushed'} · PBKDF2-SHA256 100k{' '}
                <InfoTip text={TIPS.PBKDF2} width={300} />
              </p>
            </div>
            {vault.status === 'unlocked' && (
              <div className="text-right">
                <p className="font-mono text-[20px] font-bold tabular-nums text-emerald-400">{fmtClock(vault.idleRemaining)}</p>
                <p className="text-[9.5px] uppercase tracking-widest text-slate-500">until auto-lock</p>
              </div>
            )}
          </div>
          <div className="mt-3 grid grid-cols-3 gap-2 border-t border-hair pt-3 text-[11px] text-slate-400">
            <span className="flex items-center gap-1.5"><Activity size={11} className="text-emerald-400" /> Workers: {vault.workerMode === 'worker' ? 'LSB worker live' : 'main-thread'}</span>
            <span className="flex items-center gap-1.5"><Cpu size={11} className="text-emerald-400" /> Web Crypto native</span>
            <span className="flex items-center gap-1.5"><Database size={11} className="text-emerald-400" /> IDB journal</span>
          </div>
        </div>

        <div className="card flex flex-col justify-between p-4">
          <p className="flex items-center text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <Archive size={11} className="mr-1 text-emerald-400" /> Local vault
          </p>
          <p className="mt-2 text-[22px] font-bold tracking-tight text-slate-100">
            {recent ? recent.length : '…'} <span className="text-[11px] font-medium text-slate-500">recent ops</span>
          </p>
          <p className="mt-0.5 text-[11px] text-slate-500">{vault.storageLabel}</p>
          <button onClick={() => onTab('vault')} className="link-green mt-2 flex items-center gap-1 text-[11.5px]">
            Open vault <ArrowRight size={11} />
          </button>
        </div>

        <div className="card flex flex-col justify-between p-4">
          <p className="flex items-center text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
            <ShieldDot /> Privacy posture
          </p>
          <div className="mt-2 space-y-1 text-[11px] leading-relaxed text-slate-400">
            <p>✔ 0 network calls for user data</p>
            <p>✔ No cookies / no analytics</p>
            <p>✔ Biometric optional (WebAuthn)</p>
          </div>
          <p className="mt-2 text-[9.5px] text-slate-600">Verified at build time — this app bundles no fetch targets.</p>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {quick.map((q) => {
          const Icon = q.icon;
          return (
            <button
              key={q.id}
              onClick={() => onTab(q.id)}
              className="card group flex items-center gap-3 p-4 text-left transition hover:border-brand/40 hover:shadow-glow"
            >
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-panel3">
                <Icon size={15} className={q.tone} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[12.5px] font-semibold text-slate-100">{q.label}</span>
                <span className="block truncate text-[10.5px] text-slate-500">{q.desc}</span>
              </span>
              <ArrowRight size={13} className="text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-emerald-400" />
            </button>
          );
        })}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
        <section className="card p-5">
          <h3 className="card-title mb-3">Recent Activity <span className="text-[10.5px] font-normal text-slate-600">· live from IndexedDB</span></h3>
          {!recent || recent.length === 0 ? (
            <p className="py-6 text-center text-[12px] text-slate-600">Nothing yet — hide, extract, scan or sanitize to start the journal.</p>
          ) : (
            <ul className="space-y-1.5">
              {recent.map((r) => (
                <li key={r.id} className="flex items-center gap-3 rounded-lg border border-hair/60 bg-panel2/40 px-3 py-2 text-[12px]">
                  <span className={`w-14 shrink-0 rounded px-1.5 py-0.5 text-center text-[9.5px] font-extrabold uppercase ${
                    r.op === 'Hide' ? 'bg-brand/15 text-emerald-300' : r.op === 'Extract' ? 'bg-sky-500/15 text-sky-300' : r.op === 'Scan' ? 'bg-amber-500/15 text-amber-300' : 'bg-fuchsia-500/15 text-fuchsia-300'
                  }`}>{r.op}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-slate-300">{r.coverName}</span>
                  <span className="hidden shrink-0 text-[10.5px] text-slate-500 sm:block">{fmtBytes(r.size)}</span>
                  <Clock size={10} className="shrink-0 text-slate-600" />
                  <span className="shrink-0 text-[10.5px] text-slate-500">
                    {new Date(r.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-5">
          <h3 className="card-title mb-3">System Log</h3>
          <ul className="max-h-[220px] space-y-1 overflow-y-auto pr-1 font-mono text-[10.5px] leading-relaxed">
            {vault.logs.length === 0 && <li className="text-slate-600">log buffer empty</li>}
            {vault.logs.map((l, i) => (
              <li key={i} className={l.kind === 'err' ? 'text-red-400' : l.kind === 'warn' ? 'text-amber-400/90' : l.kind === 'ok' ? 'text-emerald-400/90' : 'text-slate-500'}>
                <span className="text-slate-700">[{new Date(l.ts).toLocaleTimeString([], { hour12: false })}]</span> {l.msg}
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}

function ShieldDot() {
  return <span className="mr-1 inline-block h-2 w-2 rounded-full bg-brand shadow-[0_0_8px_rgba(34,197,94,0.8)]" />;
}
