'use client';

import { BookOpen, Info, Layers, Lock, LockKeyholeOpen, Shield, X } from 'lucide-react';
import { useVault } from '@/lib/session';
import { Logo } from '@/components/ui/Logo';
import { Tooltip } from '@/components/ui/Tooltip';

export type ModalId = 'about' | 'manual' | 'privacy' | null;

export function Navbar({ onOpen }: { onOpen: (m: ModalId) => void }) {
  const { settings, storageLabel, status, lock } = useVault();
  const initials = settings.displayName
    .split(/\s+/)
    .map((p) => p[0] ?? '')
    .join('')
    .slice(0, 2)
    .toUpperCase();

  return (
    <header className="sticky top-0 z-40 flex h-14 items-center justify-between border-b border-hair bg-[#0c1117]/95 px-4 backdrop-blur">
      <div className="flex items-center gap-2.5">
        <Logo size={26} />
      </div>

      <nav className="flex items-center gap-1">
        <button onClick={() => onOpen('about')} className="btn-ghost">
          <Info size={13} /> About
        </button>
        <button onClick={() => onOpen('manual')} className="btn-ghost">
          <BookOpen size={13} /> User Manual
        </button>
        <button onClick={() => onOpen('privacy')} className="btn-ghost">
          <Shield size={13} /> Privacy &amp; Terms
        </button>

        <span className="mx-2 hidden h-5 w-px bg-hair md:block" />

        <Tooltip
          side="bottom"
          width={300}
          text="Zero-Knowledge Client Execution: encryption, LSB embedding, extraction and steganalysis all run in this browser tab. Nothing is uploaded — the app ships with zero telemetry."
        >
          <span
            className={`hidden items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-medium md:inline-flex ${
              status === 'unlocked' ? 'border-brand/40 bg-brand/10 text-emerald-300' : 'border-hair2 bg-panel2 text-slate-400'
            }`}
          >
            {status === 'unlocked' ? <Layers size={11} /> : <Lock size={11} />}
            {status === 'unlocked' ? 'Local Mode (Zero-Log)' : 'Session Locked'}
          </span>
        </Tooltip>

        <span className="ml-1 flex h-7 w-7 items-center justify-center rounded-full border border-hair2 bg-panel3 text-[10px] font-bold text-slate-300">
          {initials || 'JD'}
        </span>
        <span className="ml-1.5 hidden text-[11px] text-slate-400 sm:block">{storageLabel}</span>

        {status === 'unlocked' ? (
          <button
            onClick={() => lock('manual lock from header')}
            className="btn-ghost ml-2 !rounded-lg border border-hair2 text-slate-300"
            title="Lock vault & flush RAM key"
          >
            <LockKeyholeOpen size={13} /> Lock Vault
          </button>
        ) : (
          <span className="ml-2 inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1.5 text-[11px] font-medium text-red-300">
            <X size={12} /> Locked
          </span>
        )}
      </nav>
    </header>
  );
}
