'use client';

import {
  Archive,
  Clock,
  EyeOff,
  LayoutDashboard,
  Settings as SettingsIcon,
  Search,
  Settings2,
  Sparkles,
  UnfoldVertical,
} from 'lucide-react';
import { fmtClock } from '@/lib/format';
import { useVault } from '@/lib/session';
import { Tooltip } from '@/components/ui/Tooltip';

export type TabId = 'dashboard' | 'hide' | 'extract' | 'scan' | 'clean' | 'vault' | 'settings';

export const TAB_META: Record<TabId, { label: string; icon: typeof EyeOff; hint: string }> = {
  dashboard: { label: 'Dashboard', icon: LayoutDashboard, hint: 'Session health & quick actions' },
  hide: { label: 'Hide (Encode)', icon: EyeOff, hint: 'Embed encrypted payloads into a lossless carrier' },
  extract: { label: 'Extract (Decode)', icon: UnfoldVertical, hint: 'Recover hidden payloads from stego media' },
  scan: { label: 'Forensic Scan', icon: Search, hint: 'Statistical steganalysis + threat score' },
  clean: { label: 'Sanitize & Clean', icon: Sparkles, hint: 'Strip EXIF and randomize the LSB noise floor' },
  vault: { label: 'Local Vault & Backups', icon: Archive, hint: 'IndexedDB history and PC folder sync' },
  settings: { label: 'Settings', icon: Settings2, hint: 'Security configuration' },
};

export function Sidebar({ active, onTab }: { active: TabId; onTab: (t: TabId) => void }) {
  const { idleRemaining, status } = useVault();

  const Item = ({ id }: { id: TabId }) => {
    const meta = TAB_META[id];
    const Icon = meta.icon;
    const isActive = active === id;
    return (
      <Tooltip text={meta.hint} side="right" width={220} className="w-full">
        <button
          onClick={() => onTab(id)}
          className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[12.5px] font-medium transition ${
            isActive ? 'bg-panel3 text-slate-100 shadow-[inset_0_0_0_1px_rgba(34,197,94,0.25)]' : 'text-slate-500 hover:bg-panel2 hover:text-slate-200'
          }`}
        >
          <Icon size={14} className={isActive ? 'text-emerald-400' : ''} />
          {meta.label}
        </button>
      </Tooltip>
    );
  };

  return (
    <aside className="flex w-[212px] shrink-0 flex-col border-r border-hair bg-[#0c1117] px-3 py-4">
      <div id="sb-switcher" className="flex flex-col gap-0.5">
        <Item id="dashboard" />
        <div className="mx-3 my-2 h-px bg-hair/70" />
        <Item id="hide" />
        <Item id="extract" />
        <Item id="scan" />
        <Item id="clean" />
        <div className="mx-3 my-2 h-px bg-hair/70" />
        <Item id="vault" />
        <Item id="settings" />
      </div>

      <div className="mt-auto space-y-2">
        {status === 'unlocked' && (
          <div className="rounded-lg border border-hair bg-panel2/60 p-2.5">
            <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
              <Clock size={10} className="text-emerald-400" /> Auto-lock in
            </p>
            <p className="mt-1 font-mono text-[16px] font-bold tabular-nums text-slate-200">{fmtClock(idleRemaining)}</p>
            <p className="text-[9.5px] leading-snug text-slate-600">
              Hiding this tab flushes the key instantly.
            </p>
          </div>
        )}
        <button
          onClick={() => onTab('settings')}
          className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-[12px] font-medium text-slate-500 transition hover:bg-panel2 hover:text-slate-200"
        >
          <SettingsIcon size={13} /> Settings
        </button>
      </div>
    </aside>
  );
}
