'use client';

/**
 * Main operational panel (§5): header navbar, mode switcher, the four
 * operation tabs + dashboard/vault/settings, the first-run privacy notice,
 * the 5-step guided tour, footer hex console and the auto-lock overlay.
 */

import { EyeOff, Radar, ScanSearch, Sparkles } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { K_PRIVACY, K_TOUR, useVault } from '@/lib/session';
import { lsGet, lsSet } from '@/lib/store';
import { Navbar, type ModalId } from '@/components/layout/Navbar';
import { Sidebar, type TabId } from '@/components/layout/Sidebar';
import { FooterConsole } from '@/components/layout/FooterConsole';
import { DashboardTab } from '@/components/tabs/DashboardTab';
import { HideTab } from '@/components/tabs/HideTab';
import { ExtractTab } from '@/components/tabs/ExtractTab';
import { ScanTab } from '@/components/tabs/ScanTab';
import { CleanTab } from '@/components/tabs/CleanTab';
import { VaultTab } from '@/components/tabs/VaultTab';
import { SettingsTab } from '@/components/tabs/SettingsTab';
import { AboutModal } from '@/components/modals/AboutModal';
import { UserManualModal } from '@/components/modals/UserManualModal';
import { PrivacyModal } from '@/components/modals/PrivacyModal';
import { TourGuide } from '@/components/onboarding/TourGuide';
import { LockScreen } from '@/components/auth/LockScreen';

const MODES: { id: TabId; label: string; icon: typeof EyeOff }[] = [
  { id: 'hide', label: 'Hide', icon: EyeOff },
  { id: 'extract', label: 'Extract', icon: ScanSearch },
  { id: 'scan', label: 'Scan', icon: Radar },
  { id: 'clean', label: 'Clean', icon: Sparkles },
];

export default function WorkspaceShell() {
  const vault = useVault();
  const router = useRouter();
  const [tab, setTab] = useState<TabId>('hide');
  const [modal, setModal] = useState<ModalId>(null);
  const [tourActive, setTourActive] = useState(false);
  const [privacyPending, setPrivacyPending] = useState(false);

  // First-run ceremony: privacy notice → guided tour (once).
  useEffect(() => {
    if (vault.status !== 'unlocked') return;
    const fresh = lsGet(K_PRIVACY) !== '1';
    setPrivacyPending(fresh);
    if (fresh) setModal('privacy');
    else if (lsGet(K_TOUR) !== '1') setTourActive(true);
  }, [vault.status, vault.lockEpoch]);

  useEffect(() => {
    // if session was fully erased, hop back to the dedicated setup screen
    if (vault.status === 'unconfigured') router.replace('/login');
  }, [vault.status, router]);

  const acknowledgePrivacy = () => {
    lsSet(K_PRIVACY, '1');
    setPrivacyPending(false);
    setModal(null);
    if (lsGet(K_TOUR) !== '1' && vault.status === 'unlocked') setTourActive(true);
  };

  const finishTour = () => {
    lsSet(K_TOUR, '1');
    setTourActive(false);
  };

  const locked = vault.status !== 'unlocked';

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-ink">
      <Navbar onOpen={(m) => setModal(m)} />
      <div className="flex min-h-0 flex-1">
        <Sidebar active={tab} onTab={setTab} />

        <main className="grid-bg flex min-w-0 flex-1 flex-col">
          <div className="flex items-center justify-between gap-3 border-b border-hair/60 bg-[#0c1117]/60 px-6 py-3 backdrop-blur">
            <div>
              <h1 className="text-[15px] font-bold tracking-tight text-slate-100">Main Operational Panel</h1>
              <p className="text-[10.5px] text-slate-500">
                {tab === 'hide' && 'Hide a sealed payload inside a lossless cover medium'}
                {tab === 'extract' && 'Sweep the LSB plane and authenticate the container'}
                {tab === 'scan' && 'Statistical steganalysis — threat score & visual anomalies'}
                {tab === 'clean' && 'Strip metadata & re-randomize the LSB noise floor'}
                {tab === 'vault' && 'IndexedDB journal · PC mirror folder · .stegvault export'}
                {tab === 'dashboard' && 'Session posture at a glance'}
                {tab === 'settings' && 'Security, biometrics and local data controls'}
              </p>
            </div>
            {/* 4-way tab switcher */}
            <div className="flex shrink-0 items-center gap-0.5 rounded-lg border border-hair bg-panel2 p-0.5">
              {MODES.map((m) => {
                const Icon = m.icon;
                const active = tab === m.id;
                return (
                  <button
                    key={m.id}
                    onClick={() => setTab(m.id)}
                    className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[11.5px] font-semibold transition ${
                      active ? 'bg-brand/15 text-emerald-300 shadow-[inset_0_0_0_1px_rgba(34,197,94,0.35)]' : 'text-slate-500 hover:text-slate-200'
                    }`}
                  >
                    <Icon size={12} /> {m.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            {/* key includes lockEpoch: a lock/unlock cycle remounts the active tab,
                guaranteeing zeroized buffers can never be reused by stale closures */}
            <div key={`${tab}:${vault.lockEpoch}`} className="mx-auto max-w-[1280px] animate-fadein">
              {tab === 'dashboard' && <DashboardTab onTab={setTab} />}
              {tab === 'hide' && <HideTab />}
              {tab === 'extract' && <ExtractTab />}
              {tab === 'scan' && <ScanTab />}
              {tab === 'clean' && <CleanTab />}
              {tab === 'vault' && <VaultTab />}
              {tab === 'settings' && (
                <SettingsTab
                  onReplayTour={() => {
                    setModal(null);
                    setTourActive(true);
                  }}
                  onOpenPrivacy={() => setModal('privacy')}
                />
              )}
            </div>
          </div>

          <FooterConsole />
        </main>
      </div>

      {modal === 'about' && <AboutModal onClose={() => setModal(null)} />}
      {modal === 'manual' && <UserManualModal onClose={() => setModal(null)} />}
      {modal === 'privacy' && <PrivacyModal onClose={privacyPending ? acknowledgePrivacy : () => setModal(null)} acked={privacyPending} />}

      <TourGuide active={tourActive && !locked} onDone={finishTour} />

      {locked && <LockScreen overlay />}
    </div>
  );
}
