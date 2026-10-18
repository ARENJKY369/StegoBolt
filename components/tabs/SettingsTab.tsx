'use client';

/**
 * Workspace settings — operator profile, auto-lock lifecycle, biometric
 * binding, default crypto algorithm, tour replay, passphrase rotation and
 * the nuclear “wipe this device” control.
 */

import { Compass, Fingerprint, KeyRound, RotateCcw, ShieldCheck, ShieldX, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { CIPHER, PBKDF2_ITERATIONS } from '@/lib/crypto';
import { clearDemoHistory } from '@/lib/vault';
import { webauthnSupported } from '@/lib/webauthn';
import { useVault } from '@/lib/session';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { Toggle } from '@/components/ui/Toggle';

export function SettingsTab({ onReplayTour, onOpenPrivacy }: { onReplayTour: () => void; onOpenPrivacy: () => void }) {
  const vault = useVault();
  const [name, setName] = useState(vault.settings.displayName);
  const [autoLock, setAutoLock] = useState(String(vault.settings.autoLockMin));
  const [rotOld, setRotOld] = useState('');
  const [rotNew, setRotNew] = useState('');
  const [rotMsg, setRotMsg] = useState<string | null>(null);
  const [rotBusy, setRotBusy] = useState(false);
  const [demoNote, setDemoNote] = useState<string | null>(null);

  const rotate = async () => {
    setRotBusy(true);
    setRotMsg(null);
    const res = await vault.changePassphrase(rotOld, rotNew);
    setRotBusy(false);
    if (res === 'ok') {
      setRotOld('');
      setRotNew('');
      setRotMsg('✔ Passphrase rotated.');
    } else {
      setRotMsg('✖ Old passphrase rejected, or the new one is shorter than 8 characters.');
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <section className="card space-y-4 p-5">
        <h3 className="card-title">Operator &amp; Session</h3>
        <div>
          <p className="label">Display initials (shown in header)</p>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => vault.updateSettings({ displayName: name.trim() || 'John Doe' })}
            className="input"
            placeholder="John Doe"
          />
        </div>
        <div className="flex items-center justify-between">
          <span className="flex items-center text-[12.5px] font-medium text-slate-300">
            Auto-Save embeds to vault <InfoTip text={TIPS.AUTOSAVE} width={300} />
          </span>
          <Toggle checked={vault.settings.autoSave} onChange={(v) => vault.updateSettings({ autoSave: v })} />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[12.5px] font-medium text-slate-300">Backup to Local Disk</span>
          <Toggle checked={vault.settings.backupToDisk} onChange={(v) => vault.updateSettings({ backupToDisk: v })} />
        </div>
        <div>
          <p className="label flex items-center">
            Inactivity auto-lock (minutes) <InfoTip text="The RAM key is flushed after this idle time AND instantly when the tab hides." width={280} />
          </p>
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={1}
              max={60}
              value={autoLock}
              onChange={(e) => setAutoLock(e.target.value)}
              onBlur={() => {
                const n = Math.min(60, Math.max(1, Number(autoLock) || 5));
                setAutoLock(String(n));
                vault.updateSettings({ autoLockMin: n });
              }}
              className="input !w-24 font-mono"
            />
            {[1, 5, 15].map((m) => (
              <button
                key={m}
                onClick={() => {
                  setAutoLock(String(m));
                  vault.updateSettings({ autoLockMin: m });
                }}
                className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold transition ${
                  vault.settings.autoLockMin === m ? 'border-brand/50 bg-brand/10 text-emerald-300' : 'border-hair bg-panel2 text-slate-400 hover:text-slate-200'
                }`}
              >
                {m}m
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="card space-y-4 p-5">
        <h3 className="card-title">Cryptographic Defaults</h3>
        <div>
          <p className="label flex items-center">
            Default payload algorithm <InfoTip text={TIPS.AES} width={310} />
          </p>
          <select
            value={vault.settings.defaultCipher}
            onChange={(e) => vault.updateSettings({ defaultCipher: Number(e.target.value) })}
            className="select input"
          >
            <option value={CIPHER.AES_256_GCM}>AES-256-GCM (authenticated — recommended)</option>
            <option value={CIPHER.AES_256_CTR}>AES-256-CTR (unauthenticated stream)</option>
            <option value={CIPHER.RAW}>None — raw LSB stream (public demo use only)</option>
          </select>
        </div>
        <div className="rounded-lg border border-hair bg-panel2/40 p-3 font-mono text-[10.5px] leading-relaxed text-slate-400">
          <p>KDF ........ PBKDF2-SHA256 · {PBKDF2_ITERATIONS.toLocaleString()} iterations · 16-byte random salt</p>
          <p>Master key . AES-GCM 256-bit · derived in RAM · never persisted</p>
          <p>Container .. SBV2 · 80-bit header · LSB scatter across R/G/B</p>
          <p>Biometrics . {vault.biometricReady ? 'enrolled (device key-wrap active)' : webauthnSupported() ? 'supported · not enrolled' : 'unavailable in this context'}</p>
        </div>
        <div>
          <p className="label flex items-center">
            Rotate master passphrase
            <InfoTip text="Verifies the old passphrase against the PBKDF2 verifier, then re-wraps the vault with a fresh salt." width={300} />
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input type="password" value={rotOld} onChange={(e) => setRotOld(e.target.value)} placeholder="current passphrase" className="input !w-52" autoComplete="off" />
            <input type="password" value={rotNew} onChange={(e) => setRotNew(e.target.value)} placeholder="new passphrase (≥ 8)" className="input !w-52" autoComplete="off" />
            <button onClick={() => void rotate()} disabled={rotBusy || !rotOld || !rotNew} className="btn-outline !py-2">
              <KeyRound size={13} /> {rotBusy ? 'Re-deriving…' : 'Rotate'}
            </button>
          </div>
          {rotMsg && <p className="mt-2 text-[11px] text-emerald-300">{rotMsg}</p>}
        </div>
      </section>

      <section className="card space-y-3 p-5">
        <h3 className="card-title">Biometric Hardware</h3>
        <p className="text-[11.5px] leading-relaxed text-slate-500">
          WebAuthn platform authenticator (Touch ID / Windows Hello / fingerprint). Enrollment creates a local credential and wraps the
          vault key with a device-only random key — the wrap never leaves this browser profile.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {vault.biometricReady ? (
            <>
              <span className="flex items-center gap-1.5 rounded-lg border border-brand/40 bg-brand/10 px-3 py-2 text-[12px] font-semibold text-emerald-300">
                <ShieldCheck size={13} /> Enrolled — instant unlock active
              </span>
              <button onClick={() => vault.removeBiometric()} className="btn-outline !py-2 !text-red-400/90">
                <ShieldX size={13} /> Unlink biometrics
              </button>
            </>
          ) : (
            <button
              onClick={() => void vault.registerBiometricNow().then((r) => r !== 'ok' && vault.log('Biometric enrollment did not complete (result: ' + r + ')', 'warn'))}
              disabled={!webauthnSupported() || vault.status !== 'unlocked'}
              className="btn-green !py-2"
            >
              <Fingerprint size={14} /> {webauthnSupported() ? 'Register biometric unlock' : 'WebAuthn not available in this browser'}
            </button>
          )}
        </div>
      </section>

      <section className="card space-y-3 p-5">
        <h3 className="card-title">Onboarding &amp; Legal</h3>
        <div className="flex flex-wrap gap-2">
          <button onClick={onReplayTour} className="btn-outline !py-2">
            <Compass size={13} /> Replay onboarding tour (5 steps)
          </button>
          <button onClick={onOpenPrivacy} className="btn-outline !py-2">
            <RotateCcw size={13} /> Re-read Privacy Policy &amp; Terms
          </button>
        </div>
        <p className="text-[10.5px] leading-relaxed text-slate-600">
          The tour auto-launches once after the first successful unlock. Tooltips ( <InfoTip text="Every (?) badge in the app explains itself on hover — same engine used by the manual." width={260} side="top" /> ) stay available everywhere.
        </p>
      </section>

      <section className="card border-red-500/25 p-5 xl:col-span-2">
        <h3 className="card-title text-red-300">Danger Zone</h3>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            onClick={async () => {
              await clearDemoHistory();
              vault.refreshStorage();
              setDemoNote('Demo history removed — the vault now reflects only operations you performed.');
            }}
            className="btn-outline !py-2"
          >
            <Trash2 size={13} /> Remove demo history
          </button>
          <DangerWipe />
        </div>
        {demoNote && <p className="mt-2 text-[11px] text-emerald-300">{demoNote}</p>}
      </section>
    </div>
  );
}

function DangerWipe() {
  const vault = useVault();
  const [arm, setArm] = useState(0);
  return (
    <button
      onClick={() => {
        if (arm === 0) {
          setArm(1);
          setTimeout(() => setArm(0), 4000);
        } else {
          void vault.wipeAllLocal();
        }
      }}
      className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-[12.5px] font-bold transition ${
        arm
          ? 'border-red-500 bg-red-500/25 text-red-200 shadow-[0_0_18px_rgba(239,68,68,0.25)]'
          : 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20'
      }`}
    >
      <ShieldX size={14} /> {arm ? '⚠ Click again — erases passphrase, keys & all history' : 'Erase everything on this device'}
    </button>
  );
}
