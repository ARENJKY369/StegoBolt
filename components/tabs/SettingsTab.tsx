'use client';

/**
 * Workspace settings — operator profile, auto-lock lifecycle, biometric
 * binding, default crypto algorithm, tour replay, passphrase rotation and
 * the nuclear “wipe this device” control.
 */

import { Compass, Fingerprint, KeyRound, Loader2, RotateCcw, Server, ShieldCheck, ShieldX, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { CIPHER, PBKDF2_ITERATIONS } from '@/lib/crypto';
import { capacity as engineCapacity, getEngineBase, setEngineBase } from '@/lib/engineApi';
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

      <section className="card space-y-3 p-5">
        <h3 className="card-title">Java Engine (optional backend)</h3>
        <p className="text-[11.5px] leading-relaxed text-slate-500">
          StegoBolt can delegate Hide &amp; Extract to the local Java 17 engine at{' '}
          <span className="font-mono text-slate-400">http://localhost:8080</span> — same algorithms, but running outside the
          browser with zero-disk RAM-only processing. Local mode keeps everything in this tab (recommended unless you are
          operating the engine).
        </p>
        <div className="flex gap-2">
          {(['local', 'engine'] as const).map((m) => (
            <button
              key={m}
              onClick={() => vault.updateSettings({ engineMode: m })}
              className={`rounded-lg border px-3 py-2 text-[12px] font-semibold transition ${
                vault.settings.engineMode === m
                  ? 'border-brand/50 bg-brand/10 text-emerald-300'
                  : 'border-hair bg-panel2 text-slate-400 hover:text-slate-200'
              }`}
            >
              {m === 'local' ? 'Local (in-browser)' : 'Java engine'}
            </button>
          ))}
        </div>
        <div>
          <p className="label">Engine base URL</p>
          <input
            value={vault.settings.engineUrl}
            onChange={(e) => vault.updateSettings({ engineUrl: e.target.value })}
            onBlur={() => setEngineBase(vault.settings.engineUrl)}
            className="input font-mono !text-[11.5px]"
            placeholder="http://localhost:8080"
            spellCheck={false}
          />
        </div>
        <EngineProbe />
        <p className="text-[10.5px] leading-relaxed text-slate-600">
          The engine exposes <span className="font-mono">POST /api/v1/stego&#123;/hide,/extract,/scan,/clean,/capacity&#125;</span>.
          Only this origin is allowed by the app&apos;s Content-Security-Policy; files never touch disk on the engine side.
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

function EngineProbe() {
  const vault = useVault();
  const [state, setState] = useState<{ ok: boolean; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const probe = async () => {
    setBusy(true);
    setState(null);
    setEngineBase(vault.settings.engineUrl);
    try {
      // 1×1 transparent PNG — enough for the engine to sniff an image medium.
      const png = new Uint8Array([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49,
        0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
      ]);
      const report = await engineCapacity(new File([png], 'probe.png', { type: 'image/png' }));
      setState({
        ok: true,
        msg: `Engine online at ${getEngineBase()} — probe PNG capacity ${report.capacityBytes} bytes (${report.medium}).`,
      });
      vault.log(`Java engine probe OK — ${report.medium} capacity ${report.capacityBytes} bytes`, 'ok');
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setState({ ok: false, msg: `Engine unreachable: ${msg}` });
      vault.log(`Java engine probe failed — ${msg}`, 'warn');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <button onClick={() => void probe()} disabled={busy} className="btn-outline !py-2">
        {busy ? <Loader2 size={13} className="animate-spin" /> : <Server size={13} />} Test engine connection
      </button>
      {state && (
        <p className={`mt-2 text-[11px] leading-relaxed ${state.ok ? 'text-emerald-300' : 'text-amber-300'}`}>{state.msg}</p>
      )}
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
