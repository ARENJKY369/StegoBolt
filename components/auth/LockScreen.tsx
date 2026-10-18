'use client';

/**
 * Local Vault Lock Screen (§2). Doubles as:
 *  • the dedicated /login route (full page, setup or unlock mode)
 *  • the in-workspace overlay shown when auto-lock fires (blurred backdrop)
 *
 * First-time setup: master passphrase (min 8) + optional WebAuthn enrollment.
 * Returning users: biometric primary path, PBKDF2-derived passphrase fallback.
 */

import { CornerDownLeft, Eye, EyeOff, Fingerprint, KeyRound, ShieldCheck, Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { importVaultFile } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { LogoMark as BrandMark } from '@/components/ui/Logo';

function LogoMark({ size = 56 }: { size?: number }) {
  return (
    <div
      className="flex items-center justify-center rounded-full"
      style={{
        width: size,
        height: size,
        background: 'radial-gradient(circle at 35% 30%, rgba(34,197,94,0.22), rgba(10,14,19,0.95) 68%)',
        boxShadow: '0 0 34px rgba(34,197,94,0.25), inset 0 0 0 1px rgba(34,197,94,0.35)',
      }}
    >
      <BrandMark size={Math.round(size * 0.58)} />
    </div>
  );
}

function passphraseStrength(p: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
  let s = 0;
  if (p.length >= 8) s++;
  if (p.length >= 14) s++;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
  if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++;
  const labels = ['Too weak', 'Weak', 'Fair', 'Strong', 'Hardened'];
  return { score: s as 0 | 1 | 2 | 3 | 4, label: labels[s] };
}

export function LockScreen({ mode: forcedMode, overlay }: { mode?: 'setup' | 'unlock'; overlay?: boolean }) {
  const vault = useVault();
  const router = useRouter();
  const importRef = useRef<HTMLInputElement>(null);
  const mode = forcedMode ?? (vault.status === 'unconfigured' ? 'setup' : 'unlock');

  const [pass, setPass] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [busy, setBusy] = useState<'pass' | 'bio' | 'import' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enrollBio, setEnrollBio] = useState(true);

  const strength = passphraseStrength(pass);

  const goWorkspace = () => {
    if (window.location.pathname !== '/workspace') router.replace('/workspace');
  };

  const submitPass = async () => {
    setError(null);
    if (busy) return;
    setBusy('pass');
    try {
      if (mode === 'setup') {
        if (pass.length < 8) {
          setError('Master passphrase must be at least 8 characters.');
          return;
        }
        if (pass !== confirm) {
          setError('Passphrases do not match.');
          return;
        }
        const res = await vault.setupVault(pass, enrollBio);
        if (res === 'weak') {
          setError('Master passphrase must be at least 8 characters.');
          return;
        }
        setPass('');
        setConfirm('');
        goWorkspace();
      } else {
        if (!pass) {
          setError('Enter your master passphrase to unlock the vault.');
          return;
        }
        const res = await vault.unlockWithPassphrase(pass);
        if (res === 'ok') {
          setPass('');
          goWorkspace();
        } else if (res === 'bad') {
          setError('Incorrect master passphrase. The AES verifier rejected this derivation.');
        } else {
          setError('No vault on this device yet — create your master passphrase first.');
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unexpected crypto failure');
    } finally {
      setBusy(null);
    }
  };

  const submitBio = async () => {
    setError(null);
    if (busy) return;
    setBusy('bio');
    const res = await vault.unlockWithBiometric();
    setBusy(null);
    if (res === 'ok') goWorkspace();
    else if (res === 'unavailable')
      setError('Biometric unlock is not enrolled on this device (or your browser blocked WebAuthn here). Use the master passphrase below.');
    else setError('The platform authenticator did not approve the unlock. Try again or use your passphrase.');
  };

  const onImport = async (f: File | null) => {
    if (!f) return;
    setBusy('import');
    setError(null);
    try {
      const r = await importVaultFile(f);
      vault.log(`Imported ${r.added} vault manifest entries from ${f.name}`, 'ok');
      setError(null);
      setNotice(`✔ Imported ${r.added} backup entries from ${f.name}. Hidden data remains inside your media files — re-attach them in Extract.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed');
    } finally {
      setBusy(null);
      if (importRef.current) importRef.current.value = '';
    }
  };

  const card = (
    <div className="w-full max-w-[420px] animate-popin rounded-2xl border border-hair2 bg-[#0d1219]/95 p-7 shadow-[0_40px_120px_rgba(0,0,0,0.7)] backdrop-blur-xl">
      <div className="flex flex-col items-center gap-3 text-center">
        <LogoMark />
        <h1 className="flex items-center gap-2 text-[19px] font-bold tracking-tight text-slate-100">
          {mode === 'unlock' && <span aria-hidden>🔒</span>}
          {mode === 'unlock' ? 'STEGOBOLT VAULT LOCKED' : 'STEGOBOLT VAULT SETUP'}
          {mode === 'unlock' && <span aria-hidden>🔒</span>}
        </h1>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-brand/40 bg-brand/10 px-3 py-1 text-[11px] font-medium text-emerald-300">
          <ShieldCheck size={12} /> Zero-Knowledge Session Security
        </span>
      </div>

      {mode === 'unlock' && vault.biometricReady && (
        <button onClick={submitBio} disabled={busy !== null} className="btn-green mt-6 w-full !py-3 normal-case tracking-normal">
          <Fingerprint size={16} />
          {busy === 'bio' ? 'Waiting for platform authenticator…' : 'Unlock with Biometrics (Touch ID / Windows Hello)'}
        </button>
      )}
      {mode === 'unlock' && !vault.biometricReady && (
        <button
          onClick={submitBio}
          disabled={busy !== null}
          title="WebAuthn platform authenticator not detected in this context"
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-hair2 bg-panel2/60 px-4 py-3 text-[12.5px] font-medium text-slate-500 transition hover:text-slate-300"
        >
          <Fingerprint size={16} /> Unlock with Biometrics (Touch ID / Windows Hello) — not enrolled
        </button>
      )}

      <div className="my-5 flex items-center gap-3 text-[10px] font-semibold tracking-[0.25em] text-slate-600">
        <span className="h-px flex-1 bg-hair" /> OR <span className="h-px flex-1 bg-hair" />
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submitPass();
        }}
      >
        <label className="label text-left !text-slate-300">
          {mode === 'setup' ? 'Create Master Passphrase (min 8 characters)' : 'Enter Master Passphrase'}
          <InfoTip text={TIPS.PBKDF2} side="bottom" />
        </label>
        <div className="relative">
          <KeyRound size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type={show ? 'text' : 'password'}
            value={pass}
            autoFocus
            onChange={(e) => {
              setPass(e.target.value);
              setError(null);
              setNotice(null);
            }}
            placeholder={mode === 'setup' ? 'At least 8 characters…' : 'Enter Master Passphrase...'}
            className="input !rounded-lg pl-9 pr-10"
            autoComplete="off"
          />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            aria-label={show ? 'Hide passphrase' : 'Show passphrase'}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-300"
          >
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>

        {mode === 'setup' && (
          <>
            <div className="mt-2 flex items-center gap-1.5">
              {[0, 1, 2, 3].map((i) => (
                <span
                  key={i}
                  className={`h-1 flex-1 rounded-full ${
                    pass && strength.score > i
                      ? strength.score >= 3
                        ? 'bg-brand'
                        : 'bg-yellow-500'
                      : 'bg-[#263041]'
                  }`}
                />
              ))}
              <span className={`ml-2 w-[70px] text-right text-[10.5px] ${strength.score >= 3 ? 'text-emerald-400' : 'text-slate-500'}`}>
                {pass ? strength.label : ''}
              </span>
            </div>
            <label className="label mt-4 !text-slate-300">Confirm Passphrase</label>
            <div className="relative">
              <KeyRound size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type={showConfirm ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => {
                  setConfirm(e.target.value);
                  setError(null);
                }}
                placeholder="Repeat passphrase…"
                className="input !rounded-lg pl-9 pr-10"
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setShowConfirm((s) => !s)}
                aria-label={showConfirm ? 'Hide confirmation' : 'Show confirmation'}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-300"
              >
                {showConfirm ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <label className="mt-4 flex cursor-pointer items-start gap-2.5 rounded-lg border border-hair bg-panel2/50 p-3 text-left">
              <input
                type="checkbox"
                checked={enrollBio}
                onChange={(e) => setEnrollBio(e.target.checked)}
                className="mt-0.5 h-3.5 w-3.5 accent-[#22a35b]"
              />
              <span>
                <span className="block text-[12px] font-medium text-slate-200">Optional: Register Biometric Hardware</span>
                <span className="block text-[11px] leading-relaxed text-slate-500">
                  Windows Hello / Touch ID / fingerprint via WebAuthn. Your passphrase is still the root secret — biometrics only open a
                  device-bound key wrap that never leaves this browser profile.
                </span>
              </span>
            </label>
          </>
        )}

        {error && <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11.5px] leading-relaxed text-red-300">{error}</p>}
        {notice && <p className="mt-3 rounded-lg border border-brand/30 bg-brand/10 px-3 py-2 text-[11.5px] text-emerald-300">{notice}</p>}

        <button type="submit" disabled={busy !== null} className="btn-outline mt-5 w-full !py-2.5">
          <CornerDownLeft size={14} />
          {busy === 'pass'
            ? mode === 'setup'
              ? 'Deriving AES-256 key via PBKDF2 (100k iterations)…'
              : 'Verifying passphrase…'
            : mode === 'setup'
            ? 'CREATE VAULT & UNLOCK'
            : 'UNLOCK VAULT'}
        </button>
      </form>

      <p className="mt-4 text-center text-[11px] leading-relaxed text-slate-500">
        {mode === 'setup'
          ? 'The key is derived in browser RAM only. If this passphrase is lost, the vault is mathematically unrecoverable.'
          : 'Master passphrase is required to decrypt local data.'}{' '}
        {mode === 'unlock' && (
          <>
            Forgot?{' '}
            <button
              type="button"
              onClick={() => importRef.current?.click()}
              disabled={busy !== null}
              className="inline-flex cursor-pointer items-center gap-1 font-medium text-emerald-400 hover:text-emerald-300"
            >
              <Upload size={10} /> Import backup key (.stegvault)
            </button>
          </>
        )}
        <input
          ref={importRef}
          type="file"
          accept=".stegvault,application/json"
          className="hidden"
          onChange={(e) => void onImport(e.target.files?.[0] ?? null)}
        />
      </p>
    </div>
  );

  if (overlay) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-md">
        {card}
      </div>
    );
  }
  return <div className="grid-bg flex min-h-screen items-center justify-center bg-ink px-4">{card}</div>;
}
