'use client';

/**
 * Vault session — the single source of truth for the in-RAM AES key, the
 * auto-lock lifecycle, local settings and the system log.
 *
 * Zero-knowledge contract:
 *  • the derived AES-256 key NEVER touches disk — only a PBKDF2 verifier and
 *    (optionally) a device-wrapped copy readable by this browser profile alone
 *  • tab hidden → key flushed; 5 min idle → key flushed; manual lock flushes
 *  • every volatile byte buffer held by the workspace is wiped on lock
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  deriveAesKey,
  exportKeyRaw,
  fromB64,
  gcmDecrypt,
  gcmEncrypt,
  importAesKeyRaw,
  PBKDF2_ITERATIONS,
  randomBytes,
  textDec,
  textEnc,
  toB64,
  wipe,
} from './crypto';
import { lsGet, lsGetJson, lsRemove, lsSet, lsSetJson } from './store';
import { assertBiometric, isUserVerifyingPlatform, registerBiometric, webauthnSupported } from './webauthn';
import { clearDemoHistory, clearVault, seedDemoHistory } from './vault';
import { getWorkerMode, primeWorker } from './worker';

export const K_SETUP = 'sb.setup.v2';
export const K_BIO = 'sb.bio.v2';
export const K_DEVICE = 'sb.devicekey.v2';
export const K_SETTINGS = 'sb.settings.v2';
export const K_TOUR = 'sb.tour.v2';
export const K_PRIVACY = 'sb.privacy.v2';
export const VERIFIER = 'SBOLT-VERIFIER-V2';

export type SessionStatus = 'boot' | 'unconfigured' | 'locked' | 'unlocked';

export interface LogEntry {
  ts: number;
  kind: 'info' | 'ok' | 'warn' | 'err';
  msg: string;
}

export interface Settings {
  displayName: string;
  autoLockMin: number;
  autoSave: boolean;
  backupToDisk: boolean;
  backupDirLabel: string;
  defaultCipher: number;
}

export const DEFAULT_SETTINGS: Settings = {
  displayName: 'John Doe',
  autoLockMin: 5,
  autoSave: true,
  backupToDisk: true,
  backupDirLabel: '',
  defaultCipher: 1,
};

export interface Artifacts {
  coverName?: string;
  coverBytes?: Uint8Array | null;
  coverInfo?: string;
  stegoName?: string;
  stegoBytes?: Uint8Array | null;
  stegoInfo?: string;
  payloadBytes?: Uint8Array | null;
  payloadInfo?: string;
}

export interface SetupBlob {
  salt: string;
  iv: string;
  ct: string;
  iterations: number;
}

export interface BioBlob {
  credId: string;
  wrapped: { iv: string; ct: string };
}

interface VaultContextValue {
  status: SessionStatus;
  setupExists: boolean;
  biometricReady: boolean;
  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => void;
  logs: LogEntry[];
  log: (msg: string, kind?: LogEntry['kind']) => void;
  idleRemaining: number;
  lockEpoch: number;
  storageLabel: string;
  workerMode: string;
  refreshStorage: () => void;
  lock: (reason?: string) => void;
  setupVault: (passphrase: string, enrollBiometric: boolean) => Promise<'ok' | 'weak'>;
  unlockWithPassphrase: (pass: string) => Promise<'ok' | 'bad' | 'none'>;
  unlockWithBiometric: () => Promise<'ok' | 'unavailable' | 'failed'>;
  changePassphrase: (oldPass: string, newPass: string) => Promise<'ok' | 'bad'>;
  registerBiometricNow: () => Promise<'ok' | 'unsupported' | 'cancelled'>;
  removeBiometric: () => void;
  wipeAllLocal: () => Promise<void>;
  artifacts: Artifacts;
  setArtifacts: (patch: Partial<Artifacts> | null) => void;
  getSessionKey: () => CryptoKey | null;
}

const VaultContext = createContext<VaultContextValue | null>(null);

export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error('useVault must be used inside <VaultProvider>');
  return ctx;
}

export function VaultProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionStatus>('boot');
  const [setupExists, setSetupExists] = useState(false);
  const [biometricReady, setBiometricReady] = useState(false);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [idleRemaining, setIdleRemaining] = useState(DEFAULT_SETTINGS.autoLockMin * 60);
  const [lockEpoch, setLockEpoch] = useState(0);
  const [storageLabel, setStorageLabel] = useState('…');
  const [workerMode, setWorkerMode] = useState('—');
  const [artifacts, setArtifactsState] = useState<Artifacts>({});

  const keyRef = useRef<CryptoKey | null>(null);
  const lastActivity = useRef<number>(Date.now());
  const statusRef = useRef<SessionStatus>('boot');
  statusRef.current = status;
  const settingsRef = useRef(settings);
  settingsRef.current = settings;

  const log = useCallback((msg: string, kind: LogEntry['kind'] = 'info') => {
    setLogs((prev) => [{ ts: Date.now(), kind, msg }, ...prev].slice(0, 60));
  }, []);

  const setArtifacts = useCallback((patch: Partial<Artifacts> | null) => {
    setArtifactsState((prev) => {
      if (patch === null) return {};
      return { ...prev, ...patch };
    });
  }, []);

  const refreshStorage = useCallback(() => {
    if (typeof navigator === 'undefined' || !navigator.storage?.estimate) {
      setStorageLabel('Local storage: n/a');
      return;
    }
    navigator.storage
      .estimate()
      .then((est) => {
        const mb = ((est.usage ?? 0) / (1024 * 1024)).toFixed(1);
        setStorageLabel(`Local Storage: ${mb} MB Used`);
      })
      .catch(() => setStorageLabel('Local Storage: 0.0 MB Used'));
  }, []);

  /* ---------------- boot ---------------- */
  useEffect(() => {
    const setup = lsGetJson<SetupBlob | null>(K_SETUP, null);
    setSetupExists(!!setup);
    setStatus(setup ? 'locked' : 'unconfigured');
    setSettings({ ...DEFAULT_SETTINGS, ...lsGetJson<Partial<Settings>>(K_SETTINGS, {}) });
    log(
      setup
        ? 'Vault state restored — session key must be re-derived in RAM'
        : 'No vault detected on this device. First-time setup required.',
      'info'
    );
    if (webauthnSupported()) {
      isUserVerifyingPlatform().then((platform) => {
        const bio = lsGetJson<BioBlob | null>(K_BIO, null);
        setBiometricReady(!!bio && platform);
      });
    }
    refreshStorage();
    primeWorker();
    const t = setTimeout(() => setWorkerMode(getWorkerMode()), 800);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ---------------- device key (biometric wrap only) ---------------- */
  const getDeviceKey = useCallback(async (): Promise<CryptoKey> => {
    let b64 = lsGet(K_DEVICE);
    if (!b64) {
      b64 = toB64(randomBytes(32));
      lsSet(K_DEVICE, b64);
    }
    return importAesKeyRaw(fromB64(b64));
  }, []);

  /* ---------------- unlock helpers ---------------- */
  const deriveFromSetup = useCallback(async (passphrase: string): Promise<CryptoKey> => {
    const setup = lsGetJson<SetupBlob | null>(K_SETUP, null);
    if (!setup) throw new Error('NO_SETUP');
    // Never weaken below the current KDF cost — a corrupted or tampered blob
    // cannot downgrade PBKDF2 iterations.
    const iterations = Math.max(PBKDF2_ITERATIONS, Math.floor(setup.iterations || 0));
    const key = await deriveAesKey(passphrase, fromB64(setup.salt), iterations, true);
    const pt = await gcmDecrypt(key, fromB64(setup.iv), fromB64(setup.ct));
    if (textDec.decode(pt) !== VERIFIER) throw new Error('VERIFIER_MISMATCH');
    return key;
  }, []);

  const afterUnlock = useCallback(
    async (key: CryptoKey, how: string) => {
      keyRef.current = key;
      setStatus('unlocked');
      lastActivity.current = Date.now();
      log(`🔓 Vault unlocked (${how}) — AES-256-GCM key lives in RAM only`, 'ok');
      void seedDemoHistory().then(() => refreshStorage());
    },
    [log, refreshStorage]
  );

  const unlockWithPassphrase = useCallback(
    async (pass: string): Promise<'ok' | 'bad' | 'none'> => {
      if (!lsGetJson<SetupBlob | null>(K_SETUP, null)) return 'none';
      try {
        const key = await deriveFromSetup(pass);
        // keep the biometric wrap in sync with the freshly derived key
        const bio = lsGetJson<BioBlob | null>(K_BIO, null);
        if (bio) {
          try {
            const dk = await getDeviceKey();
            const iv = randomBytes(12);
            const raw = await exportKeyRaw(key);
            const ct = await gcmEncrypt(dk, iv, raw);
            wipe(raw);
            lsSetJson(K_BIO, { credId: bio.credId, wrapped: { iv: toB64(iv), ct: toB64(ct) } });
          } catch {
            /* wrap refresh is best-effort */
          }
        }
        await afterUnlock(key, 'master passphrase · PBKDF2 100k');
        return 'ok';
      } catch {
        log('✖ Unlock rejected — wrong passphrase (verifier did not authenticate)', 'err');
        return 'bad';
      }
    },
    [afterUnlock, deriveFromSetup, getDeviceKey, log]
  );

  const unlockWithBiometric = useCallback(async (): Promise<'ok' | 'unavailable' | 'failed'> => {
    const bio = lsGetJson<BioBlob | null>(K_BIO, null);
    if (!bio || !webauthnSupported()) return 'unavailable';
    try {
      const ok = await assertBiometric(bio.credId);
      if (!ok) {
        log('✖ WebAuthn assertion not satisfied', 'err');
        return 'failed';
      }
      const dk = await getDeviceKey();
      const raw = await gcmDecrypt(dk, fromB64(bio.wrapped.iv), fromB64(bio.wrapped.ct));
      const key = await importAesKeyRaw(raw);
      wipe(raw);
      await afterUnlock(key, 'platform biometric + device-wrapped key');
      return 'ok';
    } catch (err) {
      const e = err as { name?: string; message?: string };
      if (e?.name === 'NotAllowedError') {
        log('✖ Biometric cancelled or timed out — passphrase fallback remains available', 'warn');
        return 'failed';
      }
      log(`✖ Biometric unlock failed: ${e?.message ?? 'unknown error'}`, 'err');
      return 'failed';
    }
  }, [afterUnlock, getDeviceKey, log]);

  /* ---------------- setup ---------------- */
  const setupVault = useCallback(
    async (passphrase: string, enroll: boolean): Promise<'ok' | 'weak'> => {
      if (passphrase.length < 8) return 'weak';
      const salt = randomBytes(16);
      const key = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS, true);
      const iv = randomBytes(12);
      const ct = await gcmEncrypt(key, iv, textEnc.encode(VERIFIER));
      lsSetJson(K_SETUP, { salt: toB64(salt), iv: toB64(iv), ct: toB64(ct), iterations: PBKDF2_ITERATIONS });
      setSetupExists(true);
      if (enroll && webauthnSupported()) {
        try {
          const credId = await registerBiometric(settingsRef.current.displayName);
          const dk = await getDeviceKey();
          const wIv = randomBytes(12);
          const raw = await exportKeyRaw(key);
          const wCt = await gcmEncrypt(dk, wIv, raw);
          wipe(raw);
          lsSetJson(K_BIO, { credId, wrapped: { iv: toB64(wIv), ct: toB64(wCt) } });
          setBiometricReady(true);
          log('🛡 Biometric hardware enrolled — vault key wrapped for this device profile only', 'ok');
        } catch (err) {
          const e = err as { name?: string };
          log(
            e?.name === 'NotAllowedError'
              ? 'Biometric enrollment dismissed — passphrase-only mode remains fully secure'
              : 'Biometric enrollment unavailable in this browser context — passphrase-only mode active',
            'warn'
          );
        }
      }
      await afterUnlock(key, 'first-time setup · PBKDF2 100k');
      return 'ok';
    },
    [afterUnlock, getDeviceKey, log]
  );

  const changePassphrase = useCallback(
    async (oldPass: string, newPass: string): Promise<'ok' | 'bad'> => {
      if (newPass.length < 8) return 'bad';
      try {
        await deriveFromSetup(oldPass); // verifies old passphrase
      } catch {
        return 'bad';
      }
      const salt = randomBytes(16);
      const key = await deriveAesKey(newPass, salt, PBKDF2_ITERATIONS, true);
      const iv = randomBytes(12);
      const ct = await gcmEncrypt(key, iv, textEnc.encode(VERIFIER));
      lsSetJson(K_SETUP, { salt: toB64(salt), iv: toB64(iv), ct: toB64(ct), iterations: PBKDF2_ITERATIONS });
      const bio = lsGetJson<BioBlob | null>(K_BIO, null);
      if (bio) {
        try {
          const dk = await getDeviceKey();
          const wIv = randomBytes(12);
          const raw = await exportKeyRaw(key);
          const wCt = await gcmEncrypt(dk, wIv, raw);
          wipe(raw);
          lsSetJson(K_BIO, { credId: bio.credId, wrapped: { iv: toB64(wIv), ct: toB64(wCt) } });
        } catch {
          /* rewrap best-effort */
        }
      }
      keyRef.current = key;
      log('✔ Master passphrase rotated — old derivation is unrecoverable by design', 'ok');
      return 'ok';
    },
    [deriveFromSetup, getDeviceKey, log]
  );

  const registerBiometricNow = useCallback(async (): Promise<'ok' | 'unsupported' | 'cancelled'> => {
    if (!webauthnSupported() || !keyRef.current) return 'unsupported';
    try {
      const credId = await registerBiometric(settingsRef.current.displayName);
      const dk = await getDeviceKey();
      const wIv = randomBytes(12);
      const raw = await exportKeyRaw(keyRef.current);
      const wCt = await gcmEncrypt(dk, wIv, raw);
      wipe(raw);
      lsSetJson(K_BIO, { credId, wrapped: { iv: toB64(wIv), ct: toB64(wCt) } });
      setBiometricReady(true);
      log('🛡 Biometric hardware registered for instant unlock', 'ok');
      return 'ok';
    } catch {
      log('Biometric registration dismissed or blocked by this browser', 'warn');
      return 'cancelled';
    }
  }, [getDeviceKey, log]);

  const removeBiometric = useCallback(() => {
    lsRemove(K_BIO);
    setBiometricReady(false);
    log('Biometric binding removed — passphrase is the only unlock path again', 'warn');
  }, [log]);

  /* ---------------- lock lifecycle ---------------- */
  const lock = useCallback(
    (reason?: string) => {
      if (statusRef.current !== 'unlocked') return;
      keyRef.current = null;
      setStatus('locked');
      setLockEpoch((n) => n + 1);
      setArtifactsState((prev) => {
        wipe(prev.coverBytes, prev.stegoBytes, prev.payloadBytes);
        return {};
      });
      setIdleRemaining(settingsRef.current.autoLockMin * 60);
      log(`🔒 Vault locked${reason ? ` — ${reason}` : ''} · RAM key flushed · pixel & payload buffers zeroized`, 'warn');
    },
    [log]
  );

  // tab visibility auto-lock
  useEffect(() => {
    if (typeof document === 'undefined') return;
    const onVis = () => {
      if (document.visibilityState === 'hidden' && statusRef.current === 'unlocked') {
        lock('tab hidden → volatile session key flushed');
      } else if (document.visibilityState === 'visible') {
        lastActivity.current = Date.now();
      }
    };
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, [lock]);

  // inactivity auto-lock (5 min default, user-tunable)
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const bump = () => {
      if (statusRef.current === 'unlocked') lastActivity.current = Date.now();
    };
    const events: (keyof WindowEventMap)[] = ['pointerdown', 'pointermove', 'keydown', 'wheel'];
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, bump));
  }, []);

  useEffect(() => {
    if (status !== 'unlocked') return;
    const timer = setInterval(() => {
      const secs = Math.max(0, settingsRef.current.autoLockMin * 60 - (Date.now() - lastActivity.current) / 1000);
      setIdleRemaining(secs);
      if (secs <= 0) lock(`inactivity timeout (${settingsRef.current.autoLockMin} min)`);
    }, 1000);
    return () => clearInterval(timer);
  }, [status, lock]);

  useEffect(() => {
    const t = setInterval(() => setWorkerMode(getWorkerMode()), 5000);
    return () => clearInterval(t);
  }, []);

  /* ---------------- settings + wipe ---------------- */
  const updateSettings = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      lsSetJson(K_SETTINGS, next);
      return next;
    });
  }, []);

  const wipeAllLocal = useCallback(async () => {
    try {
      await clearVault();
    } catch {
      /* noop */
    }
    lsRemove(K_SETUP);
    lsRemove(K_BIO);
    lsRemove(K_DEVICE);
    lsRemove(K_TOUR);
    lsRemove(K_PRIVACY);
    lsRemove('sb.demo.v1');
    keyRef.current = null;
    setSetupExists(false);
    setBiometricReady(false);
    setStatus('unconfigured');
    // zeroize in-RAM cover / stego / payload buffers before dropping references
    setArtifactsState((prev) => {
      wipe(prev.coverBytes, prev.stegoBytes, prev.payloadBytes);
      return {};
    });
    log('💥 All local vault state erased (passphrase, verifier, biometric wrap, IndexedDB history)', 'err');
  }, [log]);

  const getSessionKey = useCallback(() => keyRef.current, []);

  const value = useMemo<VaultContextValue>(
    () => ({
      status,
      setupExists,
      biometricReady,
      settings,
      updateSettings,
      logs,
      log,
      idleRemaining,
      lockEpoch,
      storageLabel,
      workerMode,
      refreshStorage,
      lock,
      setupVault,
      unlockWithPassphrase,
      unlockWithBiometric,
      changePassphrase,
      registerBiometricNow,
      removeBiometric,
      wipeAllLocal,
      artifacts,
      setArtifacts,
      getSessionKey,
    }),
    [
      status,
      setupExists,
      biometricReady,
      settings,
      updateSettings,
      logs,
      log,
      idleRemaining,
      lockEpoch,
      storageLabel,
      workerMode,
      refreshStorage,
      lock,
      setupVault,
      unlockWithPassphrase,
      unlockWithBiometric,
      changePassphrase,
      registerBiometricNow,
      removeBiometric,
      wipeAllLocal,
      artifacts,
      setArtifacts,
      getSessionKey,
    ]
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export { clearDemoHistory };
