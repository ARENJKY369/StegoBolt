'use client';

/**
 * Hide (Encode) — Input & Configuration + Local Backup (PC Storage) as per
 * the reference UI. Pipeline: decode → PBKDF2/AES-256-GCM seal → SBV2 LSB
 * embedding in a Web Worker → lossless PNG → PSNR/SSIM report → vault backup.
 */

import {
  ChevronDown,
  ChevronRight,
  Eye,
  EyeOff,
  FolderOpen,
  FolderInput,
  Info,
  Loader2,
  FileDown,
  ShieldCheck,
  Sparkle,
} from 'lucide-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { CIPHER, ivLenFor, sealPayload, sha256Hex, textEnc } from '@/lib/crypto';
import { dimsCapacityBytes } from '@/lib/lsbcore';
import { encodeBlob } from '@/lib/image';
import { measureQuality } from '@/lib/analysis';
import { backupDir, fsapiSupported, pickBackupDir, writeToDir, suggestedBackupPath } from '@/lib/fsaccess';
import { fmtBytes } from '@/lib/format';
import { workerEmbed } from '@/lib/worker';
import { capacity as engineCapacity, hide as engineHide, setEngineBase } from '@/lib/engineApi';
import type { CapacityReport } from '@/lib/engineApi';
import { CARRIER_ACCEPT, capacityHint, localEngineRequired, vercelBodyLimitWarning } from '@/lib/mediums';
import { addRecord, exportVaultFile, type VaultRecord } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { FileDropzone } from '@/components/ui/Dropzone';
import { InfoTip, TIPS, Tooltip } from '@/components/ui/Tooltip';
import { Toggle } from '@/components/ui/Toggle';
import { FileChip } from './FileChip';
import { typeBadge, useStegoFile } from './useStegoFile';
import { downloadBlob, HistoryPanel } from './HistoryPanel';

interface EmbedResult {
  blob: Blob;
  name: string;
  hash: string;
  psnrDb: number | null;
  mse: number | null;
  ssim: number | null;
  bitsUsed: number;
  capacityBits: number | null;
  viaEngine?: boolean;
  medium?: string;
}

export function HideTab() {
  const vault = useVault();
  const { loaded, pixels, loading, error, setError, load, clear } = useStegoFile();
  const [payload, setPayload] = useState('');
  const [encrypt, setEncrypt] = useState(true);
  const [algorithm, setAlgorithm] = useState<number>(vault.settings.defaultCipher || CIPHER.AES_256_GCM);
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(true);
  const [stage, setStage] = useState<string | null>(null);
  const [result, setResult] = useState<EmbedResult | null>(null);
  const [dirNote, setDirNote] = useState<string | null>(null);
  const [engineCapacityReport, setEngineCapacityReport] = useState<CapacityReport | null>(null);
  const [engineCapacityBusy, setEngineCapacityBusy] = useState(false);
  const [engineCapacityError, setEngineCapacityError] = useState<string | null>(null);

  const cipher = encrypt ? algorithm : CIPHER.RAW;
  const payloadBytes = useMemo(() => textEnc.encode(payload).length, [payload]);
  const capacity = pixels
    ? dimsCapacityBytes(pixels.width, pixels.height)
    : loaded && loaded.width && loaded.height
    ? dimsCapacityBytes(loaded.width, loaded.height)
    : null;
  // Local SBV2 layout: salt(16) | iv | ciphertext/tag plus the 10-byte local header.
  const overhead =
    cipher === CIPHER.RAW ? 28 : 16 + ivLenFor(cipher) + (cipher === CIPHER.AES_256_GCM ? 16 : 0);
  const needed = payloadBytes + overhead + 10;
  const engineMode = vault.settings.engineMode === 'engine';

  useEffect(() => {
    if (engineMode) setEncrypt(true);
  }, [engineMode]);

  // Capacity is deliberately requested before Hide is enabled in engine mode.
  // That gives operators a real per-medium answer instead of an image-only
  // pixel estimate, and prevents an avoidable multipart round trip.
  useEffect(() => {
    let cancelled = false;
    if (!engineMode || !loaded) {
      setEngineCapacityReport(null);
      setEngineCapacityError(null);
      setEngineCapacityBusy(false);
      return () => {
        cancelled = true;
      };
    }
    setEngineBase(vault.settings.engineUrl);
    setEngineCapacityBusy(true);
    setEngineCapacityReport(null);
    setEngineCapacityError(null);
    engineCapacity(loaded.file)
      .then((report) => {
        if (!cancelled) setEngineCapacityReport(report);
      })
      .catch((error) => {
        if (!cancelled) setEngineCapacityError(error instanceof Error ? error.message : 'Java engine capacity check failed.');
      })
      .finally(() => {
        if (!cancelled) setEngineCapacityBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engineMode, loaded, vault.settings.engineUrl]);

  const effectiveCapacity = engineMode ? engineCapacityReport?.capacityBytes ?? null : capacity;
  const overCapacity = engineMode
    ? engineCapacityReport != null && payloadBytes > engineCapacityReport.capacityBytes
    : capacity != null && needed > capacity;
  const busy = stage !== null || engineCapacityBusy;
  const capacityReady = !engineMode || (!!engineCapacityReport && !engineCapacityBusy);
  const canRun =
    (!!loaded && (engineMode || loaded.kind !== 'image' || !!pixels)) &&
    payloadBytes > 0 &&
    capacityReady &&
    !overCapacity &&
    (engineMode ? password.length > 0 : !encrypt || password.length > 0) &&
    !busy;

  const runEmbed = async () => {
    if (!loaded) {
      setError('Choose a supported carrier file first.');
      return;
    }
    if (!engineMode && loaded.kind !== 'image') {
      setError(localEngineRequired(loaded.kind, 'embedding'));
      return;
    }
    if (!pixels && !engineMode) {
      setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
      return;
    }
    if (!payloadBytes) {
      setError('The Secret Payload box is empty.');
      return;
    }
    if (engineMode && !password) {
      setError('Java engine mode always encrypts with AES-256-GCM — enter a passphrase before embedding.');
      return;
    }
    if (!engineMode && encrypt && !password) {
      setError('Encrypt Payload is armed — a password is required to derive the AES key.');
      return;
    }
    if (engineMode && !engineCapacityReport) {
      setError('Wait for the Java engine capacity report before embedding.');
      return;
    }
    if (overCapacity) {
      setError(
        engineMode
          ? `Payload (${fmtBytes(payloadBytes)}) exceeds this ${loaded.kind} carrier's engine capacity of ${fmtBytes(engineCapacityReport?.capacityBytes ?? 0)}.`
          : `Payload (${fmtBytes(needed)}) exceeds this image's LSB capacity.`
      );
      return;
    }
    setError(null);
    setResult(null);
    try {
      if (engineMode) {
        setEngineBase(vault.settings.engineUrl);
        setStage('Handing cover + payload to the Java engine (zero-disk, RAM-only)…');
        const { report, stego, fileName } = await engineHide({
          cover: loaded.file,
          passphrase: password,
          payloadText: payload,
        });
        const name = report.stegoFileName || fileName || loaded.name.replace(/\.[^.]+$/, '') + '.stego';
        const hash = await sha256Hex(stego);
        setResult({
          blob: stego,
          name,
          hash,
          psnrDb: report.psnrDb ?? null,
          mse: null,
          ssim: null,
          bitsUsed: report.capacityUsedBits,
          capacityBits: engineCapacityReport?.capacityBits ?? null,
          viaEngine: true,
          medium: report.medium,
        });
        vault.setArtifacts({
          coverName: loaded.name,
          coverInfo: `Cover carrier ${loaded.name} · ${fmtBytes(loaded.size)} · processed by the Java engine`,
          stegoBytes: new Uint8Array(await stego.arrayBuffer()),
          stegoName: name,
          stegoInfo: `Stego object ${name} · ${fmtBytes(report.stegoBytes)} · SHA-256 ${hash.slice(0, 16)}…`,
          payloadInfo: `Payload sealed by the Java engine (PBKDF2 100k · AES-256-GCM) — ${fmtBytes(report.payloadBytes)}`,
        });
        let backup: VaultRecord['backup'] = vault.settings.autoSave ? 'Saved' : 'No local download';
        if (vault.settings.backupToDisk && backupDir.handle) {
          const ok = await writeToDir(backupDir.handle, name, stego);
          backup = ok ? 'Saved to local disk' : 'Disk write failed';
        }
        if (vault.settings.autoSave) {
          await addRecord({
            ts: Date.now(),
            op: 'Hide',
            coverName: loaded.name,
            outName: name,
            size: stego.size,
            dims: '—',
            backup,
            hash,
            payloadPreview: `••• engine-sealed payload (${fmtBytes(report.payloadBytes)}) — only the passphrase opens it •••`,
            meta: {
              Via: 'Java engine',
              'Bits used': report.capacityUsedBits.toLocaleString(),
              PSNR: report.psnrDb != null ? `${report.psnrDb.toFixed(1)} dB` : '—',
              Cipher: 'AES-256-GCM',
            },
            blob: stego,
          });
          vault.refreshStorage();
        }
        vault.log(
          `Embed complete (Java engine) — ${report.capacityUsedBits.toLocaleString()} bits hidden in ${loaded.name}${
            backup === 'Saved to local disk' ? `, mirrored to ${backupDir.path}` : vault.settings.autoSave ? ', saved to local vault' : ''
          }`,
          'ok'
        );
        return;
      }
      if (!pixels) {
        setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
        return;
      }
      setStage('Sealing payload with ' + (cipher === CIPHER.RAW ? 'raw bitstream' : 'AES-256-' + (cipher === CIPHER.AES_256_CTR ? 'CTR' : 'GCM') + ' (PBKDF2 · 100k iterations)'));
      const plain = textEnc.encode(payload);
      const sealed = await sealPayload(plain, cipher, password || 'stegobolt-unencrypted');
      plain.fill(0);

      setStage('Scattering SBV2 bitstream across the R/G/B LSB plane (Web Worker)…');
      const out = await workerEmbed(pixels.data, sealed, cipher);
      const newPixels = new Uint8Array(out.pixels);

      setStage('Rendering lossless PNG stego carrier via Canvas…');
      const blob = await encodeBlob(pixels.width, pixels.height, newPixels, 'image/png');
      const q = measureQuality(pixels.data, newPixels, out.bitsUsed, out.capacityBits);
      const name = loaded.name.replace(/\.[^.]+$/, '') + '.stego.png';
      const hash = await sha256Hex(blob);

      setResult({ blob, name, hash, psnrDb: q.psnrDb, mse: q.mse, ssim: q.ssimApprox, bitsUsed: out.bitsUsed, capacityBits: out.capacityBits });

      vault.setArtifacts({
        coverBytes: pixels.data,
        coverName: loaded.name,
        coverInfo: `Cover carrier ${loaded.name} · ${pixels.width}×${pixels.height} RGBA · ${fmtBytes(loaded.size)}`,
        stegoBytes: newPixels,
        stegoName: name,
        stegoInfo: `Stego object ${name} · ${out.bitsUsed.toLocaleString()} embedded bits`,
        payloadBytes: sealed,
        payloadInfo: 'Sealed payload container (salt | iv | ciphertext||tag) exactly as scattered into the LSB plane',
      });

      let backup: VaultRecord['backup'] = vault.settings.autoSave ? 'Saved' : 'No local download';
      if (vault.settings.backupToDisk && backupDir.handle) {
        const ok = await writeToDir(backupDir.handle, name, blob);
        backup = ok ? 'Saved to local disk' : 'Disk write failed';
      }
      if (vault.settings.autoSave) {
        await addRecord({
          ts: Date.now(),
          op: 'Hide',
          coverName: loaded.name,
          outName: name,
          size: blob.size,
          dims: `${pixels.width}×${pixels.height}`,
          backup,
          hash,
          payloadPreview: encrypt ? `••• ${cipher === CIPHER.AES_256_CTR ? 'CTR' : 'GCM'}-sealed payload (${fmtBytes(sealed.length)}) — only the passphrase opens it •••` : payload.slice(0, 240),
          meta: { 'Bits used': out.bitsUsed.toLocaleString(), PSNR: Number.isFinite(q.psnrDb) ? `${q.psnrDb.toFixed(1)} dB` : '∞', Cipher: cipher === CIPHER.RAW ? 'raw' : `AES-256-${cipher === CIPHER.AES_256_CTR ? 'CTR' : 'GCM'}` },
          blob,
        });
        vault.refreshStorage();
      }
      vault.log(
        `Embed complete — ${out.bitsUsed.toLocaleString()} bits hidden in ${loaded.name}${
          backup === 'Saved to local disk' ? `, mirrored to ${backupDir.path}` : vault.settings.autoSave ? ', saved to local vault' : ''
        }`,
        'ok'
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg.startsWith('CAPACITY_EXCEEDED') ? 'Capacity exceeded — choose a larger carrier or a shorter payload.' : msg);
    } finally {
      setStage(null);
    }
  };

  const pickDir = async () => {
    if (!fsapiSupported()) {
      setDirNote('File System Access API is not available in this browser context — backups stay in IndexedDB and normal downloads.');
      return;
    }
    try {
      const res = await pickBackupDir();
      if (res) {
        vault.updateSettings({ backupDirLabel: res.path });
        setDirNote(`Local folder attached: ${res.path} (handle held in RAM only)`);
        vault.log(`Backup directory bound to ${res.path}`, 'ok');
      }
    } catch {
      setDirNote('Directory selection was blocked by the browser.');
    }
  };

  const doExportVault = async () => {
    try {
      const blob = await exportVaultFile();
      downloadBlob(blob, 'stegobolt-backup.stegvault');
      vault.log('Exported .stegvault manifest to your device', 'ok');
    } catch {
      vault.log('Vault export failed (no records?)', 'err');
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
        {/* ------- Input & Configuration ------- */}
        <section className="card p-5">
          <h3 className="card-title mb-4">Input &amp; Configuration</h3>

          <p className="label">Select Cover File</p>
          <FileDropzone
            id="sb-dropzone"
            accept={CARRIER_ACCEPT}
            hint="PNG/BMP/WebP/GIF/TIFF/JPEG · WAV/FLAC · MP4/MKV/AVI · PDF/DOCX · text/code · PCAP/PCAPNG"
            filled={!!loaded}
            onFile={(f) => void load(f)}
          >
            {loaded && (
              <FileChip
                loaded={loaded}
                onRemove={() => {
                  clear();
                  setResult(null);
                }}
              />
            )}
          </FileDropzone>
          {loading && (
            <p className="mt-2 flex items-center gap-1.5 text-[11px] text-slate-500">
              <Loader2 size={11} className="animate-spin" /> hashing &amp; probing carrier locally…
            </p>
          )}

          <div className="mt-4">
            <p className="label flex items-center">
              Secret Payload
              <InfoTip text="Text hidden inside the carrier. Keep it under the capacity meter — it is encrypted before scattering." side="bottom" width={280} />
            </p>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              rows={4}
              placeholder="Enter your secret message here..."
              className="input resize-y font-mono text-[12px]"
            />
            <div className="mt-1.5 flex items-center justify-between text-[10.5px]">
              <span className="text-slate-600">
                {engineMode
                  ? `${fmtBytes(payloadBytes)} plaintext · engine capacity ${effectiveCapacity != null ? fmtBytes(effectiveCapacity) : '…'}`
                  : loaded?.width && loaded?.height
                  ? `${fmtBytes(needed)} sealed payload · image LSB capacity ${capacity != null ? fmtBytes(capacity) : '…'}`
                  : 'image capacity appears after a successful local decode'}
              </span>
              <span className={`font-medium ${overCapacity ? 'text-red-400' : payloadBytes === 0 ? 'text-slate-600' : 'text-emerald-400'}`}>
                {overCapacity
                  ? 'OVER CAPACITY'
                  : effectiveCapacity != null
                  ? `${((payloadBytes / Math.max(1, effectiveCapacity)) * 100).toFixed(2)}% of capacity`
                  : 'capacity pending'}
                <InfoTip text={TIPS.LSB} width={290} />
              </span>
            </div>
          </div>

          {engineMode && loaded && (
            <div className="mt-3 space-y-1.5 rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2.5 text-[10.5px] leading-relaxed">
              <p className="flex items-center justify-between gap-3 font-semibold text-sky-200">
                <span>Java engine capacity</span>
                <span className="font-mono text-sky-100">
                  {engineCapacityBusy
                    ? 'checking…'
                    : engineCapacityReport
                    ? `${fmtBytes(engineCapacityReport.capacityBytes)} payload · ${engineCapacityReport.medium}`
                    : 'unavailable'}
                </span>
              </p>
              {engineCapacityReport && (
                <>
                  <p className="text-slate-400">{capacityHint(loaded.kind, loaded.name)}</p>
                  {engineCapacityReport.details && <p className="font-mono text-[10px] text-slate-500">Engine detail: {engineCapacityReport.details}</p>}
                </>
              )}
              {engineCapacityError && <p className="text-amber-300">{engineCapacityError}</p>}
              {(() => {
                const warning = vercelBodyLimitWarning(vault.settings.engineUrl, loaded.size);
                return warning ? <p className="text-amber-300">{warning}</p> : null;
              })()}
            </div>
          )}

          {/* Security Configuration */}
          <div id="sb-security" className="mt-4 rounded-xl border border-hair bg-panel2/35 p-4 transition-shadow focus-within:shadow-glow">
            <button onClick={() => setSecurityOpen((v) => !v)} className="flex w-full items-center gap-1.5 text-left">
              {securityOpen ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
              <span className="text-[13px] font-semibold text-slate-200">Security Configuration</span>
            </button>
            {securityOpen && (
              <div className="mt-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-[12.5px] font-medium text-slate-300">
                    <ShieldCheck size={13} className="text-emerald-400" /> Encrypt Payload
                    <InfoTip text={encrypt ? TIPS.AES : 'Payload will be scattered RAW — any LSB extractor can read it. Toggle encryption for confidentiality + tamper evidence.'} width={300} />
                  </span>
                  <Toggle checked={encrypt} onChange={setEncrypt} disabled={engineMode} label="Encrypt payload" />
                </div>
                {engineMode && (
                  <p className="rounded-md border border-sky-500/25 bg-sky-500/10 px-2.5 py-1.5 text-[11px] text-sky-200">
                    Java engine mode uses AES-256-GCM for every medium. Enter a passphrase; the browser never receives the sealed key.
                  </p>
                )}
                {!encrypt && !engineMode && (
                  <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-300">
                    Warning: unencrypted payloads are trivially recoverable by anyone with an LSB dumper.
                  </p>
                )}
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p className="label">Algorithm</p>
                    <select
                      value={algorithm}
                      disabled={!encrypt || engineMode}
                      onChange={(e) => setAlgorithm(Number(e.target.value))}
                      className="select input"
                    >
                      <option value={CIPHER.AES_256_GCM}>AES-256-GCM</option>
                      <option value={CIPHER.AES_256_CTR}>AES-256-CTR</option>
                    </select>
                  </div>
                  <div>
                    <p className="label flex items-center">
                      Password
                      {algorithm === CIPHER.AES_256_CTR && <InfoTip text={TIPS.CTR} width={300} />}
                    </p>
                    <div className="relative">
                      <input
                        type={showPass ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="derive key via PBKDF2…"
                        disabled={!encrypt}
                        className="input pr-9"
                        autoComplete="off"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPass((s) => !s)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                        aria-label="toggle password visibility"
                      >
                        {showPass ? <Eye size={13} /> : <EyeOff size={13} />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {error && (
            <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11.5px] text-red-300">{error}</p>
          )}
        </section>

        {/* ------- Local Backup (PC Storage) ------- */}
        <section id="sb-backup" className="card p-5">
          <h3 className="card-title mb-3 flex items-center gap-2">
            Local Backup <span className="text-slate-500">(PC Storage)</span>
          </h3>
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-sky-500/25 bg-sky-500/10 px-3 py-2.5 text-[11.5px] leading-relaxed text-sky-200/90">
            <Info size={13} className="mt-0.5 shrink-0 text-sky-400" />
            Automatic backups are stored locally on your device.
            <Tooltip text={TIPS.INDEXEDDB} width={300} side="bottom" className="ml-auto shrink-0">
              <span className="cursor-help text-[9px] font-bold text-sky-300/70">?</span>
            </Tooltip>
          </div>

          <p className="label flex items-center">
            Backup Directory Path
            <InfoTip text={TIPS.FSA} width={310} />
          </p>
          <div className="flex gap-2">
            <input
              readOnly
              value={vault.settings.backupDirLabel || suggestedBackupPath()}
              className="input flex-1 font-mono !text-[11.5px]"
              title={vault.settings.backupDirLabel ? 'Live folder handle attached this session' : 'Cosmetic default — click the folder button to bind a real local directory'}
            />
            <button onClick={() => void pickDir()} className="btn-outline !px-3" title="Choose a local backup folder (File System Access API)">
              <FolderOpen size={14} />
            </button>
          </div>
          {dirNote && <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">{dirNote}</p>}
          <p className="mt-1.5 text-[10px] text-slate-600">
            File System Access API: {fsapiSupported() ? <span className="text-emerald-400">supported</span> : <span className="text-amber-400">unsupported here — IndexedDB + manual downloads remain active</span>}
          </p>

          <div className="mt-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[12.5px] font-medium text-slate-300">
                Auto-Save on every Embed <InfoTip text={TIPS.AUTOSAVE} width={300} />
              </span>
              <Toggle checked={vault.settings.autoSave} onChange={(v) => vault.updateSettings({ autoSave: v })} label="Auto-save embeds to vault" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[12.5px] font-medium text-slate-300">Backup to Local Disk</span>
              <Toggle
                checked={vault.settings.backupToDisk}
                onChange={(v) => {
                  vault.updateSettings({ backupToDisk: v });
                  if (v && !backupDir.handle) setDirNote('Enable this after attaching a folder with the button above.');
                }}
                label="Backup to local disk"
              />
            </div>
          </div>

          <button onClick={() => void runEmbed()} disabled={!canRun} className="btn-green mt-5 w-full">
            {busy ? (
              <>
                <Loader2 size={14} className="animate-spin" /> {stage}
              </>
            ) : (
              <>
                <Sparkle size={14} /> [ Embed &amp; Backup File ]
              </>
            )}
          </button>
          <button onClick={() => void doExportVault()} className="btn-outline mt-2.5 w-full">
            <FileDown size={13} /> [ Export Vault File (.stegvault) ]
          </button>

          {stage && (
            <div className="mt-3 h-1 overflow-hidden rounded-full bg-panel3">
              <div className="h-full w-1/3 animate-pulse rounded-full bg-brand" />
            </div>
          )}
        </section>
      </div>

      {/* Embed result */}
      {result && (
        <section className="card border-brand/35 p-5 shadow-[0_0_0_1px_rgba(34,197,94,0.15),0_10px_30px_rgba(0,0,0,0.35)]">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h3 className="card-title flex items-center gap-2 text-emerald-300">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-brand/20"><ShieldCheck size={12} className="text-emerald-400" /></span>
                Stego object ready — {result.name}
              </h3>
              <p className="mt-1 font-mono text-[10.5px] text-slate-500">SHA-256 {result.hash}</p>
              {result.viaEngine && <p className="mt-1 text-[10.5px] text-sky-300">{result.medium} · Java engine report · {fmtBytes(result.blob.size)} output</p>}
            </div>
            <div className="flex gap-2">
              <button onClick={() => downloadBlob(result.blob, result.name)} className="btn-green !py-2">
                <FolderInput size={13} /> Download Stego File
              </button>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2 text-center sm:grid-cols-4">
            <Metric label={<>PSNR <InfoTip text={TIPS.PSNR} width={300} /></>} value={result.psnrDb == null ? '—' : Number.isFinite(result.psnrDb) ? `${result.psnrDb.toFixed(2)} dB` : '∞'} good={result.psnrDb != null && result.psnrDb > 40} />
            <Metric label={<>SSIM <InfoTip text={TIPS.SSIM} width={280} /></>} value={result.ssim == null ? (result.viaEngine ? 'engine-reported' : '—') : result.ssim.toFixed(5)} good={result.ssim != null && result.ssim > 0.99} />
            <Metric label="Bits embedded" value={result.capacityBits ? `${(result.bitsUsed / 8).toFixed(0)} B / ${((result.bitsUsed / result.capacityBits) * 100).toFixed(3)}%` : `${(result.bitsUsed / 8).toFixed(0)} B`} />
            <Metric label="MSE · carrier" value={`${result.mse == null ? '—' : result.mse.toFixed(4)} · ${typeBadge(result.name, result.viaEngine ? loaded?.type || 'application/octet-stream' : 'image/png')} ${fmtBytes(result.blob.size)}`} />
          </div>
          <p className="mt-3 text-[10.5px] leading-relaxed text-slate-500">
            {result.viaEngine
              ? `The Java engine reported a ${result.name.toLowerCase().endsWith('.png') ? 'lossless PNG' : 'medium-preserving'} stego carrier. To recover it, switch to Extract, load this file and supply the same passphrase.`
              : 'The SBV2 container lives in the lowest bit of the image colour channels. To recover it, switch to Extract, load this PNG and supply the password.'}
          </p>
        </section>
      )}

      <HistoryPanel limit={3} />
    </div>
  );
}

function Metric({ label, value, good }: { label: ReactNode; value: string; good?: boolean }) {
  return (
    <div className="rounded-lg border border-hair bg-panel2/50 px-3 py-2.5">
      <p className="text-[9.5px] font-bold uppercase tracking-[0.12em] text-slate-500">{label}</p>
      <p className={`mt-1 font-mono text-[13px] font-semibold ${good === undefined ? 'text-slate-200' : good ? 'text-emerald-400' : 'text-amber-400'}`}>{value}</p>
    </div>
  );
}
