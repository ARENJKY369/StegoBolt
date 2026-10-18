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
import { useMemo, useState, type ReactNode } from 'react';
import { CIPHER, sealPayload, sha256Hex, textEnc } from '@/lib/crypto';
import { dimsCapacityBytes } from '@/lib/lsbcore';
import { encodeBlob } from '@/lib/image';
import { measureQuality } from '@/lib/analysis';
import { backupDir, fsapiSupported, pickBackupDir, writeToDir, suggestedBackupPath } from '@/lib/fsaccess';
import { fmtBytes } from '@/lib/format';
import { workerEmbed } from '@/lib/worker';
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
  psnrDb: number;
  mse: number;
  ssim: number;
  bitsUsed: number;
  capacityBits: number;
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

  const cipher = encrypt ? algorithm : CIPHER.RAW;
  const payloadBytes = useMemo(() => textEnc.encode(payload).length, [payload]);
  const capacity = pixels
    ? dimsCapacityBytes(pixels.width, pixels.height)
    : loaded && loaded.width && loaded.height
    ? dimsCapacityBytes(loaded.width, loaded.height)
    : null;
  const needed = payloadBytes + (encrypt ? 16 + 12 : 28) + 10;
  const overCapacity = capacity != null && needed > capacity;
  const busy = stage !== null;
  const canRun = !!pixels && payloadBytes > 0 && !overCapacity && (!encrypt || password.length > 0) && !busy;

  const runEmbed = async () => {
    if (!loaded || !pixels) {
      setError('Select a lossless cover image (PNG / BMP / TIFF / WebP) first.');
      return;
    }
    if (!payloadBytes) {
      setError('The Secret Payload box is empty.');
      return;
    }
    if (encrypt && !password) {
      setError('Encrypt Payload is armed — a password is required to derive the AES key.');
      return;
    }
    if (overCapacity) {
      setError(`Payload (${fmtBytes(needed)}) exceeds this carrier's LSB capacity.`);
      return;
    }
    setError(null);
    setResult(null);
    try {
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
            accept="image/png,image/bmp,image/webp,image/gif,image/tiff,image/jpeg"
            hint="PNG / BMP / TIFF / WebP recommended — lossy JPEG recompression destroys the LSB plane"
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
                {loaded?.width && loaded?.height
                  ? `${fmtBytes(needed)} payload · carrier LSB capacity ${capacity != null ? fmtBytes(capacity) : '…'}`
                  : `carrier capacity unknown until an image is decoded`}
              </span>
              <span className={`font-medium ${overCapacity ? 'text-red-400' : payloadBytes === 0 ? 'text-slate-600' : 'text-emerald-400'}`}>
                {overCapacity ? 'OVER CAPACITY' : `${((needed / Math.max(1, capacity ?? 1)) * 100).toFixed(2)}% of plane used`}
                <InfoTip text={TIPS.LSB} width={290} />
              </span>
            </div>
          </div>

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
                  <Toggle checked={encrypt} onChange={setEncrypt} label="Encrypt payload" />
                </div>
                {!encrypt && (
                  <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-300">
                    Warning: unencrypted payloads are trivially recoverable by anyone with an LSB dumper.
                  </p>
                )}
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <p className="label">Algorithm</p>
                    <select
                      value={algorithm}
                      disabled={!encrypt}
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
            </div>
            <div className="flex gap-2">
              <button onClick={() => downloadBlob(result.blob, result.name)} className="btn-green !py-2">
                <FolderInput size={13} /> Download Stego File
              </button>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2 text-center sm:grid-cols-4">
            <Metric label={<>PSNR <InfoTip text={TIPS.PSNR} width={300} /></>} value={Number.isFinite(result.psnrDb) ? `${result.psnrDb.toFixed(2)} dB` : '∞'} good={result.psnrDb > 40} />
            <Metric label={<>SSIM <InfoTip text={TIPS.SSIM} width={280} /></>} value={result.ssim.toFixed(5)} good={result.ssim > 0.99} />
            <Metric label="Bits embedded" value={`${(result.bitsUsed / 8).toFixed(0)} B / ${((result.bitsUsed / result.capacityBits) * 100).toFixed(3)}%`} />
            <Metric label="MSE · carrier" value={`${result.mse.toFixed(4)} · ${typeBadge(result.name, 'image/png')} ${fmtBytes(result.blob.size)}`} />
          </div>
          <p className="mt-3 text-[10.5px] leading-relaxed text-slate-500">
            Imperceptible modification verified — the SBV2 container lives only in the lowest bit of R/G/B bytes. To recover: switch to
            Extract (Decode), load this PNG and supply the password.
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
