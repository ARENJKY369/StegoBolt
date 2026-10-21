'use client';

/**
 * Sanitize & Clean — rebuilds the image through Canvas (erasing EXIF/XMP/ICC
 * and every ancillary chunk) and re-draws the whole LSB noise floor from the
 * CSPRNG, destroying prior hidden bitstreams and low-entropy tells.
 */

import { Check, Eraser, Loader2, RadioTower, ShieldCheck, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { sha256Hex } from '@/lib/crypto';
import { clean as engineClean, setEngineBase, type CleanResponse } from '@/lib/engineApi';
import { CARRIER_ACCEPT, localEngineRequired } from '@/lib/mediums';
import { inspectMetadata, type MetadataReport } from '@/lib/exif';
import { encodeBlob } from '@/lib/image';
import { fmtBytes } from '@/lib/format';
import { measureQuality } from '@/lib/analysis';
import { workerNoise } from '@/lib/worker';
import { addRecord } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { FileDropzone } from '@/components/ui/Dropzone';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { Toggle } from '@/components/ui/Toggle';
import { FileChip } from './FileChip';
import { useStegoFile } from './useStegoFile';
import { downloadBlob } from './HistoryPanel';

export function CleanTab() {
  const vault = useVault();
  const { loaded, pixels, loading, error, setError, load, clear } = useStegoFile();
  const [stripMeta, setStripMeta] = useState(true);
  const [noiseFloor, setNoiseFloor] = useState(true);
  const [fmt, setFmt] = useState<'image/png' | 'image/jpeg'>('image/png');
  const [quality, setQuality] = useState(0.94);
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{
    blob: Blob;
    name: string;
    hash: string;
    changed: number;
    psnr: number | null;
    after: MetadataReport | null;
    viaEngine?: boolean;
    engineReport?: CleanResponse;
  } | null>(null);

  const report: MetadataReport | null = useMemo(() => {
    if (!loaded?.bytes) return null;
    try {
      return inspectMetadata(loaded.bytes, loaded.name);
    } catch {
      return null;
    }
  }, [loaded]);

  const run = async () => {
    const engineMode = vault.settings.engineMode === 'engine';
    if (!loaded) {
      setError('Choose a supported carrier file first.');
      return;
    }
    if (!engineMode && loaded.kind !== 'image') {
      setError(localEngineRequired(loaded.kind, 'cleaning'));
      return;
    }
    if (!engineMode && !pixels) {
      setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
      return;
    }
    const imagePixels = pixels;
    setBusy(true);
    setError(null);
    setOut(null);
    try {
      if (engineMode) {
        setEngineBase(vault.settings.engineUrl);
        const { report, cleaned, fileName } = await engineClean(loaded.file, noiseFloor);
        const name = fileName || loaded.name.replace(/\.[^.]+$/, '') + '.clean';
        const hash = await sha256Hex(cleaned);
        setOut({
          blob: cleaned,
          name,
          hash,
          changed: report.changedBits,
          psnr: report.psnrDb ?? null,
          after: null,
          viaEngine: true,
          engineReport: report,
        });
        vault.setArtifacts({
          coverName: loaded.name,
          coverInfo: `Original of ${name} · processed by the Java engine`,
          stegoName: name,
          stegoInfo: `Sanitized ${name} · ${fmtBytes(report.cleanedBytes)} · ${report.changedBits.toLocaleString()} bits changed`,
        });
        void addRecord({
          ts: Date.now(),
          op: 'Sanitize',
          coverName: loaded.name,
          outName: name,
          size: cleaned.size,
          dims: loaded.width && loaded.height ? `${loaded.width}×${loaded.height}` : '—',
          backup: 'No local download',
          hash,
          meta: {
            Via: 'Java engine',
            Medium: report.medium,
            'Tags stripped': report.exifTagsRemoved.toLocaleString(),
            'LSB bits changed': report.changedBits.toLocaleString(),
          },
          blob: cleaned,
        }).then(() => vault.refreshStorage());
        vault.log(`Java engine cleaned ${loaded.name} → ${name} (${fmtBytes(cleaned.size)})`, 'ok');
        return;
      }

      if (!imagePixels) {
        setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
        return;
      }
      let work: Uint8Array;
      let touched = 0;
      if (noiseFloor) {
        const res = await workerNoise(imagePixels.data);
        work = new Uint8Array(res.pixels);
        touched = res.touched;
      } else {
        work = imagePixels.data.slice();
      }
      const passthrough = !noiseFloor && !stripMeta;
      const name = passthrough ? loaded.name : loaded.name.replace(/\.[^.]+$/, '') + (fmt === 'image/png' ? '.clean.png' : '.clean.jpg');
      const blob = passthrough ? loaded.file : await encodeBlob(imagePixels.width, imagePixels.height, work, fmt, quality);
      const hash = await sha256Hex(blob);
      const q = measureQuality(imagePixels.data, work, touched, imagePixels.width * imagePixels.height * 3);
      let after: MetadataReport | null = null;
      if (stripMeta) {
        try {
          after = inspectMetadata(await blob.arrayBuffer(), name);
        } catch {
          after = null;
        }
      }
      setOut({ blob, name, hash, changed: q.bitsChanged, psnr: q.psnrDb, after });
      vault.setArtifacts({
        coverBytes: imagePixels.data,
        coverName: loaded.name,
        coverInfo: `Original of ${name}`,
        stegoBytes: work,
        stegoName: name,
        stegoInfo: `Sanitized ${name} · ${fmtBytes(blob.size)} · ${touched.toLocaleString()} LSB slots re-noised`,
      });
      void addRecord({
        ts: Date.now(),
        op: 'Sanitize',
        coverName: loaded.name,
        outName: name,
        size: blob.size,
        dims: `${imagePixels.width}×${imagePixels.height}`,
        backup: 'Saved',
        hash,
        meta: { 'Tags stripped': report ? report.tags.length + report.textChunks.length : 'n/a', 'LSB bits re-randomized': touched.toLocaleString() },
        blob,
      }).then(() => vault.refreshStorage());
      vault.log(`Sanitized ${loaded.name} → ${name} (${fmtBytes(blob.size)})`, 'ok');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Sanitization failed');
    } finally {
      setBusy(false);
    }
  };

  const tagCount = report ? report.tags.length : 0;
  const engineMode = vault.settings.engineMode === 'engine';

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
      <section className="card space-y-4 p-5">
        <h3 className="card-title">Carrier to Scrub</h3>
        <FileDropzone
          accept={CARRIER_ACCEPT}
          hint="Clean images locally, or use Java engine mode for WAV/FLAC, video, documents, text/code and PCAP"
          filled={!!loaded}
          onFile={(f) => {
            setOut(null);
            void load(f);
          }}
        >
          {loaded && (
            <FileChip
              loaded={loaded}
              onRemove={() => {
                clear();
                setOut(null);
              }}
            />
          )}
        </FileDropzone>
        {loading && (
          <p className="flex items-center gap-1.5 text-[11px] text-slate-500">
            <Loader2 size={11} className="animate-spin" /> parsing containers for metadata…
          </p>
        )}

        <div className="rounded-xl border border-hair bg-panel2/40 p-3.5">
          <p className="mb-2 flex items-center text-[11.5px] font-bold uppercase tracking-[0.1em] text-slate-400">
            Detected Metadata
            <InfoTip text={TIPS.EXIF} width={320} />
            {report && tagCount > 0 && (
              <span className="ml-auto rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-[9.5px] font-bold text-red-300">
                {tagCount} TAG{tagCount === 1 ? '' : 'S'} FOUND
              </span>
            )}
          </p>
          {!report ? (
            <p className="text-[11.5px] text-slate-600">{loaded ? 'Not an inspectable raster — load a PNG/JPEG.' : 'Drop a file to enumerate its EXIF/XMP baggage.'}</p>
          ) : report.tags.length === 0 && report.textChunks.length === 0 ? (
            <p className="flex items-center gap-1.5 text-[11.5px] text-emerald-400/90">
              <Check size={12} /> No {report.format} metadata found — this {report.format} is already lean. LSB floor is still re-randomized on clean.
            </p>
          ) : (
            <div className="max-h-44 space-y-1 overflow-y-auto pr-1">
              {report.tags.map((t, i) => (
                <p key={i} className="flex items-baseline justify-between gap-3 font-mono text-[10.5px]">
                  <span className="text-slate-500">{t.label}</span>
                  <span className="truncate text-right text-slate-200">{t.value}</span>
                </p>
              ))}
              {report.hasGps && (
                <p className="mt-1 flex items-center gap-1.5 rounded-md bg-red-500/10 px-2 py-1 text-[10.5px] font-semibold text-red-300">
                  <RadioTower size={11} /> Geolocation embedded — sanitize before sharing!
                </p>
              )}
            </div>
          )}
        </div>
      </section>

      <section className="card p-5">
        <h3 className="card-title flex items-center gap-2">
          <Eraser size={14} className="text-fuchsia-400" /> Sanitization Recipe
        </h3>
        {engineMode && (
          <p className="mt-3 rounded-lg border border-sky-500/25 bg-sky-500/10 px-3 py-2 text-[11px] leading-relaxed text-sky-200">
            Java engine mode delegates Clean for all six mediums. It removes the medium&apos;s hidden layer and returns the sanitized binary object with an X-StegoBolt-Report.
          </p>
        )}
        <div className="mt-3 space-y-3">
          <div className="flex items-center justify-between rounded-lg border border-hair bg-panel2/40 px-3 py-2.5">
            <span className="text-[12px] font-medium text-slate-300">
              Strip EXIF / XMP metadata <InfoTip text="Canvas re-encode rebuilds the container from raw pixels — every tag, thumbnail, ICC hint and PNG text chunk outside IHDR/IDAT/IEND is discarded." width={300} />
            </span>
            <Toggle checked={stripMeta} onChange={setStripMeta} disabled={engineMode} label="Strip metadata" />
          </div>
          <div className="flex items-center justify-between rounded-lg border border-hair bg-panel2/40 px-3 py-2.5">
            <span className="text-[12px] font-medium text-slate-300">
              Randomize LSB noise floor <InfoTip text={TIPS.LSB} width={290} />
            </span>
            <Toggle checked={noiseFloor} onChange={setNoiseFloor} label="Randomize LSB plane" />
          </div>
          <div className="grid grid-cols-2 items-center gap-3 rounded-lg border border-hair bg-panel2/40 px-3 py-2.5">
            <span className="text-[12px] font-medium text-slate-300">Output container</span>
            <div className="flex items-center justify-end gap-2">
              <select disabled={engineMode} value={fmt} onChange={(e) => setFmt(e.target.value as 'image/png' | 'image/jpeg')} className="select !w-auto !bg-transparent !py-1 text-[11.5px]">
                <option value="image/png">PNG · lossless</option>
                <option value="image/jpeg">JPEG · recompress</option>
              </select>
            </div>
            {fmt === 'image/jpeg' && (
              <>
                <span className="text-[11px] text-slate-500">Quality {(quality * 100).toFixed(0)}</span>
                <input type="range" min={70} max={98} value={Math.round(quality * 100)} onChange={(e) => setQuality(Number(e.target.value) / 100)} className="accent-[#22a35b]" />
              </>
            )}
          </div>
          {fmt === 'image/jpeg' && (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-[10.5px] leading-relaxed text-amber-300">
              JPEG quantization also crushes any fragile LSB payload — but it degrades visual fidelity versus PNG.
            </p>
          )}
        </div>

        {error && <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11.5px] text-red-300">{error}</p>}

        <button
          onClick={() => void run()}
          disabled={busy || !loaded || (loaded?.kind === 'image' && !pixels && !engineMode)}
          className="btn-green mt-4 w-full"
        >
          {busy ? (
            <>
              <Loader2 size={14} className="animate-spin" /> {engineMode ? 'Cleaning through Java engine…' : 'Re-encoding through Canvas…'}
            </>
          ) : (
            <>
              <Eraser size={14} /> [ {engineMode ? 'Clean with Java Engine' : 'Sanitize & Save to Vault'} ]
            </>
          )}
        </button>

        {out && (
          <div className="mt-4 rounded-xl border border-brand/35 bg-black/25 p-4">
            <div className="flex items-center justify-between">
              <p className="flex items-center gap-1.5 text-[12.5px] font-semibold text-emerald-300">
                <ShieldCheck size={13} /> Clean object ready — {out.name}
              </p>
              <button onClick={() => downloadBlob(out.blob, out.name)} className="btn-green !px-3 !py-1.5 !text-[11px]">
                Download
              </button>
            </div>
            <p className="mt-1.5 break-all font-mono text-[10px] text-slate-500">SHA-256 {out.hash}</p>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Tags after</p>
                <p className="mt-0.5 flex items-center justify-center gap-1 font-mono text-[13px] font-semibold text-emerald-400">
                  {out.engineReport ? out.engineReport.exifTagsRemoved : out.after ? out.after.tags.length : '—'}{' '}
                  {out.engineReport ? 'removed' : out.after && out.after.tags.length === 0 ? <Check size={11} /> : null}
                </p>
              </div>
              <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">LSBs re-drawn</p>
                <p className="mt-0.5 font-mono text-[13px] font-semibold text-slate-200">{out.changed.toLocaleString()}</p>
              </div>
              <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">PSNR vs original</p>
                <p className="mt-0.5 font-mono text-[13px] font-semibold text-slate-200">{out.psnr == null ? '—' : Number.isFinite(out.psnr) ? `${out.psnr.toFixed(1)} dB` : '∞'}</p>
              </div>
            </div>
            {out.engineReport && (
              <p className="mt-2.5 rounded-md border border-sky-500/20 bg-sky-500/5 px-2.5 py-2 text-[10.5px] leading-relaxed text-sky-200">
                Engine report: {out.engineReport.medium} · {fmtBytes(out.engineReport.originalBytes)} → {fmtBytes(out.engineReport.cleanedBytes)} · {out.engineReport.lsbBitsReRandomized.toLocaleString()} slots re-randomized · {out.engineReport.changedBits.toLocaleString()} bits changed.
              </p>
            )}
            <p className="mt-2.5 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
              <X size={11} className="mt-0.5 shrink-0 text-red-400" />
              Pre-sanitize fingerprint was {loaded?.hash.slice(0, 18)}… — publish only the clean output. The original stays in RAM
              until you lock the vault.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
