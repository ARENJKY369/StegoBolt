'use client';

/**
 * Extract (Decode): reads the SBV2 bitstream from the LSB plane in a Web
 * Worker, re-derives the AES key with PBKDF2 and authenticates the GCM tag —
 * a wrong password or a single tampered pixel fails closed.
 */

import { CheckCircle2, Copy, Download, Eye, EyeOff, Loader2, ScanSearch, ShieldAlert, Unlock } from 'lucide-react';
import { useState } from 'react';
import { CIPHER, CIPHER_LABELS, openPayload } from '@/lib/crypto';
import { measureQuality } from '@/lib/analysis';
import { fmtBytes } from '@/lib/format';
import { LsbError } from '@/lib/lsbcore';
import { workerExtract } from '@/lib/worker';
import { extract as engineExtract, setEngineBase } from '@/lib/engineApi';
import { CARRIER_ACCEPT, localEngineRequired } from '@/lib/mediums';
import { addRecord } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { FileDropzone } from '@/components/ui/Dropzone';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { FileChip } from './FileChip';
import { useStegoFile } from './useStegoFile';
import { downloadBlob } from './HistoryPanel';

interface Extracted {
  text: string;
  bytes: Uint8Array;
  cipher: number;
  sealedLen: number;
  bitsUsed: number;
  viaEngine?: boolean;
  medium?: string;
  sha256?: string | null;
}

const FRIENDLY: Record<string, string> = {
  NOT_STEGO: 'No SBV2 container found in this file’s LSB plane. Either it is a clean cover — or it was lossy-recompressed after embedding.',
  TOO_SMALL: 'The image is too small to hold even a container header.',
  BAD_LENGTH: 'The container header is corrupt or spoofed (invalid payload length).',
  BAD_FLAGS: 'The container declares an unknown cipher id — corrupt or spoofed header.',
  TRUNCATED: 'The carrier was resized/re-encoded after embedding — the hidden stream is cut off.',
  CAPACITY_EXCEEDED: 'Payload exceeds carrier capacity.',
  IMAGE_TOO_LARGE: 'Image exceeds the 64 megapixel processing ceiling.',
  WORKER_TIMEOUT: 'The LSB worker timed out. Try a smaller file.',
  UNKNOWN_JOB: 'Internal pipeline error.',
};

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function ExtractTab() {
  const vault = useVault();
  const { loaded, pixels, loading, error, setError, load, clear } = useStegoFile();
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Extracted | null>(null);
  const [copied, setCopied] = useState(false);

  const run = async () => {
    const engineMode = vault.settings.engineMode === 'engine';
    if (!loaded) {
      setError('Choose a supported stego carrier first.');
      return;
    }
    if (!engineMode && loaded.kind !== 'image') {
      setError(localEngineRequired(loaded.kind, 'extraction'));
      return;
    }
    if (!engineMode && !pixels) {
      setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      if (engineMode && loaded) {
        setEngineBase(vault.settings.engineUrl);
        const report = await engineExtract(loaded.file, password);
        if (!report.found) {
          setError('No StegoBolt container found in this file — either it is a clean cover, or it was recompressed after embedding.');
          vault.log(`Extract via Java engine — no container in ${loaded.name}`, 'warn');
          return;
        }
        const plain = report.payloadBase64 ? b64ToBytes(report.payloadBase64) : new TextEncoder().encode(report.payloadText ?? '');
        const text = report.payloadText ?? new TextDecoder().decode(plain);
        setResult({
          text,
          bytes: plain,
          cipher: CIPHER.AES_256_GCM,
          sealedLen: report.payloadBytes ?? plain.length,
          bitsUsed: (report.payloadBytes ?? plain.length) * 8,
          viaEngine: true,
          medium: report.medium,
          sha256: report.sha256,
        });
        vault.setArtifacts({
          coverName: loaded.name,
          coverInfo: `Stego carrier ${loaded.name} · ${fmtBytes(loaded.size)} · processed by the Java engine`,
          payloadBytes: plain,
          payloadInfo: `Payload recovered by the Java engine — ${fmtBytes(plain.length)} of plaintext`,
        });
        void addRecord({
          ts: Date.now(),
          op: 'Extract',
          coverName: loaded.name,
          size: loaded.size,
          dims: '—',
          backup: 'No local download',
          hash: loaded.hash,
          payloadPreview: `••• engine-extracted payload (${fmtBytes(plain.length)}) •••`,
          meta: { Via: 'Java engine', 'Payload size': fmtBytes(plain.length) },
        }).then(() => vault.refreshStorage());
        vault.log(`Payload recovered via Java engine from ${loaded.name} — ${fmtBytes(plain.length)} of plaintext`, 'ok');
        return;
      }
      if (!pixels) {
        setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
        return;
      }
      const out = await workerExtract(pixels.data);
      const sealed = new Uint8Array(out.payload);
      let plain: Uint8Array;
      try {
        plain = await openPayload(sealed, out.flags, password);
      } catch {
        throw new Error('GCM authentication failed — wrong passphrase, or the carrier was modified (tamper detection).');
      }
      const text = new TextDecoder().decode(plain);
      setResult({ text, bytes: plain, cipher: out.flags, sealedLen: sealed.length, bitsUsed: out.bitsUsed });
      vault.setArtifacts({
        coverBytes: pixels.data,
        coverName: loaded.name,
        coverInfo: `Stego carrier ${loaded.name} (${pixels.width}×${pixels.height})`,
        payloadBytes: sealed,
        payloadInfo: 'Sealed container read back from the LSB plane (salt | iv | ciphertext||tag)',
      });
      void addRecord({
        ts: Date.now(),
        op: 'Extract',
        coverName: loaded.name,
        size: loaded.size,
        dims: `${pixels.width}×${pixels.height}`,
        backup: 'No local download',
        hash: loaded.hash,
        payloadPreview: out.flags === CIPHER.RAW ? text.slice(0, 240) : `••• decrypted ${CIPHER_LABELS[out.flags]} payload (${fmtBytes(plain.length)}) •••`,
        meta: { Cipher: CIPHER_LABELS[out.flags] ?? String(out.flags), 'Container bits': out.bitsUsed.toLocaleString(), 'Payload size': fmtBytes(plain.length) },
      }).then(() => vault.refreshStorage());
      vault.log(`Payload recovered from ${loaded.name} — ${fmtBytes(plain.length)} of ${CIPHER_LABELS[out.flags] ?? 'raw'} plaintext`, 'ok');
    } catch (e) {
      if (e instanceof LsbError) setError(FRIENDLY[e.code] ?? `${e.code}${e.detail ? ` — ${e.detail}` : ''}`);
      else setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
      <section className="card p-5">
        <h3 className="card-title mb-4">Stego Carrier Input</h3>
        <FileDropzone
          accept={CARRIER_ACCEPT}
          hint="PNG/BMP/WebP/GIF/TIFF/JPEG · WAV/FLAC · MP4/MKV/AVI · PDF/DOCX · text/code · PCAP/PCAPNG"
          filled={!!loaded}
          onFile={(f) => {
            setResult(null);
            void load(f);
          }}
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
            <Loader2 size={11} className="animate-spin" /> decoding raster &amp; hashing locally…
          </p>
        )}

        <div className="mt-4">
          <p className="label flex items-center">
            Vault Passphrase
            <InfoTip text="Used only to run PBKDF2 and decrypt — it is never stored or sent. Leave empty for raw (unencrypted) containers." width={290} side="bottom" />
          </p>
          <div className="relative">
            <input
              type={showPass ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="password that sealed the payload…"
              className="input pr-9"
              autoComplete="off"
              onKeyDown={(e) => e.key === 'Enter' && void run()}
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

        {error && (
          <p className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11.5px] leading-relaxed text-red-300">
            <ShieldAlert size={13} className="mt-0.5 shrink-0" /> {error}
          </p>
        )}
      </section>

      <section className="card flex flex-col p-5">
        <h3 className="card-title mb-3">Recovery Console</h3>
        <p className="text-[11.5px] leading-relaxed text-slate-500">
          {vault.settings.engineMode === 'engine'
            ? 'The Java engine identifies the carrier, opens the sealed SBV2-J container and returns only the recovered payload report.'
            : 'StegoBolt parses the SBV2 magic and length prefix from an image LSB plane, then authenticates the GCM tag before showing any plaintext.'}{' '}
          <InfoTip text={TIPS.AES} width={300} />
        </p>
        <button
          onClick={() => void run()}
          disabled={busy || !loaded || (loaded?.kind === 'image' && !pixels && vault.settings.engineMode !== 'engine')}
          className="btn-green mt-4 w-full"
        >
          {busy ? (
            <>
              <Loader2 size={14} className="animate-spin" /> Sweeping LSB plane…
            </>
          ) : (
            <>
              <ScanSearch size={14} /> [ Extract Payload ]
            </>
          )}
        </button>

        {result ? (
          <div className="mt-4 flex min-h-0 flex-1 flex-col rounded-xl border border-brand/35 bg-black/25 p-3.5">
            <p className="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-300">
              <CheckCircle2 size={12} /> Payload recovered — {result.viaEngine ? 'Java engine · AES-256-GCM' : `${CIPHER_LABELS[result.cipher] ?? 'raw'} · integrity verified`}
            </p>
            {result.viaEngine && (
              <p className="mt-1 font-mono text-[10px] text-sky-300">
                {result.medium} carrier · plaintext {fmtBytes(result.bytes.length)}{result.sha256 ? ` · SHA-256 ${result.sha256.slice(0, 16)}…` : ''}
              </p>
            )}
            <pre className="mt-2 min-h-[110px] flex-1 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-hair bg-panel2/60 p-3 font-mono text-[12px] leading-relaxed text-slate-100">
              {result.text || '(empty payload)'}
            </pre>
            <div className="mt-2.5 flex items-center justify-between text-[10.5px] text-slate-500">
              <span>
                {result.viaEngine
                  ? `${fmtBytes(result.bytes.length)} plaintext recovered · Java engine report`
                  : `${fmtBytes(result.bytes.length)} · ${result.bitsUsed.toLocaleString()} bits swept · salt+iv ${Math.max(0, result.sealedLen - result.bytes.length)} B`}
              </span>
              <span className="flex gap-1.5">
                <button
                  onClick={() => {
                    navigator.clipboard?.writeText(result.text).then(() => {
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1400);
                    }, () => undefined);
                  }}
                  className="btn-ghost !px-2 !py-1 text-[11px]"
                >
                  {copied ? <CheckCircle2 size={11} className="text-emerald-400" /> : <Copy size={11} />} Copy
                </button>
                <button
                  onClick={() => downloadBlob(new Blob([new Uint8Array(result.bytes)], { type: 'text/plain' }), 'recovered-payload.txt')}
                  className="btn-ghost !px-2 !py-1 text-[11px]"
                >
                  <Download size={11} /> Save .txt
                </button>
              </span>
            </div>
            <p className="mt-2 text-[9.5px] italic text-slate-600">
              Recovered text lives in RAM only — it is zeroized the moment the vault locks or the tab closes.
            </p>
          </div>
        ) : (
          <div className="mt-4 flex flex-1 flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-hair2 px-4 py-8 text-center">
            <Unlock size={18} className="text-slate-600" />
            <p className="text-[12px] text-slate-500">No payload recovered yet</p>
            <p className="text-[10.5px] text-slate-600">Load a carrier, enter the passphrase, hit Extract.</p>
          </div>
        )}
      </section>
    </div>
  );
}
