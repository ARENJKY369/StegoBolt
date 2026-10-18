'use client';

/**
 * Forensic Scan — statistical steganalysis. Chi-square pair attack, LSB
 * balance, entropy, run anomaly + SBV2 signature detection feed a Threat
 * Assessment Score; histogram & LSB-plane canvases visualize anomalies.
 */

import { AlertTriangle, Gauge, Loader2, Radar, ScanSearch } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { analyzeLsbPlane, detectSbv2Magic, renderLsbPlane, threatAssessment, type LsbStats, type ThreatVerdict } from '@/lib/analysis';
import { fmtBytes, fmtInt, fmtSci } from '@/lib/format';
import { capacityBits } from '@/lib/lsbcore';
import { addRecord } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { FileDropzone } from '@/components/ui/Dropzone';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { FileChip } from './FileChip';
import { useStegoFile } from './useStegoFile';

const LEVEL_COLOR: Record<ThreatVerdict['level'], string> = {
  LOW: '#22c55e',
  ELEVATED: '#eab308',
  HIGH: '#f97316',
  CRITICAL: '#ef4444',
};

function GaugeArc({ score, color }: { score: number; color: string }) {
  const r = 54;
  const c = Math.PI * r; // half circle
  const filled = (score / 100) * c;
  return (
    <svg width="148" height="86" viewBox="0 0 148 86" className="overflow-visible">
      <path d={`M 14 80 A ${r} ${r} 0 0 1 134 80`} fill="none" stroke="#1c2532" strokeWidth="10" strokeLinecap="round" />
      <path
        d={`M 14 80 A ${r} ${r} 0 0 1 134 80`}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${c - filled}`}
        style={{ transition: 'stroke-dasharray 0.5s ease' }}
      />
      <text x="74" y="66" textAnchor="middle" fontSize="26" fontWeight="800" fill="#f1f5f9" fontFamily="ui-monospace, monospace">
        {score}
      </text>
      <text x="74" y="82" textAnchor="middle" fontSize="9" fill="#64748b" fontWeight="700" letterSpacing="2">
        THREAT SCORE
      </text>
    </svg>
  );
}

function HistogramCanvas({ data }: { data: number[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const ctx = cv.getContext('2d');
    if (!ctx) return;
    const w = cv.width;
    const h = cv.height;
    ctx.clearRect(0, 0, w, h);
    const n = data.length;
    const bw = w / n;
    for (let i = 0; i < n; i++) {
      const v = data[i];
      const bh = Math.max(1, v * (h - 4));
      ctx.fillStyle = v > 0.55 ? 'rgba(239,68,68,0.95)' : v > 0.3 ? 'rgba(234,179,8,0.9)' : 'rgba(34,197,94,0.75)';
      ctx.fillRect(i * bw, h - bh, Math.max(1, bw - 0.6), bh);
    }
  }, [data]);
  return <canvas ref={ref} width={512} height={96} className="h-[96px] w-full rounded-md bg-black/40" />;
}

function LsbPlaneCanvas({ plane, width, height }: { plane: Uint8ClampedArray<ArrayBuffer>; width: number; height: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current;
    if (!cv) return;
    const ctx = cv.getContext('2d');
    if (!ctx) return;
    const off = document.createElement('canvas');
    off.width = width;
    off.height = height;
    off.getContext('2d')!.putImageData(new ImageData(plane, width, height), 0, 0);
    ctx.imageSmoothingEnabled = false;
    ctx.clearRect(0, 0, cv.width, cv.height);
    ctx.drawImage(off, 0, 0, cv.width, cv.height);
  }, [plane, width, height]);
  return <canvas ref={ref} width={336} height={189} className="h-[189px] w-[336px] rounded-md border border-hair bg-black" />;
}

export function ScanTab() {
  const vault = useVault();
  const { loaded, pixels, loading, error, setError, load, clear } = useStegoFile();
  const [busy, setBusy] = useState(false);
  const [stats, setStats] = useState<LsbStats | null>(null);
  const [verdict, setVerdict] = useState<ThreatVerdict | null>(null);
  const [plane, setPlane] = useState<{ arr: Uint8ClampedArray<ArrayBuffer>; w: number; h: number } | null>(null);
  const [signature, setSignature] = useState<boolean | null>(null);

  const run = useCallback(async () => {
    if (!loaded || !pixels) {
      setError('Load an image carrier to scan.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // let the spinner paint first
      await new Promise((r) => setTimeout(r, 30));
      const s = analyzeLsbPlane(pixels.data, pixels.width, pixels.height);
      const magic = detectSbv2Magic(pixels.data);
      const v = threatAssessment(s, magic);
      const planeArr = renderLsbPlane(pixels.data, pixels.width, pixels.height);
      setStats(s);
      setVerdict(v);
      setSignature(magic);
      setPlane({ arr: planeArr, w: pixels.width, h: pixels.height });
      vault.setArtifacts({
        coverBytes: pixels.data,
        coverName: loaded.name,
        coverInfo: `Scanned carrier ${loaded.name} · threat ${v.score}/100 (${v.level})`,
      });
      void addRecord({
        ts: Date.now(),
        op: 'Scan',
        coverName: loaded.name,
        size: loaded.size,
        dims: `${pixels.width}×${pixels.height}`,
        backup: 'Saved',
        hash: loaded.hash,
        meta: { 'Threat score': `${v.score}/100`, Verdict: v.level, 'Chi-square p': fmtSci(s.pValue) },
      }).then(() => vault.refreshStorage());
      vault.log(`Steganalysis of ${loaded.name}: ${v.level} (score ${v.score}/100) — recorded locally`, v.level === 'LOW' ? 'ok' : 'warn');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setBusy(false);
    }
  }, [loaded, pixels, setError, vault]);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
      <section className="card space-y-4 p-5">
        <h3 className="card-title">Evidence Carrier</h3>
        <FileDropzone
          accept="image/*"
          hint="Any raster image — analyze the suspicious file without revealing it to anyone"
          filled={!!loaded}
          onFile={(f) => {
            setStats(null);
            setVerdict(null);
            void load(f);
          }}
        >
          {loaded && (
            <FileChip
              loaded={loaded}
              accent="red"
              onRemove={() => {
                clear();
                setStats(null);
                setVerdict(null);
              }}
            />
          )}
        </FileDropzone>
        {loading && (
          <p className="flex items-center gap-1.5 text-[11px] text-slate-500">
            <Loader2 size={11} className="animate-spin" /> hashing &amp; rasterizing…
          </p>
        )}
        {error && <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11.5px] text-red-300">{error}</p>}

        <button onClick={() => void run()} disabled={busy || !pixels} className="btn-green w-full">
          {busy ? (
            <>
              <Loader2 size={14} className="animate-spin" /> Running chi-square + entropy suite…
            </>
          ) : (
            <>
              <Radar size={14} /> [ Run Forensic Scan ]
            </>
          )}
        </button>

        {stats && (
          <div className="rounded-lg border border-hair bg-panel2/40 p-3 font-mono text-[10.5px] leading-relaxed text-slate-400">
            <p>pixels analyzed · {fmtInt(stats.pixels)}</p>
            <p>embeddable bit slots · {fmtInt(stats.embeddable)}</p>
            <p>theoretical payload ceiling · {fmtBytes(Math.floor(stats.embeddable / 8) - 10)}</p>
            <p>
              channel LSB bias ·{' '}
              {stats.channelStats.map((c) => `${c.name}:${c.ratio.toFixed(3)}`).join('  ')}
            </p>
          </div>
        )}
        <p className="text-[10.5px] leading-relaxed text-slate-500">
          Detection suite: chi-square pair attack <InfoTip text={TIPS.CHI} width={320} />, LSB balance drift, 8-bit windowed entropy,
          long-run structure analysis and SBV2 container-signature search.
        </p>
      </section>

      <section className="card p-5">
        <h3 className="card-title flex items-center justify-between">
          Threat Assessment
          {verdict && (
            <span
              className="rounded-md px-2 py-0.5 text-[10px] font-extrabold tracking-widest"
              style={{ color: LEVEL_COLOR[verdict.level], backgroundColor: `${LEVEL_COLOR[verdict.level]}1f`, boxShadow: `inset 0 0 0 1px ${LEVEL_COLOR[verdict.level]}55` }}
            >
              {verdict.level}
            </span>
          )}
        </h3>

        {!verdict ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <ScanSearch size={22} className="text-slate-700" />
            <p className="text-[12px] text-slate-500">No scan yet</p>
            <p className="max-w-[320px] text-[10.5px] leading-relaxed text-slate-600">
              StegoBolt evaluates the LSB plane of whatever you drop in. Results never leave this tab — safe for seized or NDA media.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-5">
              <div className="shrink-0 rounded-xl border border-hair bg-black/30 px-3 pb-1 pt-3">
                <GaugeArc score={verdict.score} color={LEVEL_COLOR[verdict.level]} />
              </div>
              <p className="flex items-start gap-2 text-[12px] leading-relaxed text-slate-300">
                {verdict.level !== 'LOW' && <AlertTriangle size={13} className="mt-0.5 shrink-0" style={{ color: LEVEL_COLOR[verdict.level] }} />}
                {verdict.summary}
                {signature && <span className="mt-1 block font-mono text-[10.5px] text-red-400">⚑ StegoBolt SBV2 magic detected in the first bits — this object was produced by the Hide pipeline.</span>}
              </p>
              <Gauge size={15} className="ml-auto hidden shrink-0 text-slate-700 sm:block" />
            </div>

            <div className="space-y-2">
              {verdict.signals.map((sig) => (
                <div key={sig.label} className="flex items-center gap-3">
                  <span className="w-[150px] shrink-0 text-[10.5px] text-slate-500">
                    {sig.label}
                  </span>
                  <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel3">
                    <span
                      className="block h-full rounded-full transition-all duration-500"
                      style={{ width: `${Math.max(3, Math.min(100, sig.weight * 100))}%`, backgroundColor: sig.weight > 0.6 ? '#ef4444' : sig.weight > 0.3 ? '#eab308' : '#22c55e' }}
                    />
                  </span>
                  <span className="w-[130px] shrink-0 text-right font-mono text-[10.5px] text-slate-300">{sig.value}</span>
                  {sig.label === 'SBV2 container signature' && <InfoTip text={TIPS.THREAT} width={300} />}
                </div>
              ))}
            </div>

            {stats && (
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-hair bg-black/30 p-2.5">
                  <p className="mb-1.5 flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    <span>Value-pair histogram <span className="normal-case text-slate-600">(stairs = embedding)</span></span>
                    <span className="font-mono text-slate-400">p={fmtSci(stats.pValue)}</span>
                  </p>
                  <HistogramCanvas data={stats.histogram} />
                </div>
                {plane && (
                  <div className="rounded-lg border border-hair bg-black/30 p-2.5">
                    <p className="mb-1.5 flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                      <span>LSB plane heatmap <InfoTip text={TIPS.LSB} width={280} /></span>
                      <span className="font-mono normal-case text-slate-600">{plane.w}×{plane.h}</span>
                    </p>
                    <div className="flex justify-center overflow-hidden rounded">
                      <LsbPlaneCanvas plane={plane.arr} width={plane.w} height={plane.h} />
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="grid grid-cols-3 gap-2 text-center">
              {stats && (
                <>
                  <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                    <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">LSB ones ratio</p>
                    <p className={`mt-1 font-mono text-[13px] font-semibold ${Math.abs(stats.onesRatio - 0.5) > 0.08 ? 'text-red-400' : 'text-emerald-400'}`}>{stats.onesRatio.toFixed(3)}</p>
                  </div>
                  <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                    <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Stream entropy</p>
                    <p className={`mt-1 font-mono text-[13px] font-semibold ${stats.entropy < 0.97 ? 'text-amber-400' : 'text-emerald-400'}`}>{stats.entropy.toFixed(3)}</p>
                  </div>
                  <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                    <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Carrier bits</p>
                    <p className="mt-1 font-mono text-[13px] font-semibold text-slate-200">{stats ? fmtInt(capacityBits(stats.pixels * 4)) : '—'}</p>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
