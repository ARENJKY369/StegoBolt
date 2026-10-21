'use client';

/**
 * Forensic Scan — statistical steganalysis. Chi-square pair attack, LSB
 * balance, entropy, run anomaly + SBV2 signature detection feed a Threat
 * Assessment Score; histogram & LSB-plane canvases visualize anomalies.
 */

import { AlertTriangle, Gauge, Loader2, Radar, ScanSearch } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  analyzeLsbPlane,
  assessEngineScan,
  inspectSbv2Container,
  renderLsbPlane,
  threatAssessment,
  type LsbStats,
  type Sbv2Inspection,
  type ThreatConfidence,
  type ThreatVerdict,
} from '@/lib/analysis';
import { fmtBytes, fmtInt, fmtSci } from '@/lib/format';
import { capacityBits } from '@/lib/lsbcore';
import { scan as engineScan, setEngineBase, type ScanReport } from '@/lib/engineApi';
import { CARRIER_ACCEPT, localEngineRequired } from '@/lib/mediums';
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

const CONFIDENCE_COLOR: Record<ThreatConfidence, string> = {
  CONFIRMED: '#ef4444',
  SUSPICIOUS: '#f97316',
  INCONCLUSIVE: '#eab308',
  CLEAN: '#22c55e',
};

function ConfidenceChip({ confidence }: { confidence: ThreatConfidence }) {
  const color = CONFIDENCE_COLOR[confidence];
  return (
    <span
      className="rounded-md px-1.5 py-0.5 text-[9px] font-bold tracking-[0.12em]"
      style={{ color, backgroundColor: `${color}12`, boxShadow: `inset 0 0 0 1px ${color}44` }}
    >
      {confidence}
    </span>
  );
}

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

function EngineScanPanel({ report }: { report: ScanReport }) {
  const score = Math.max(0, Math.min(100, report.threatScore));
  const verdict = assessEngineScan(report);
  const tone = score >= 75 ? 'text-red-300' : score >= 50 ? 'text-orange-300' : score >= 25 ? 'text-amber-300' : 'text-emerald-300';
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-sky-500/25 bg-sky-500/5 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-sky-300">Java engine report</p>
            <p className="mt-1 text-[12px] text-slate-400">{report.medium} · {fmtBytes(report.carrierBytes)} inspected in RAM</p>
          </div>
          <p className={`font-mono text-2xl font-bold ${tone}`}>{score}<span className="text-xs text-slate-500">/100</span></p>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span
            className="rounded-md px-2 py-0.5 text-[10px] font-extrabold tracking-widest"
            style={{ color: LEVEL_COLOR[verdict.level], backgroundColor: `${LEVEL_COLOR[verdict.level]}1f`, boxShadow: `inset 0 0 0 1px ${LEVEL_COLOR[verdict.level]}55` }}
          >
            {verdict.level}
          </span>
          <ConfidenceChip confidence={verdict.confidence} />
          <span className="text-[10px] text-slate-500">{report.sampleBased === false ? 'structural evidence only' : 'sample-stream statistics'}</span>
        </div>
        <p className="mt-2 text-[12px] leading-relaxed text-slate-300">{verdict.summary}</p>
        <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">{verdict.basis}</p>
      </div>
      <div className="grid grid-cols-2 gap-2 text-center sm:grid-cols-4">
        <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
          <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Pair equalisation p</p>
          <p className="mt-1 font-mono text-[12px] text-slate-200">{report.sampleBased === false ? 'n/a' : report.chiSquareProbability.toExponential(2)}</p>
        </div>
        <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
          <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">SPA rate est.</p>
          <p className="mt-1 font-mono text-[12px] text-slate-200">{report.sampleBased === false ? 'n/a' : report.spaEmbeddingRatio.toFixed(3)}</p>
        </div>
        <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
          <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">LSB ones</p>
          <p className="mt-1 font-mono text-[12px] text-slate-200">{report.sampleBased === false ? 'n/a' : report.lsbOnesRatio.toFixed(3)}</p>
        </div>
        <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
          <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Container</p>
          <p className={`mt-1 font-mono text-[12px] ${report.containerSignatureFound ? 'text-red-300' : 'text-emerald-300'}`}>
            {report.containerSignatureFound ? 'confirmed' : 'not found'}
          </p>
        </div>
      </div>
      <div className="rounded-lg border border-hair bg-panel2/40 p-3">
        <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">Engine indicators</p>
        <ul className="space-y-1.5 text-[11px] leading-relaxed text-slate-300">
          {(report.indicators.length ? report.indicators : ['No indicators returned by the engine.']).map((indicator) => (
            <li key={indicator} className="flex gap-2"><span className="text-sky-400">•</span><span>{indicator}</span></li>
          ))}
        </ul>
      </div>
      {report.exifTags && report.exifTags.length > 0 && (
        <p className="text-[10.5px] text-slate-500">Image metadata tags found: {report.exifTags.length}. Use Clean to remove them.</p>
      )}
    </div>
  );
}

export function ScanTab() {
  const vault = useVault();
  const { loaded, pixels, loading, error, setError, load, clear } = useStegoFile();
  const [busy, setBusy] = useState(false);
  const [stats, setStats] = useState<LsbStats | null>(null);
  const [verdict, setVerdict] = useState<ThreatVerdict | null>(null);
  const [plane, setPlane] = useState<{ arr: Uint8ClampedArray<ArrayBuffer>; w: number; h: number } | null>(null);
  const [signature, setSignature] = useState<Sbv2Inspection | null>(null);
  const [engineReport, setEngineReport] = useState<ScanReport | null>(null);
  // Engine reports carry their own calibrated verdict; fall back locally for
  // older engines that omit the level/summary fields.
  const engineVerdict = engineReport ? assessEngineScan(engineReport) : null;
  const shownVerdict = verdict ?? engineVerdict;

  const run = useCallback(async () => {
    const engineMode = vault.settings.engineMode === 'engine';
    if (!loaded) {
      setError('Choose a supported carrier file first.');
      return;
    }
    if (!engineMode && loaded.kind !== 'image') {
      setError(localEngineRequired(loaded.kind, 'scanning'));
      return;
    }
    if (!engineMode && !pixels) {
      setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
      return;
    }
    const imagePixels = pixels;
    setBusy(true);
    setError(null);
    try {
      // Engine mode is authoritative for every carrier, including images.
      if (engineMode) {
        setEngineBase(vault.settings.engineUrl);
        const report = await engineScan(loaded.file);
        setEngineReport(report);
        setStats(null);
        setVerdict(null);
        setPlane(null);
        setSignature(null);
        vault.setArtifacts({
          coverName: loaded.name,
          coverInfo: `Engine scan of ${loaded.name} · threat ${report.threatScore}/100`,
        });
        void addRecord({
          ts: Date.now(),
          op: 'Scan',
          coverName: loaded.name,
          size: loaded.size,
          dims: loaded.width && loaded.height ? `${loaded.width}×${loaded.height}` : '—',
          backup: 'No local download',
          hash: loaded.hash,
          meta: {
            Via: 'Java engine',
            Medium: report.medium,
            'Threat score': `${report.threatScore}/100`,
            'Chi-square p': fmtSci(report.chiSquareProbability),
          },
        }).then(() => vault.refreshStorage());
        vault.log(`Java engine scan of ${loaded.name}: threat ${report.threatScore}/100`, report.threatScore < 25 ? 'ok' : 'warn');
        return;
      }

      if (!imagePixels) {
        setError('The image could not be decoded in this browser. Try a smaller, valid image or switch to Java engine mode.');
        return;
      }
      // let the spinner paint first
      await new Promise((r) => setTimeout(r, 30));
      const s = analyzeLsbPlane(imagePixels.data, imagePixels.width, imagePixels.height);
      const container = inspectSbv2Container(imagePixels.data);
      const v = threatAssessment(s, container);
      const planeArr = renderLsbPlane(imagePixels.data, imagePixels.width, imagePixels.height);
      setStats(s);
      setVerdict(v);
      setSignature(container);
      setPlane({ arr: planeArr, w: imagePixels.width, h: imagePixels.height });
      vault.setArtifacts({
        coverBytes: imagePixels.data,
        coverName: loaded.name,
        coverInfo: `Scanned carrier ${loaded.name} · threat ${v.score}/100 (${v.level})`,
      });
      void addRecord({
        ts: Date.now(),
        op: 'Scan',
        coverName: loaded.name,
        size: loaded.size,
        dims: `${imagePixels.width}×${imagePixels.height}`,
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
          accept={CARRIER_ACCEPT}
          hint="Scan images locally, or use Java engine mode for WAV/FLAC, video, documents, text/code and PCAP"
          filled={!!loaded}
          onFile={(f) => {
            setStats(null);
            setVerdict(null);
            setEngineReport(null);
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
                setEngineReport(null);
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

        <button
          onClick={() => void run()}
          disabled={busy || !loaded || (loaded?.kind === 'image' && !pixels && vault.settings.engineMode !== 'engine')}
          className="btn-green w-full"
        >
          {busy ? (
            <>
              <Loader2 size={14} className="animate-spin" /> {vault.settings.engineMode === 'engine' ? 'Asking Java engine for forensic report…' : 'Running chi-square + entropy suite…'}
            </>
          ) : (
            <>
              <Radar size={14} /> [ {vault.settings.engineMode === 'engine' ? 'Run Engine Scan' : 'Run Forensic Scan'} ]
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
          {shownVerdict && (
            <span className="flex items-center gap-1.5">
              <ConfidenceChip confidence={shownVerdict.confidence} />
              <span
                className="rounded-md px-2 py-0.5 text-[10px] font-extrabold tracking-widest"
                style={{ color: LEVEL_COLOR[shownVerdict.level], backgroundColor: `${LEVEL_COLOR[shownVerdict.level]}1f`, boxShadow: `inset 0 0 0 1px ${LEVEL_COLOR[shownVerdict.level]}55` }}
              >
                {shownVerdict.level}
              </span>
            </span>
          )}
        </h3>

        {engineReport ? (
          <EngineScanPanel report={engineReport} />
        ) : !verdict ? (
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
              <div className="min-w-0 flex-1">
                <p className="flex items-start gap-2 text-[12px] leading-relaxed text-slate-300">
                  {verdict.level !== 'LOW' && <AlertTriangle size={13} className="mt-0.5 shrink-0" style={{ color: LEVEL_COLOR[verdict.level] }} />}
                  <span>
                    {verdict.summary}
                    {signature?.confirmed && (
                      <span className="mt-1 block font-mono text-[10.5px] text-red-400">
                        ⚑ Valid SBV2 container framing in the first bits — this object was produced by the Hide pipeline.
                      </span>
                    )}
                  </span>
                </p>
                <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">{verdict.basis}</p>
              </div>
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
                  {sig.label.startsWith('Sample-pair') && <InfoTip text={TIPS.SPA} width={300} />}
                  {sig.label.startsWith('Value-pair') && <InfoTip text={TIPS.CHI} width={320} />}
                </div>
              ))}
            </div>

            {stats && (
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-hair bg-black/30 p-2.5">
                  <p className="mb-1.5 flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    <span>Value-pair histogram <span className="normal-case text-slate-600">(flat = equalised pairs)</span></span>
                    <span className="font-mono text-slate-400">p={fmtSci(stats.pValue)} <InfoTip text={TIPS.CHI} width={320} /></span>
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
                    <p className="mt-1 font-mono text-[13px] font-semibold text-slate-200">{stats.onesRatio.toFixed(3)}</p>
                  </div>
                  <div className="rounded-lg border border-hair bg-panel2/50 px-2 py-2">
                    <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Stream entropy</p>
                    <p className="mt-1 font-mono text-[13px] font-semibold text-slate-200">{stats.entropy.toFixed(3)}</p>
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
