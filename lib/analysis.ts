'use client';

/**
 * Client-side steganalysis: LSB-plane statistics, chi-square pair attack,
 * entropy estimate and PSNR / SSIM-lite visual metrics. Pure math over the
 * in-memory pixel buffer — nothing is transmitted.
 */

export interface LsbStats {
  pixels: number;
  embeddable: number;
  ones: number;
  onesRatio: number; // ~0.5 is natural; strong drift is suspicious
  runAnomaly: number; // long identical-bit runs (structured payloads)
  chiSquare: number; // 0..1 normalized evidence for sequential LSB embedding
  chiSquareRaw: number;
  degreesOfFreedom: number;
  pValue: number;
  lsbmRateEstimate: number; // estimated LSB-matching embedding rate 0..1
  entropy: number; // bits per embedded bit (windowed)
  channelStats: { name: string; ratio: number }[];
  histogram: number[]; // 128 pair-imbalance bars for the UI overlay
}

const CHAN = 3;

export function analyzeLsbPlane(data: Uint8Array, width: number, height: number): LsbStats {
  const pixels = Math.min(width * height, Math.floor(data.length / 4));
  let ones = 0;
  let runsLong = 0;
  let runsTotal = 0;
  let curRun = 0;
  let prevBit = -1;

  const chanOnes = new Float64Array(CHAN);
  const chanTot = new Float64Array(CHAN);

  for (let p = 0; p < pixels; p++) {
    const base = p * 4;
    for (let c = 0; c < CHAN; c++) {
      const v = data[base + c];
      const bit = v & 1;
      chanOnes[c] += bit;
      chanTot[c] += 1;
      ones += bit;
      if (bit === prevBit) {
        curRun++;
      } else {
        if (curRun >= 5) runsLong++;
        if (curRun > 0) runsTotal++;
        curRun = 1;
        prevBit = bit;
      }
    }
  }
  if (curRun >= 5) runsLong++;
  if (curRun > 0) runsTotal++;

  const embeddable = pixels * CHAN;
  const onesRatio = embeddable ? ones / embeddable : 0;
  const runAnomaly = runsTotal ? runsLong / runsTotal : 0;

  // Chi-square pair attack: for every value pair (2i, 2i+1) natural images
  // keep the two halves balanced; embedding flips that balance.
  const even = new Float64Array(128);
  const odd = new Float64Array(128);
  for (let p = 0; p < pixels; p++) {
    const base = p * 4;
    for (let c = 0; c < CHAN; c++) {
      const v = data[base + c];
      const bucket = (v >> 1) & 0x7f;
      if (v & 1) odd[bucket] += 1;
      else even[bucket] += 1;
    }
  }
  let chiSq = 0;
  let dfReal = 0;
  for (let b = 0; b < 128; b++) {
    const n = even[b] + odd[b];
    if (n < 20) continue;
    const e = n / 2;
    const d = even[b] - odd[b];
    chiSq += (d * d) / n; // Σ (o−e)²/e collapsed over the pair
    dfReal += 1;
  }
  const pValue = chiSquareTail(chiSq, Math.max(1, dfReal));
  const chiSquare = Math.max(0, Math.min(1, 1 - pValue));
  // Wilson–Petersen-style rate proxy: statistic per pair decays linearly with rate
  const lsbmRateEstimate = Math.max(0, Math.min(1, 1 - chiSq / Math.max(1, dfReal)));

  // windowed entropy over the LSB stream
  let entropy = 1;
  {
    const win = 4096;
    const samples = Math.min(24, Math.max(1, Math.floor(embeddable / win)));
    let acc = 0;
    for (let s = 0; s < samples; s++) {
      let o = 0;
      const start = Math.floor((s / samples) * Math.max(0, embeddable - win));
      for (let k = 0; k < win; k++) {
        const n = start + k;
        const p = (n / CHAN) | 0;
        const c = n - p * CHAN;
        o += data[p * 4 + c] & 1;
      }
      const p1 = o / win;
      const p0 = 1 - p1;
      acc += -(p0 * Math.log2(p0 || 1e-12) + p1 * Math.log2(p1 || 1e-12));
    }
    entropy = samples ? acc / samples : 1;
  }

  const channelStats: { name: string; ratio: number }[] = [];
  const names = ['R', 'G', 'B'];
  for (let c = 0; c < CHAN; c++) {
    channelStats.push({ name: names[c], ratio: chanTot[c] ? chanOnes[c] / chanTot[c] : 0 });
  }

  const histogram: number[] = [];
  let maxImb = 1;
  for (let b = 0; b < 128; b++) {
    const imbalance = Math.abs(even[b] - odd[b]);
    histogram.push(imbalance);
    if (imbalance > maxImb) maxImb = imbalance;
  }
  for (let b = 0; b < 128; b++) histogram[b] = histogram[b] / maxImb;

  return {
    pixels,
    embeddable,
    ones,
    onesRatio,
    runAnomaly,
    chiSquare,
    chiSquareRaw: chiSq,
    degreesOfFreedom: dfReal,
    pValue,
    lsbmRateEstimate,
    entropy,
    channelStats,
    histogram,
  };
}

/** Regularized upper incomplete gamma Q(k/2, x/2) — chi-square survival function. */
function chiSquareTail(x: number, k: number): number {
  if (x <= 0) return 1;
  const halfK = k / 2;
  const lx = Math.log(x);
  const lg = lnGamma(halfK);
  if (x < halfK + 1) {
    let sum = 1 / halfK;
    let term = sum;
    for (let n = 1; n < 300; n++) {
      term *= x / (halfK + n);
      sum += term;
      if (Math.abs(term) < Math.abs(sum) * 1e-12) break;
    }
    const lower = sum * Math.exp(-x + halfK * lx - lg);
    return Math.max(0, Math.min(1, 1 - lower));
  }
  let b = x + 1 - halfK;
  let c = 1e300;
  let d = 1 / b;
  let h = d;
  for (let i = 1; i < 300; i++) {
    const an = -i * (i - halfK);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c;
    if (Math.abs(c) < 1e-300) c = 1e-300;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < 1e-12) break;
  }
  return Math.max(0, Math.min(1, Math.exp(-x + halfK * lx - lg) * h));
}

function lnGamma(z: number): number {
  const g = [
    76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155,
    0.1208650973866179e-2, -0.5395239384953e-5,
  ];
  let y = z;
  const tmp = z + 5.5 - (z + 0.5) * Math.log(z + 5.5);
  let ser = 1.000000000190015;
  for (let j = 0; j < 6; j++) {
    y += 1;
    ser += g[j] / y;
  }
  return -tmp + Math.log((2.5066282746310005 * ser) / z);
}

/** Scan the LSB bitstream for the StegoBolt SBV2 magic (framed in the first bytes). */
export function detectSbv2Magic(data: Uint8Array): boolean {
  const want = [0x53, 0x42, 0x56, 0x32];
  let byteIdx = 0;
  let bitBuf = 0;
  const pixelCount = Math.floor(data.length / 4);
  outer: for (let p = 0; p < pixelCount && byteIdx < 4; p++) {
    const base = p * 4;
    for (let c = 0; c < CHAN; c++) {
      bitBuf = (bitBuf << 1) | (data[base + c] & 1);
      if ((p * CHAN + c) % 8 === 7) {
        if (bitBuf !== want[byteIdx]) return false;
        byteIdx++;
        bitBuf = 0;
        if (byteIdx >= 4) break outer;
      }
    }
  }
  return byteIdx >= 4;
}

export interface StegoQuality {
  psnrDb: number; // Infinity when untouched
  mse: number;
  ssimApprox: number; // 0..1 (1 = identical)
  bitsChanged: number;
  capacityUsedPct: number;
}

export function measureQuality(
  original: Uint8Array,
  stego: Uint8Array,
  usedBits: number,
  totalBits: number
): StegoQuality {
  const n = Math.min(original.length, stego.length);
  let sq = 0;
  let counted = 0;
  let changed = 0;
  for (let i = 0; i < n; i++) {
    if ((i & 3) === 3) continue; // skip alpha
    const a = original[i];
    const b = stego[i];
    counted++;
    if (a !== b) changed++;
    const d = a - b;
    sq += d * d;
  }
  const mse = counted ? sq / counted : 0;
  const psnrDb = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

  // SSIM-lite: block luminance similarity (mean/variance/covariance over 64 samples)
  const step = Math.max(1, Math.floor(n / 4 / 65536)) * 4; // cap total work
  const c1 = 6.5025;
  const c2 = 58.5225;
  let s1 = 0, s2 = 0, q1 = 0, q2 = 0, q12 = 0, bn = 0;
  let simSum = 0;
  let simCount = 0;
  for (let i = 0; i + 2 < n; i += step) {
    const l1 = original[i] * 0.299 + original[i + 1] * 0.587 + original[i + 2] * 0.114;
    const l2 = stego[i] * 0.299 + stego[i + 1] * 0.587 + stego[i + 2] * 0.114;
    s1 += l1; s2 += l2; q1 += l1 * l1; q2 += l2 * l2; q12 += l1 * l2; bn++;
    if (bn >= 64) {
      const m1 = s1 / bn, m2 = s2 / bn;
      const v1 = Math.max(0, q1 / bn - m1 * m1);
      const v2 = Math.max(0, q2 / bn - m2 * m2);
      const v12 = q12 / bn - m1 * m2;
      simSum += ((2 * m1 * m2 + c1) * (2 * v12 + c2)) / ((m1 * m1 + m2 * m2 + c1) * (v1 + v2 + c2));
      simCount++;
      s1 = s2 = q1 = q2 = q12 = bn = 0;
    }
  }
  const ssimApprox = simCount ? simSum / simCount : 1;

  return {
    psnrDb,
    mse,
    ssimApprox: Number.isFinite(ssimApprox) ? Math.max(0, Math.min(1, ssimApprox)) : 1,
    bitsChanged: changed,
    capacityUsedPct: totalBits ? (usedBits / totalBits) * 100 : 0,
  };
}

export interface ThreatVerdict {
  score: number; // 0..100
  level: 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
  summary: string;
  signals: { label: string; value: string; weight: number }[];
}

export function threatAssessment(s: LsbStats, sbv2Found: boolean): ThreatVerdict {
  const balance = Math.abs(s.onesRatio - 0.5) * 2;
  const entropyRisk = Math.max(0, Math.min(1, (1 - s.entropy) * 2));
  const runRisk = Math.min(1, s.runAnomaly * 6);
  const magicHit = sbv2Found ? 1 : 0;
  const score = Math.round(
    100 *
      Math.min(
        1,
        0.34 * s.chiSquare + 0.18 * balance + 0.14 * entropyRisk + 0.1 * runRisk + 0.24 * magicHit
      )
  );
  const level: ThreatVerdict['level'] =
    score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'LOW';
  const summary =
    level === 'CRITICAL'
      ? 'Near-certain hidden container detected. The LSB plane carries StegoBolt framing or strongly non-natural statistics.'
      : level === 'HIGH'
      ? 'Strong statistical deviation from a natural cover. Assume data is embedded; sanitize before sharing.'
      : level === 'ELEVATED'
      ? 'Mild LSB-plane asymmetry. Likely a recompressed or lightly modified medium — verify provenance.'
      : 'Pixel statistics match an untouched natural cover medium. No embedding evidence found.';
  return {
    score,
    level,
    summary,
    signals: [
      { label: 'Chi-square pair attack', value: `${(s.chiSquare * 100).toFixed(1)}% evidence`, weight: s.chiSquare },
      { label: 'Estimated LSBM rate', value: `${(s.lsbmRateEstimate * 100).toFixed(1)}%`, weight: Math.max(0, 1 - s.lsbmRateEstimate) },
      { label: 'LSB ones ratio', value: s.onesRatio.toFixed(3), weight: balance },
      { label: 'Bit-stream entropy', value: `${s.entropy.toFixed(3)} bits/bit`, weight: entropyRisk },
      { label: 'Long-run anomaly', value: `${(s.runAnomaly * 100).toFixed(1)}%`, weight: runRisk },
      { label: 'SBV2 container signature', value: sbv2Found ? 'MAGIC FOUND' : 'absent', weight: magicHit },
    ],
  };
}

/** Grayscale rendering of the LSB plane for the anomaly heatmap canvas. */
export function renderLsbPlane(data: Uint8Array, width: number, height: number): Uint8ClampedArray<ArrayBuffer> {
  const out = new Uint8ClampedArray(width * height * 4);
  const pixels = Math.min(width * height, Math.floor(data.length / 4));
  for (let p = 0; p < pixels; p++) {
    const base = p * 4;
    const sum = (data[base] & 1) + (data[base + 1] & 1) + (data[base + 2] & 1);
    const g = sum * 85;
    out[base] = g;
    out[base + 1] = g;
    out[base + 2] = g;
    out[base + 3] = 255;
  }
  return out;
}
