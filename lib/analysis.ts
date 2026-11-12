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
  runExcess: number; // run share above the i.i.d. chance floor, 0..1
  chiSquare: number; // 0..1 pair-equalization evidence for sequential LSB embedding
  chiSquareRaw: number;
  degreesOfFreedom: number;
  pValue: number;
  lsbmRateEstimate: number; // SPA embedding-rate estimate 0..1 (grows with payload size)
  entropy: number; // bits per embedded bit (windowed)
  sbv2Detected: boolean; // tolerant SBV2 header match in the first bits
  sbv2DeclaredBytes: number; // exact payload size from the SBV2 header (0 if unusable)
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
  const onesRatio = embeddable ? ones / embeddable : 0.5;
  const runAnomaly = runsTotal ? runsLong / runsTotal : 0;
  // Share of runs reaching 5 bits that pure chance produces: (p⁴+(1−p)⁴)/2
  // under i.i.d. bits with ones probability p. Only the *excess* above this
  // floor means structured content, so random-clean planes read ~0.
  const pOnes = Math.max(1e-9, Math.min(1 - 1e-9, onesRatio));
  const runChance = (Math.pow(pOnes, 4) + Math.pow(1 - pOnes, 4)) / 2;
  const runExcess = Math.max(0, Math.min(1, runAnomaly - runChance));

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
  // Under clean sampling, this statistic is centered near dfReal. Embedding
  // equalizes value pairs and drives it below that baseline, so only a
  // statistically low result is evidence of embedding.
  const sizeGate = Math.max(0, Math.min(1, Math.sqrt(embeddable / 65536)));
  const dfGate = Math.max(0, Math.min(1, (dfReal - 8) / 24));
  const equalizationZ = (chiSq - dfReal) / Math.sqrt(2 * Math.max(1, dfReal));
  const chiSquare = Math.max(0, Math.min(1, (-equalizationZ - 1) / 4)) * sizeGate * dfGate;
  // Embedding rate via a scan-prefix equalization profile: StegoBolt writes
  // sequentially, so the embedded prefix sits at the equalization floor while
  // the untouched remainder stays natural. The estimate is the largest prefix
  // fraction that still looks equalized — it grows monotonically with the
  // payload size and stays ~0 on natural covers, whose prefixes never
  // equalize no matter how much of them is examined.
  // Embedding-extent estimate: whichever is stronger of the sample-pair
  // estimate (Dumitrescu) and the pair-equalization evidence. Both stay ~0 on
  // natural covers and grow monotonically with the embedded fraction, so the
  // verdict scales with how much of the carrier is actually overwritten.
  const lsbmRateEstimate = Math.max(samplePairRate(data, pixels), chiSquare);

  // windowed entropy over the LSB stream (guarded for tiny images)
  let entropy = 1;
  {
    const win = 4096;
    const samples = Math.min(24, Math.max(1, Math.floor(embeddable / win)));
    let acc = 0;
    let used = 0;
    if (embeddable >= win) {
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
        used++;
      }
    }
    entropy = used ? acc / used : 1;
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

  // SBV2 framing probe — the declared length is an exact embedded-extent
  // measurement for StegoBolt-written carriers (statistics only need it at
  // the corroboration level for foreign carriers).
  const sbv2 = inspectSbv2Header(data);

  return {
    pixels,
    embeddable,
    ones,
    onesRatio,
    runAnomaly,
    runExcess,
    chiSquare,
    chiSquareRaw: chiSq,
    degreesOfFreedom: dfReal,
    pValue,
    lsbmRateEstimate,
    entropy,
    sbv2Detected: sbv2.found,
    sbv2DeclaredBytes: sbv2.declaredBytes,
    channelStats,
    histogram,
  };
}

/**
 * Dumitrescu-style sample-pair estimate over disjoint adjacent pairs of the
 * R/G/B stream. Adjacent samples differing by exactly 1 ("poised" pairs) are
 * split by the parity of the smaller value; LSB replacement erodes the
 * even-lead pairs, so r = A/B yields π = 2·√max(0, r−1)/(1+√max(0, r−1)).
 * Natural covers and compressed bytes keep A ≈ B → π ≈ 0.
 */
function samplePairRate(data: Uint8Array, pixels: number): number {
  const total = pixels * CHAN;
  if (total < 512) return 0;
  let typeA = 0;
  let typeB = 0;
  const pairCount = total >> 1;
  for (let k = 0; k < pairCount; k++) {
    const i = k * 2;
    const a = data[((i / CHAN) | 0) * 4 + (i % CHAN)];
    const j = i + 1;
    const b = data[((j / CHAN) | 0) * 4 + (j % CHAN)];
    const lo = a < b ? a : b;
    const hi = a < b ? b : a;
    if (hi - lo === 1) {
      if ((lo & 1) === 0) typeA++;
      else typeB++;
    }
  }
  if (typeB === 0 || typeA + typeB < 8) return 0;
  const r = typeA / typeB;
  const s = Math.sqrt(Math.max(0, r - 1));
  return Math.max(0, Math.min(1, (2 * s) / (1 + s)));
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

export interface Sbv2Inspection {
  found: boolean;
  /** Declared payload bytes from the SBV2 length field, 0 when unusable. */
  declaredBytes: number;
}

/**
 * Scan the LSB bitstream for the StegoBolt SBV2 header (framed in the first
 * bytes) and read the declared payload length. The magic match tolerates a
 * few corrupted framing bits: canvas color-managed sampling can round
 * isolated pixel values by ±1, flipping sparse LSBs while the upper bits
 * survive. 32 bits with ≤6 errors match a random plane with probability
 * ≈ 2.7e-4, so clean covers still read as clean.
 */
export function inspectSbv2Header(data: Uint8Array): Sbv2Inspection {
  const want = [0x53, 0x42, 0x56, 0x32];
  const MAX_BIT_ERRORS = 6;
  const HEADER_BYTES = 10; // magic(4) + version(1) + flags(1) + length(4)
  const bytes = new Uint8Array(HEADER_BYTES);
  let bitIdx = 0;
  let bitBuf = 0;
  let errors = 0;
  const pixelCount = Math.floor(data.length / 4);
  for (let p = 0; p < pixelCount && bitIdx < HEADER_BYTES * 8; p++) {
    const base = p * 4;
    for (let c = 0; c < CHAN && bitIdx < HEADER_BYTES * 8; c++) {
      bitBuf = (bitBuf << 1) | (data[base + c] & 1);
      if (bitIdx % 8 === 7) {
        const idx = bitIdx >> 3;
        bytes[idx] = bitBuf;
        if (idx < 4) {
          let diff = bitBuf ^ want[idx];
          while (diff) {
            diff &= diff - 1;
            errors++;
            if (errors > MAX_BIT_ERRORS) return { found: false, declaredBytes: 0 };
          }
        }
        bitBuf = 0;
      }
      bitIdx++;
    }
  }
  const found = bitIdx >= HEADER_BYTES * 8 && errors <= MAX_BIT_ERRORS;
  // The length field rides the same sampled LSBs, so allow its self-healing:
  // accept it verbatim when it fits the carrier, otherwise accept the smallest
  // single-bit repair that fits (a ±1 canvas rounding flips exactly one bit).
  const declared = ((bytes[6] << 24) | (bytes[7] << 16) | (bytes[8] << 8) | bytes[9]) >>> 0;
  const capacityBytes = (pixelCount * CHAN - HEADER_BYTES * 8) >> 3;
  let declaredBytes = 0;
  if (found && capacityBytes > 0) {
    if (declared > 0 && declared <= capacityBytes) {
      declaredBytes = declared;
    } else {
      // The magic already gated attribution, so correcting corrupted framing
      // bits is safe here: ±1 value rounding flips exactly one bit per rounded
      // sample, so the corrupted length reads oversized — clamping, bounded
      // bit-repair and byte splicing against the carrier capacity recover the
      // true extent.
      const tryRepair = (candidate: number) => {
        const repaired = candidate >>> 0;
        if (repaired > 0 && repaired <= capacityBytes && (declaredBytes === 0 || repaired < declaredBytes)) {
          declaredBytes = repaired;
        }
      };
      const withByte = (base: number, shift: number, byteVal: number) =>
        ((base & ~(0xff << shift)) | ((byteVal & 0xff) << shift)) >>> 0;
      const cByte = (shift: number) => (capacityBytes >>> shift) & 0xff;
      // 1) width clamps (the fit-difference lives in the unused top byte)
      tryRepair(declared & 0x00ffffff);
      tryRepair(declared & 0x01ffffff);
      // 2) per-byte splice with the capacity byte at that position
      for (const shift of [24, 16, 8, 0]) {
        tryRepair(withByte(declared, shift, cByte(shift)));
      }
      // 3) two high-byte splices (covers a corruption in either of them)
      tryRepair(withByte(withByte(declared, 24, cByte(24)), 16, cByte(16)));
      tryRepair(withByte(withByte(declared, 24, cByte(24)), 8, cByte(8)));
      // 4) bounded bit repair: ≤3 flips, smallest fitting result wins
      for (let a = 0; a < 32; a++) {
        tryRepair(declared ^ (1 << a));
        for (let b = a + 1; b < 32; b++) {
          tryRepair(declared ^ (1 << a) ^ (1 << b));
          for (let c = b + 1; c < 32; c++) {
            tryRepair(declared ^ (1 << a) ^ (1 << b) ^ (1 << c));
          }
        }
      }
    }
  }
  return { found, declaredBytes };
}

/** Scan the LSB bitstream for the StegoBolt SBV2 magic (framed in the first bytes). */
export function detectSbv2Magic(data: Uint8Array): boolean {
  return inspectSbv2Header(data).found;
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
  const magicHit = sbv2Found ? 1 : 0;
  const eq = s.chiSquare;
  // Embedding-extent ramp: silent below 0.2, saturated at 0.75 — driven by
  // whichever detector is stronger, so it grows monotonically with payload size.
  const sizeEvidence = Math.max(0, Math.min(1, (s.lsbmRateEstimate - 0.2) / 0.55));
  // For StegoBolt-written carriers the header declares the payload size
  // verbatim — an exact, texture-independent severity ramp: a short note in a
  // large photo reads mild, a near-full plane reads critical.
  const declaredFraction = s.embeddable
    ? Math.min(1, (s.sbv2DeclaredBytes * 8 + 80) / s.embeddable)
    : 0;
  const declaredRamp = Math.max(0, Math.min(1, (declaredFraction - 0.02) / 0.4));
  const extent = Math.max(sizeEvidence, magicHit ? declaredRamp : 0);
  const supports = 0.1 * balance + 0.08 * entropyRisk + 0.08 * s.runExcess;
  let score: number;
  if (magicHit) {
    // A confirmed SBV2 container signature proves the carrier was written by
    // the Hide pipeline, so the only remaining question is how MUCH it holds:
    // severity scales directly with the embedding extent — a short note reads
    // mild ELEVATED, a near-full carrier climbs to CRITICAL.
    score = Math.round(100 * Math.min(1, 0.3 + 0.42 * extent + 0.1 * eq + supports));
  } else {
    // Without a signature the statistical core stays cautionary and the two
    // independent detector families (equalization, embedding extent) must
    // corroborate each other, so clean media — even compressed, noisy or
    // strongly textured ones — can never read as HIGH.
    const eqAgreement = eq * (0.15 + 0.85 * sizeEvidence);
    const extentAgreement = sizeEvidence * (0.15 + 0.85 * eq);
    const statsCore = 0.34 * eqAgreement + 0.2 * extentAgreement + supports;
    score = Math.round(100 * Math.min(1, 0.55 * statsCore));
  }
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
      { label: 'Estimated LSBM rate', value: `${(s.lsbmRateEstimate * 100).toFixed(1)}%`, weight: extent },
      { label: 'LSB ones ratio', value: s.onesRatio.toFixed(3), weight: balance },
      { label: 'Bit-stream entropy', value: `${s.entropy.toFixed(3)} bits/bit`, weight: entropyRisk },
      { label: 'Long-run anomaly', value: `${(s.runAnomaly * 100).toFixed(1)}%`, weight: s.runExcess },
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
