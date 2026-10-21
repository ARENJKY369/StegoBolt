'use client';

/**
 * Client-side steganalysis: LSB-plane statistics, chi-square value-pair test,
 * sample-pair analysis (SPA), entropy estimate and PSNR / SSIM-lite quality
 * metrics. Pure math over the in-memory pixel buffer — nothing is transmitted.
 *
 * Statistical semantics (important — this is where false positives come from):
 *
 *  - The Westfeld chi-square value-pair test is a *goodness-of-fit* test of the
 *    natural-image hypothesis. Its survival probability `p` rises when
 *    neighbouring value pairs (2i, 2i+1) become equally populated, which is what
 *    sequential LSB replacement produces. A *small* p therefore means "pairs are
 *    unevenly populated", i.e. normal texture, gradients and JPEG quantisation —
 *    NOT embedding evidence. We consequently treat `p` itself (gated by the
 *    observed effect size and the sample size) as the equalisation signal and
 *    never collapse it into "100 % evidence" for an imbalanced plane.
 *  - A high chi-square probability alone is weak evidence: grain, flat regions
 *    and sensor noise equalise pairs in clean photographs too. It is only used
 *    together with an independent detector family (SPA) before the combined
 *    verdict can exceed LOW.
 *  - LSB replacement *pushes* the ones ratio towards 0.5. A large deviation from
 *    0.5 (e.g. 0.60) therefore indicates cover structure that survived, not an
 *    embedded payload, so closeness to 0.5 is only ever a *supporting* signal.
 *  - Only a validated SBV2 container header is treated as confirmed evidence.
 */

export interface LsbStats {
  pixels: number;
  embeddable: number;
  ones: number;
  onesRatio: number; // ~0.5 is natural and also what full-plane LSB replacement produces
  runAnomaly: number; // observed share of LSB runs with length >= 5 (context only)
  runExcess: number; // 0..1 excess over the i.i.d. expectation (context only)
  chiSquareStatistic: number;
  degreesOfFreedom: number;
  pValue: number; // pair-equality survival probability: high = equalised pairs
  pairImbalanceEffect: number; // mean |even-odd|/n over tested pairs (effect size)
  chiEqualization: number; // 0..1 calibrated equalisation evidence
  spaEmbeddingRatio: number; // SPA rate estimate 0..1
  spaEvidence: number; // 0..1 calibrated SPA evidence
  lsbmRateEstimate: number; // honest rate estimate (SPA based)
  entropy: number; // windowed binary entropy of the LSB stream (bits/bit)
  randomnessSupport: number; // 0..1 supporting signal, never decisive
  balanceSupport: number; // 0..1 support from channel LSB ratios sitting at 0.5
  maxChannelDeviation: number;
  sampleConfidence: number; // 0..1 how much the sample size can support
  channelStats: { name: string; ratio: number; deviation: number }[];
  histogram: number[]; // 128 pair-imbalance bars for the UI overlay
}

const CHAN = 3;
const PAIR_MIN_COUNT = 20;
const MIN_DF = 8;

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
  // Under i.i.d. bits the share of runs reaching 5 bits is ≈ (p⁵+(1−p)⁵)/(2p(1−p)).
  const p1 = onesRatio;
  const runChance =
    p1 > 0 && p1 < 1 ? (Math.pow(p1, 5) + Math.pow(1 - p1, 5)) / (2 * p1 * (1 - p1)) : 0;
  const runExcess = Math.max(0, Math.min(1, runAnomaly - runChance));

  // ---- Chi-square value-pair test (Westfeld) -------------------------------
  // d_b = n_even − n_odd for bucket b. Σ d²/n is the collapsed Pearson
  // statistic with one degree of freedom per adequately populated pair.
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
  let absImbalance = 0;
  let testedSamples = 0;
  for (let b = 0; b < 128; b++) {
    const n = even[b] + odd[b];
    if (n < PAIR_MIN_COUNT) continue;
    const d = even[b] - odd[b];
    chiSq += (d * d) / n;
    absImbalance += Math.abs(d);
    testedSamples += n;
    dfReal += 1;
  }
  const pValue = dfReal > 0 ? chiSquareTail(chiSq, dfReal) : 1;
  const pairImbalanceEffect = testedSamples ? absImbalance / testedSamples : 0;

  // Equalisation evidence from the proper statistic, not from a probability
  // threshold: under complete pair equalisation the collapsed statistic follows
  // χ²(df) (mean df, sd √(2df)). Real covers sit far above that mean (gradients,
  // texture, JPEG quantisation), so the z-score above the equalisation floor is
  // a stable, sample-size-aware measure. Large samples cannot inflate it.
  const sampleConfidence = Math.max(0, Math.min(1, Math.sqrt(embeddable / 32768)));
  const sizeGate = Math.max(0, Math.min(1, Math.sqrt(embeddable / 65536)));
  const dfGate = Math.max(0, Math.min(1, (dfReal - MIN_DF) / 24));
  const sigma = Math.sqrt(2 * Math.max(1, dfReal));
  const equalizationZ = (chiSq - dfReal) / sigma;
  const chiEqualization =
    Math.max(0, Math.min(1, 1 - (equalizationZ - 1) / 4)) * sizeGate * dfGate;

  // ---- Sample Pair Analysis (Dumitrescu-style rate estimate) ---------------
  const spaEmbeddingRatio = samplePairRatio(data, pixels);
  const spaEvidence = Math.max(0, Math.min(1, (spaEmbeddingRatio - 0.15) / 0.35)) * sizeGate;

  // ---- Windowed LSB entropy (supporting signal only) -----------------------
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
        const pOnes = o / win;
        const pZero = 1 - pOnes;
        acc += -(pZero * Math.log2(pZero || 1e-12) + pOnes * Math.log2(pOnes || 1e-12));
        used++;
      }
    }
    entropy = used ? acc / used : 1;
  }
  const randomnessSupport = Math.max(0, Math.min(1, (entropy - 0.9) / 0.1));

  const names = ['R', 'G', 'B'];
  const channelStats: { name: string; ratio: number; deviation: number }[] = [];
  let maxChannelDeviation = 0;
  for (let c = 0; c < CHAN; c++) {
    const ratio = chanTot[c] ? chanOnes[c] / chanTot[c] : 0.5;
    const deviation = Math.abs(ratio - 0.5);
    if (deviation > maxChannelDeviation) maxChannelDeviation = deviation;
    channelStats.push({ name: names[c], ratio, deviation });
  }
  // LSB replacement drives every channel towards 0.5, so "all channels close to
  // 0.5" is mild support — never evidence on its own.
  const balanceSupport = Math.max(0, Math.min(1, (0.06 - maxChannelDeviation) / 0.06));

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
    runExcess,
    chiSquareStatistic: chiSq,
    degreesOfFreedom: dfReal,
    pValue,
    pairImbalanceEffect,
    chiEqualization,
    spaEmbeddingRatio,
    spaEvidence,
    lsbmRateEstimate: spaEmbeddingRatio,
    entropy,
    randomnessSupport,
    balanceSupport,
    maxChannelDeviation,
    sampleConfidence,
    channelStats,
    histogram,
  };
}

/**
 * Dumitrescu-style sample-pair estimate over disjoint adjacent pairs of the
 * R/G/B channel stream. Pairs differing by one are split by the parity of the
 * smaller value; LSB replacement erodes type A into type B, so r = A/B yields
 * π = 2s/(1+s), s = √max(0, r−1). Returns 0 when the sample is too small.
 */
function samplePairRatio(data: Uint8Array, pixels: number): number {
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
  if (typeA + typeB < 64 || typeB === 0) return 0;
  const r = typeA / typeB;
  const s = Math.sqrt(Math.max(0, r - 1));
  return Math.max(0, Math.min(1, (2 * s) / (1 + s)));
}

/** Regularized upper incomplete gamma Q(k/2, x/2) — chi-square survival function. */
function chiSquareTail(statistic: number, df: number): number {
  // Survival function of the chi-square distribution: Q(k/2, x/2).
  const x = statistic / 2;
  const k = df;
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

/* -------------------------------------------------------------------------- */
/* SBV2 container inspection                                                  */
/* -------------------------------------------------------------------------- */

export type Sbv2Status = 'absent' | 'valid' | 'bad-version' | 'bad-flags' | 'bad-length' | 'truncated';

export interface Sbv2Inspection {
  status: Sbv2Status;
  /** The 4-byte magic was found in the first bits of the LSB plane. */
  found: boolean;
  /** Header validated: safe to state that an SBV2 container is present. */
  confirmed: boolean;
  version: number;
  flags: number;
  declaredLength: number;
  detail: string;
}

const SBV2_MAGIC = [0x53, 0x42, 0x56, 0x32];
const SBV2_VERSION = 2;
const SBV2_HEADER_BYTES = 10;
const SBV2_MAX_PAYLOAD = 32 * 1024 * 1024;

/** Read `count` bytes from the MSB-first LSB bit stream (R, G, B per pixel). */
function readLsbBytes(data: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(count);
  let bitBuf = 0;
  let filled = 0;
  let byteIdx = 0;
  const pixelCount = Math.floor(data.length / 4);
  outer: for (let p = 0; p < pixelCount; p++) {
    const base = p * 4;
    for (let c = 0; c < CHAN; c++) {
      bitBuf = (bitBuf << 1) | (data[base + c] & 1);
      if (++filled === 8) {
        out[byteIdx++] = bitBuf;
        bitBuf = 0;
        filled = 0;
        if (byteIdx >= count) break outer;
      }
    }
  }
  return out;
}

/**
 * Inspect the SBV2 container framing in the LSB plane without trusting it.
 * Distinguishes "no signature", "valid container" and damaged framing so the UI
 * never claims a message is embedded from a coincidental four-byte match.
 */
export function inspectSbv2Container(data: Uint8Array): Sbv2Inspection {
  const absent: Sbv2Inspection = {
    status: 'absent',
    found: false,
    confirmed: false,
    version: 0,
    flags: 0,
    declaredLength: 0,
    detail: 'No SBV2 container framing in the first bits of the LSB plane.',
  };
  const pixels = Math.floor(data.length / 4);
  if (pixels * CHAN < SBV2_HEADER_BYTES * 8) return absent;
  const head = readLsbBytes(data, SBV2_HEADER_BYTES);
  for (let i = 0; i < SBV2_MAGIC.length; i++) {
    if (head[i] !== SBV2_MAGIC[i]) return absent;
  }
  const version = head[4];
  const flags = head[5];
  const declaredLength =
    ((head[6] << 24) | (head[7] << 16) | (head[8] << 8) | head[9]) >>> 0;
  const base = { found: true, version, flags, declaredLength };
  if (version !== SBV2_VERSION) {
    return {
      ...absent,
      ...base,
      status: 'bad-version',
      detail: `SBV2 magic found but the container version is ${version} (expected ${SBV2_VERSION}).`,
    };
  }
  if (flags > 2) {
    return {
      ...absent,
      ...base,
      status: 'bad-flags',
      detail: `SBV2 magic found but the cipher flags are ${flags} (expected 0–2).`,
    };
  }
  if (declaredLength === 0 || declaredLength > SBV2_MAX_PAYLOAD) {
    return {
      ...absent,
      ...base,
      status: 'bad-length',
      detail: `SBV2 magic found but the declared payload length (${declaredLength}) is implausible.`,
    };
  }
  const neededBits = (SBV2_HEADER_BYTES + declaredLength) * 8;
  if (neededBits > pixels * CHAN) {
    return {
      ...absent,
      ...base,
      status: 'truncated',
      detail: 'SBV2 header found but the carrier is too small for the declared payload — it was likely resized or recompressed.',
    };
  }
  return {
    status: 'valid',
    found: true,
    confirmed: true,
    version,
    flags,
    declaredLength,
    detail: `Valid SBV2 v${version} container header (cipher id ${flags}, ${declaredLength} ciphertext bytes).`,
  };
}

/** Backwards-compatible boolean probe: the SBV2 magic is present. */
export function detectSbv2Magic(data: Uint8Array): boolean {
  return inspectSbv2Container(data).found;
}

/* -------------------------------------------------------------------------- */
/* Threat assessment                                                          */
/* -------------------------------------------------------------------------- */

export type ThreatLevel = 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
export type ThreatConfidence = 'CONFIRMED' | 'SUSPICIOUS' | 'INCONCLUSIVE' | 'CLEAN';

export interface ThreatVerdict {
  score: number; // 0..100
  level: ThreatLevel;
  /** Extra confidence label — never replaces the LOW/ELEVATED/HIGH/CRITICAL scale. */
  confidence: ThreatConfidence;
  summary: string;
  basis: string;
  signals: { label: string; value: string; weight: number }[];
}

export function levelFromScore(score: number): ThreatLevel {
  return score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'LOW';
}

const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

interface StatisticalInput {
  chiProbability: number; // pair-equalisation survival probability (0..1)
  chiEqualization: number; // calibrated equalisation evidence
  spa: number; // SPA rate estimate
  spaEvidence: number;
  onesRatio: number;
  randomnessSupport: number;
  sampleConfidence: number;
  sampleSize: number;
  hasSampleStatistics: boolean;
}

interface Classification {
  score: number;
  level: ThreatLevel;
  confidence: ThreatConfidence;
  summary: string;
}

/**
 * Combined statistical classification. Two independent detector families
 * (value-pair equalisation and SPA) must agree before the verdict may reach
 * HIGH; a single detector can never lift a carrier above LOW on its own.
 */
function classifyStatistics(input: StatisticalInput, mediumLabel: string): Classification {
  if (!input.hasSampleStatistics) {
    return {
      score: 8,
      level: 'LOW',
      confidence: 'INCONCLUSIVE',
      summary: `No StegoBolt container detected in this ${mediumLabel} carrier; no medium-specific embedding layer or structural anomaly was found.`,
    };
  }
  if (input.sampleSize < 4096 || input.sampleConfidence < 0.25) {
    return {
      score: 12,
      level: 'LOW',
      confidence: 'INCONCLUSIVE',
      summary: `No StegoBolt container detected. The sample is too small for reliable statistics, so no direct evidence of an embedded message was found and none can be excluded.`,
    };
  }

  const eq = input.chiEqualization;
  const spa = input.spaEvidence;
  const balance = clamp01((0.06 - Math.abs(input.onesRatio - 0.5)) / 0.06);
  const support = 0.5 * balance + 0.5 * clamp01(input.randomnessSupport);

  // Two independent detector families: SPAn (sample-pair analysis) and the
  // value-pair equalisation measured by chi-square. Neither is allowed to raise
  // the level on its own: SPA must be strong *and* value-pair equalisation must
  // corroborate it, which keeps chi-square usable without letting a high
  // chi-square probability alone drive an ELEVATED verdict.
  const weighted = 0.55 * eq + 0.45 * spa;
  const adjusted = clamp01(weighted * input.sampleConfidence);

  if (spa >= 0.6 && eq >= 0.45) {
    return {
      score: Math.round(Math.min(88, 50 + 40 * adjusted)),
      level: 'HIGH',
      confidence: 'SUSPICIOUS',
      summary:
        'No StegoBolt container signature was found, but two independent statistical detectors agree on an embedding-like layer. Treat this as strong statistical suspicion, not a confirmed message, and sanitize before sharing.',
    };
  }
  if (spa >= 0.6 && eq >= 0.3) {
    return {
      score: Math.round(Math.min(49, 25 + 22 * adjusted)),
      level: 'ELEVATED',
      confidence: 'INCONCLUSIVE',
      summary:
        'No StegoBolt container detected; statistical irregularities are inconclusive. No direct evidence of an embedded message.',
    };
  }
  return {
    score: Math.round(Math.min(24, 6 + 16 * Math.max(weighted, 0.5 * support) * input.sampleConfidence)),
    level: 'LOW',
    confidence: 'CLEAN',
    summary:
      'No StegoBolt container detected and no direct evidence of an embedded message. The LSB statistics are consistent with an ordinary cover medium.',
  };
}

/**
 * Threat assessment for a locally scanned image.
 *
 * @param signature SBV2 inspection result (a boolean is accepted for
 *                  backwards compatibility and treated as a magic-only hit).
 */
export function threatAssessment(
  stats: LsbStats | null,
  signature: Sbv2Inspection | boolean
): ThreatVerdict {
  const insp: Sbv2Inspection =
    typeof signature === 'boolean'
      ? signature
        ? {
            status: 'valid',
            found: true,
            confirmed: true,
            version: 2,
            flags: 0,
            declaredLength: 0,
            detail: 'SBV2 magic detected in the first bits of the LSB plane.',
          }
        : {
            status: 'absent',
            found: false,
            confirmed: false,
            version: 0,
            flags: 0,
            declaredLength: 0,
            detail: 'No SBV2 container framing in the first bits of the LSB plane.',
          }
      : signature;

  const basis = stats
    ? `Pixel LSB plane · ${stats.channelStats.length} channels · ${stats.pixels.toLocaleString('en-US')} pixels (${stats.embeddable.toLocaleString('en-US')} bit slots)`
    : 'Pixel LSB plane';

  // A single detector never reads as strong evidence on the bars: isolated
  // detector output is attenuated until the independent family agrees.
  const corroborate = (own: number, other: number) => own * (0.35 + 0.65 * other);
  const signals: ThreatVerdict['signals'] = stats
    ? [
        {
          label: 'Value-pair equalisation',
          value: `p=${stats.pValue < 1e-4 ? stats.pValue.toExponential(1) : stats.pValue.toFixed(3)} · ${(stats.chiEqualization * 100).toFixed(0)}%`,
          weight: corroborate(stats.chiEqualization, stats.spaEvidence),
        },
        {
          label: 'Sample-pair rate (SPA)',
          value: `${(stats.lsbmRateEstimate * 100).toFixed(1)}%${stats.chiEqualization < 0.3 && stats.spaEvidence > 0.3 ? ' · uncorroborated' : ''}`,
          weight: corroborate(stats.spaEvidence, stats.chiEqualization),
        },
        {
          label: 'LSB ones ratio',
          value: stats.onesRatio.toFixed(3),
          weight: stats.balanceSupport,
        },
        {
          label: 'Bit-stream entropy',
          value: `${stats.entropy.toFixed(3)} bits/bit`,
          weight: stats.randomnessSupport,
        },
        {
          label: 'LSB run structure',
          value: `${(stats.runAnomaly * 100).toFixed(1)}%`,
          weight: stats.runExcess, // context only — run structure is not embedding evidence
        },
        {
          label: 'SBV2 container signature',
          value:
            insp.confirmed
              ? 'CONFIRMED'
              : insp.status !== 'absent'
              ? insp.status.replace('-', ' ').toUpperCase()
              : 'absent',
          weight: insp.confirmed ? 1 : insp.status !== 'absent' ? 0.6 : 0,
        },
      ]
    : [];

  if (insp.confirmed) {
    return {
      score: 96,
      level: 'CRITICAL',
      confidence: 'CONFIRMED',
      summary:
        'Confirmed StegoBolt container detected: a valid SBV2 container header is present in the LSB plane of this carrier.',
      basis,
      signals,
    };
  }

  if (insp.status !== 'absent') {
    return {
      score: 68,
      level: 'HIGH',
      confidence: 'SUSPICIOUS',
      summary:
        'Damaged StegoBolt container framing detected: the SBV2 signature is present but its header is inconsistent, so the payload cannot be read. Treat this carrier as modified and sanitize it before sharing.',
      basis,
      signals,
    };
  }

  const classification = stats
    ? classifyStatistics(
        {
          chiProbability: stats.pValue,
          chiEqualization: stats.chiEqualization,
          spa: stats.spaEmbeddingRatio,
          spaEvidence: stats.spaEvidence,
          onesRatio: stats.onesRatio,
          randomnessSupport: stats.randomnessSupport,
          sampleConfidence: stats.sampleConfidence,
          sampleSize: stats.embeddable,
          hasSampleStatistics: true,
        },
        'image'
      )
    : {
        score: 0,
        level: 'LOW' as ThreatLevel,
        confidence: 'INCONCLUSIVE' as ThreatConfidence,
        summary: 'No StegoBolt container detected and no direct evidence of an embedded message.',
      };

  return { ...classification, basis, signals };
}

/* -------------------------------------------------------------------------- */
/* Java engine report normalisation / fallback classification                 */
/* -------------------------------------------------------------------------- */

/**
 * Structural subset of the Java engine scan report used by the UI. All fields
 * except the legacy numeric ones are optional so an older engine still renders.
 */
export interface EngineScanView {
  medium: string;
  threatScore: number;
  containerSignatureFound: boolean;
  chiSquareProbability: number;
  spaEmbeddingRatio: number;
  lsbOnesRatio: number;
  lsbEntropy?: number;
  sampleBased?: boolean;
  sampleSize?: number;
  level?: string;
  confidence?: string;
  summary?: string;
  analysisBasis?: string;
  indicators: string[];
}

function normaliseLevel(value: string | undefined, score: number): ThreatLevel {
  const upper = (value ?? '').toUpperCase();
  return upper === 'CRITICAL' || upper === 'HIGH' || upper === 'ELEVATED' || upper === 'LOW'
    ? (upper as ThreatLevel)
    : levelFromScore(score);
}

/**
 * Engine-mode verdict. Prefers the engine's own calibrated verdict (which is
 * medium-aware) and only derives a fallback from the numeric fields when an
 * older engine omits it. Never upgrades a report to "confirmed" without the
 * engine's `containerSignatureFound` flag.
 */
export function assessEngineScan(report: EngineScanView): ThreatVerdict {
  const basis =
    report.analysisBasis ||
    `${report.medium} container structure · ${report.sampleBased === false ? 'structural evidence only' : 'sample-stream statistics'}`;

  const hasSamples = report.sampleBased !== false;
  const eqWeight = hasSamples && !report.containerSignatureFound
    ? clamp01((report.chiSquareProbability - 0.5) / 0.45)
    : 0;
  const spaWeight = hasSamples ? clamp01((report.spaEmbeddingRatio - 0.15) / 0.35) : 0;
  const corroborate = (own: number, other: number) => own * (0.35 + 0.65 * other);
  const signals: ThreatVerdict['signals'] = [
    {
      label: 'Value-pair equalisation',
      value: hasSamples ? `p=${report.chiSquareProbability.toExponential(2)}` : 'not applicable',
      weight: corroborate(eqWeight, spaWeight),
    },
    {
      label: 'Sample-pair rate (SPA)',
      value: hasSamples ? `${(report.spaEmbeddingRatio * 100).toFixed(1)}%${eqWeight < 0.3 && spaWeight > 0.3 ? ' · uncorroborated' : ''}` : 'not applicable',
      weight: corroborate(spaWeight, eqWeight),
    },
    { label: 'LSB ones ratio', value: report.lsbOnesRatio.toFixed(3), weight: report.sampleBased === false ? 0 : clamp01((0.06 - Math.abs(report.lsbOnesRatio - 0.5)) / 0.06) },
    { label: 'Container signature', value: report.containerSignatureFound ? 'CONFIRMED' : 'absent', weight: report.containerSignatureFound ? 1 : 0 },
  ];

  if (report.summary && report.level) {
    const level = normaliseLevel(report.level, report.threatScore);
    const confidence = (() => {
      const upper = (report.confidence ?? '').toUpperCase();
      return upper === 'CONFIRMED' || upper === 'SUSPICIOUS' || upper === 'INCONCLUSIVE' || upper === 'CLEAN'
        ? (upper as ThreatConfidence)
        : report.containerSignatureFound
        ? 'CONFIRMED'
        : level === 'LOW'
        ? 'CLEAN'
        : 'INCONCLUSIVE';
    })();
    return {
      score: report.threatScore,
      level,
      confidence,
      summary: report.summary,
      basis,
      signals,
    };
  }

  // Fallback for an engine without calibrated verdict fields.
  if (report.containerSignatureFound) {
    return {
      score: 96,
      level: 'CRITICAL',
      confidence: 'CONFIRMED',
      summary:
        'Confirmed StegoBolt container detected: the Java engine recovered a valid SBV2-J container header from this carrier.',
      basis,
      signals,
    };
  }
  const classification = classifyStatistics(
    {
      chiProbability: report.chiSquareProbability,
      chiEqualization: clamp01((report.chiSquareProbability - 0.5) / 0.45) * clamp01((0.06 - Math.abs(report.lsbOnesRatio - 0.5)) / 0.06),
      spa: report.spaEmbeddingRatio,
      spaEvidence: clamp01((report.spaEmbeddingRatio - 0.15) / 0.35),
      onesRatio: report.lsbOnesRatio,
      randomnessSupport: clamp01(((report.lsbEntropy ?? 0) - 0.9) / 0.1),
      sampleConfidence: clamp01(Math.sqrt((report.sampleSize ?? 0) / 65536)),
      sampleSize: report.sampleSize ?? 0,
      hasSampleStatistics: report.sampleBased !== false,
    },
    report.medium.toLowerCase()
  );
  return { ...classification, basis, signals };
}

/* -------------------------------------------------------------------------- */
/* Quality metrics                                                            */
/* -------------------------------------------------------------------------- */

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
