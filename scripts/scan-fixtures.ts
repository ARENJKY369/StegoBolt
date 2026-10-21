// Deterministic steganalysis fixtures for the pipeline/regression suite.
// Everything is generated from a fixed seed — no binary assets in Git, no
// network access, no canvas dependency (Node runs this headlessly).
//
// The fixtures deliberately model the failure modes of real carriers:
//   * natural photographs      — multi-scale gradients + grain + per-channel gain
//   * recompressed JPEG        — 8×8 quantisation + even-value bias
//   * natural channel imbalance— a blue-channel gain that skews the LSB ratio
//   * stego carriers           — the real SBV2 embedder from lib/lsbcore.ts

import { embedIntoPixels } from '../lib/lsbcore.ts';

export type Rgba = Uint8Array;

/** Small deterministic PRNG (xorshift32) — reproducible across Node runs. */
export function makeRng(seed: number): () => number {
  let s = seed >>> 0 || 0x9e3779b9;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    return s / 0x100000000;
  };
}

function hash2(x: number, y: number, seed: number): number {
  let h = (x * 374761393 + y * 668265263 + seed * 2246822519) >>> 0;
  h = (h ^ (h >>> 13)) * 1274126177 >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}

/** Smooth multi-octave value noise in [0,1]. */
function valueNoise(x: number, y: number, octaves: number, seed: number): number {
  let sum = 0;
  let amp = 1;
  let norm = 0;
  for (let o = 0; o < octaves; o++) {
    const scale = 1 << o;
    const fx = x * scale;
    const fy = y * scale;
    const x0 = Math.floor(fx);
    const y0 = Math.floor(fy);
    const tx = fx - x0;
    const ty = fy - y0;
    const sx = tx * tx * (3 - 2 * tx);
    const sy = ty * ty * (3 - 2 * ty);
    const v00 = hash2(x0, y0, seed + o) / 0xffffffff;
    const v10 = hash2(x0 + 1, y0, seed + o) / 0xffffffff;
    const v01 = hash2(x0, y0 + 1, seed + o) / 0xffffffff;
    const v11 = hash2(x0 + 1, y0 + 1, seed + o) / 0xffffffff;
    const top = v00 + (v10 - v00) * sx;
    const bottom = v01 + (v11 - v01) * sx;
    sum += (top + (bottom - top) * sy) * amp;
    norm += amp;
    amp *= 0.5;
  }
  return sum / norm;
}

/**
 * A clean "photograph": multi-scale luminance structure, mild sensor grain and
 * small per-channel gains (red/blue sensitivity differences are normal).
 * Returns RGBA with opaque alpha, like the browser's canvas decode.
 */
export function cleanNaturalPhoto(width: number, height: number, seed = 7): Rgba {
  const rng = makeRng(seed);
  const out = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const u = x / width;
      const v = y / height;
      const glow = 0.55 + 0.35 * Math.sin(u * 6.1 + 0.7) * Math.cos(v * 4.3 - 0.2);
      const base = 0.5 * glow + 0.5 * valueNoise(u * 6, v * 6, 5, seed);
      const grain = (rng() - 0.5) * 0.06;
      const shade = Math.max(0, Math.min(1, base + grain));
      const i = (y * width + x) * 4;
      out[i] = Math.round(255 * Math.max(0, Math.min(1, shade * 1.02 + 0.01)));
      out[i + 1] = Math.round(255 * Math.max(0, Math.min(1, shade)));
      out[i + 2] = Math.round(255 * Math.max(0, Math.min(1, shade * 0.97 + 0.02)));
      out[i + 3] = 255;
    }
  }
  return out;
}

/**
 * Clean image with a deliberate natural channel imbalance: quantisation of the
 * red channel and highlight saturation in the blue channel skew the per-channel
 * LSB ratios to ~0.60 overall. This is the shape of the reported false positive
 * ("LSB ones ratio 0.597") and must not be read as an embedded payload.
 */
export function cleanChannelImbalance(width: number, height: number, seed = 11): Rgba {
  const photo = cleanNaturalPhoto(width, height, seed);
  const out = photo.slice();
  const rng = makeRng(seed + 5);
  // Per-channel quantisation/saturation bias: red is quantised coarsely, blue
  // is saturated, green keeps the sensor's noise floor. Overall LSB ones ≈ 0.60,
  // i.e. exactly the shape of the reported false positive.
  for (let p = 0; p < width * height; p++) {
    const i = p * 4;
    out[i] = (out[i] & 0xfe) | (rng() < 0.7 ? 1 : 0);
    out[i + 1] = (out[i + 1] & 0xfe) | (rng() < 0.56 ? 1 : 0);
    out[i + 2] = (out[i + 2] & 0xfe) | (rng() < 0.53 ? 1 : 0);
  }
  return out;
}

/**
 * Simulated recompressed JPEG: 8×8 block quantisation with the even-value bias
 * a DCT quantiser leaves behind (plus ringing dither so the LSB plane is not
 * degenerate). Pairs become *unequal*, which the old inverted chi-square
 * mapping reported as 100 % evidence.
 */
export function recompressedJpeg(width: number, height: number, seed = 19): Rgba {
  const photo = cleanNaturalPhoto(width, height, seed);
  const out = new Uint8Array(photo.length);
  const block = 8;
  for (let by = 0; by < height; by += block) {
    for (let bx = 0; bx < width; bx += block) {
      const sums = [0, 0, 0];
      let n = 0;
      for (let y = by; y < Math.min(height, by + block); y++) {
        for (let x = bx; x < Math.min(width, bx + block); x++) {
          const i = (y * width + x) * 4;
          sums[0] += photo[i];
          sums[1] += photo[i + 1];
          sums[2] += photo[i + 2];
          n++;
        }
      }
      const means = sums.map((s) => s / Math.max(1, n));
      for (let y = by; y < Math.min(height, by + block); y++) {
        for (let x = bx; x < Math.min(width, bx + block); x++) {
          const i = (y * width + x) * 4;
          const ringing = (((x * 5 + y * 3) & 3) === 0 ? 1 : 0);
          for (let c = 0; c < 3; c++) {
            // Coarse quantisation (step 6) snapped to even values + ringing.
            const q = Math.round((means[c] + (photo[i + c] - means[c]) * 0.3) / 6) * 6;
            const v = q + ringing;
            out[i + c] = Math.max(0, Math.min(255, (v & 0xfe) | (ringing && (q & 2) === 0 ? 1 : 0)));
          }
          out[i + 3] = 255;
        }
      }
    }
  }
  return out;
}

/**
 * A structured synthetic image (flat colour panels + smooth ramps) with mild
 * natural channel imbalance — the "clean synthetic" regression case.
 */
export function syntheticChannelBias(width: number, height: number, seed = 23): Rgba {
  const out = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      const panel = ((x / 40 | 0) + (y / 40 | 0)) % 2;
      const ramp = Math.round((x / width) * 30);
      const dither = hash2(x, y, seed) % 2;
      out[i] = Math.min(255, 96 + panel * 8 + ramp + dither);
      out[i + 1] = Math.min(255, 104 + panel * 6 + dither);
      out[i + 2] = Math.min(255, 118 + panel * 4 - Math.round((y / height) * 6) + dither);
      out[i + 3] = 255;
    }
  }
  return out;
}

/**
 * Full-plane LSB replacement with pseudo-random bits and no StegoBolt framing —
 * the strongest legitimate "statistical suspicion" case (both detector families
 * must agree) which still must never be reported as a confirmed container.
 */
export function fullPlaneLsbNoise(cover: Rgba, seed = 31): Rgba {
  const rng = makeRng(seed);
  const out = cover.slice();
  for (let i = 0; i < out.length; i += 4) {
    for (let c = 0; c < 3; c++) {
      out[i + c] = (out[i + c] & 0xfe) | (rng() < 0.5 ? 1 : 0);
    }
  }
  return out;
}

/** Embed a real SBV2 container (raw cipher id) using the production embedder. */
export function sbv2Stego(cover: Rgba, width: number, height: number, payloadBytes = 96): Rgba {
  const payload = new Uint8Array(payloadBytes);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 73 + 19) & 0xff;
  const stego = cover.slice();
  embedIntoPixels(stego, payload, 0);
  void width; void height;
  return stego;
}

/**
 * Corrupt the SBV2 framing (version byte) while keeping the magic intact — the
 * "wrong or corrupted signature" regression case.
 */
export function corruptedSbv2(stego: Rgba): Rgba {
  const out = stego.slice();
  // Header byte 4 (version) lives in LSB bits 32..39 of the R/G/B stream.
  // Write 0x09 instead of 0x02 into those bits.
  const wanted = 0x09;
  for (let b = 0; b < 8; b++) {
    const bitIndex = 32 + b;
    const p = Math.floor(bitIndex / 3);
    const c = bitIndex % 3;
    const bit = (wanted >> (7 - b)) & 1;
    out[p * 4 + c] = (out[p * 4 + c] & 0xfe) | bit;
  }
  return out;
}

/** RGBA → the engine's RGB sample stream (used by the Java-side fixtures too). */
export function rgbSamples(image: Rgba): Uint8Array {
  const out = new Uint8Array((image.length / 4) * 3);
  for (let p = 0; p < image.length / 4; p++) {
    out[p * 3] = image[p * 4];
    out[p * 3 + 1] = image[p * 4 + 1];
    out[p * 3 + 2] = image[p * 4 + 2];
  }
  return out;
}
