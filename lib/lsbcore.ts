'use client';

/**
 * Pure LSB (Least Significant Bit) stego engine.
 *
 * Container bitstream embedded into the LSB plane of the R/G/B channels
 * (the alpha channel is never touched):
 *
 *   [ magic 'SBV2' (4B) ][ version (1B) ][ flags (1B) ][ payload length uint32 BE (4B) ][ payload … ]
 *
 * flags == cipher id (0 raw, 1 AES-256-GCM, 2 AES-256-CTR).
 * This module is duplicated inside lib/worker.ts's inline worker so the
 * identical algorithm can run off the main thread.
 */

export const MAGIC = [0x53, 0x42, 0x56, 0x32]; // 'SBV2'
export const SB_VERSION = 2;
export const HEADER_LEN = 10; // bytes
export const HEADER_BITS = HEADER_LEN * 8;

export class LsbError extends Error {
  code: string;
  detail?: string;
  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.detail = detail;
    this.name = 'LsbError';
  }
}

export function capacityBits(pixelByteLength: number): number {
  // 3 embeddable bits per RGBA pixel (R, G, B)
  return Math.floor(pixelByteLength / 4) * 3;
}

export function capacityBytes(pixelByteLength: number): number {
  return Math.floor((capacityBits(pixelByteLength) - HEADER_BITS) / 8);
}

export function dimsCapacityBytes(width: number, height: number): number {
  return Math.floor((width * height * 3 - HEADER_BITS) / 8);
}

function getBit(data: Uint8Array, n: number): number {
  const p = (n / 3) | 0;
  const c = n - p * 3;
  return data[p * 4 + c] & 1;
}

function bitsToBytes(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array((bits.length + 7) >> 3);
  for (let i = 0; i < bits.length; i++) {
    out[i >> 3] |= (bits[i] & 1) << (7 - (i & 7));
  }
  return out;
}

function bytesToBits(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length * 8);
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) out[i * 8 + b] = (bytes[i] >> (7 - b)) & 1;
  }
  return out;
}

export interface EmbedResult {
  bitsUsed: number;
  capacityBits: number;
  headerBytes: number;
}

export function embedIntoPixels(
  data: Uint8Array,
  payload: Uint8Array,
  flags: number
): EmbedResult {
  const header = new Uint8Array(HEADER_LEN);
  header[0] = MAGIC[0];
  header[1] = MAGIC[1];
  header[2] = MAGIC[2];
  header[3] = MAGIC[3];
  header[4] = SB_VERSION;
  header[5] = flags;
  const len = payload.length;
  header[6] = (len >>> 24) & 0xff;
  header[7] = (len >>> 16) & 0xff;
  header[8] = (len >>> 8) & 0xff;
  header[9] = len & 0xff;

  const container = new Uint8Array(HEADER_LEN + len);
  container.set(header, 0);
  container.set(payload, HEADER_LEN);

  const bits = bytesToBits(container);
  const cap = capacityBits(data.length);
  if (bits.length > cap) {
    throw new LsbError(
      'CAPACITY_EXCEEDED',
      `payload needs ${bits.length} bits, carrier offers ${cap}`
    );
  }

  let bi = 0;
  const pixelCount = Math.floor(data.length / 4);
  outer: for (let p = 0; p < pixelCount; p++) {
    const base = p * 4;
    for (let c = 0; c < 3; c++) {
      const bit = bits[bi];
      data[base + c] = (data[base + c] & 0xfe) | bit;
      bi++;
      if (bi >= bits.length) break outer;
    }
  }
  return { bitsUsed: bits.length, capacityBits: cap, headerBytes: HEADER_LEN };
}

export interface ExtractedBits {
  version: number;
  flags: number;
  payload: Uint8Array;
  bitsUsed: number;
}

export function extractFromPixels(data: Uint8Array): ExtractedBits {
  const cap = capacityBits(data.length);
  if (cap < HEADER_BITS) throw new LsbError('TOO_SMALL', 'carrier has no room for an SBV2 header');
  const headBits = new Uint8Array(HEADER_BITS);
  for (let i = 0; i < HEADER_BITS; i++) headBits[i] = getBit(data, i);
  const head = bitsToBytes(headBits);
  if (head[0] !== MAGIC[0] || head[1] !== MAGIC[1] || head[2] !== MAGIC[2] || head[3] !== MAGIC[3]) {
    throw new LsbError('NOT_STEGO', 'no SBV2 container in the LSB plane');
  }
  const version = head[4];
  if (version !== SB_VERSION) throw new LsbError('BAD_VERSION', `container v${version} unsupported`);
  const flags = head[5];
  if (flags > 2) throw new LsbError('BAD_FLAGS', `container cipher id ${flags} unsupported`);
  const len = ((head[6] << 24) | (head[7] << 16) | (head[8] << 8) | head[9]) >>> 0;
  if (len === 0 || len > 32 * 1024 * 1024) throw new LsbError('BAD_LENGTH', `declared payload ${len} bytes`);
  const bits = HEADER_BITS + len * 8;
  if (bits > cap) throw new LsbError('TRUNCATED', 'carrier was resized or recompressed lossily');
  const all = new Uint8Array(bits);
  for (let i = 0; i < bits; i++) all[i] = getBit(data, i);
  const payload = bitsToBytes(all).slice(HEADER_LEN, HEADER_LEN + len);
  return { version, flags, payload, bitsUsed: bits };
}

/** Randomize every RGB LSB (destroys any hidden payload + low-entropy artifacts). */
export function randomizeLsb(data: Uint8Array): number {
  let touched = 0;
  const pixelCount = Math.floor(data.length / 4);
  let pool = crypto.getRandomValues(new Uint8Array(65536));
  let pi = 0;
  for (let p = 0; p < pixelCount; p++) {
    const base = p * 4;
    for (let c = 0; c < 3; c++) {
      if (pi >= pool.length) {
        pool = crypto.getRandomValues(new Uint8Array(65536));
        pi = 0;
      }
      data[base + c] = (data[base + c] & 0xfe) | (pool[pi++] & 1);
      touched++;
    }
  }
  return touched;
}

export function pixelDiffStats(orig: Uint8Array, mod: Uint8Array): { changed: number; mse: number; psnr: number } {
  const n = Math.min(orig.length, mod.length);
  let changed = 0;
  let sq = 0;
  let counted = 0;
  for (let i = 0; i < n; i++) {
    if ((i & 3) === 3) continue; // skip alpha
    counted++;
    if (orig[i] !== mod[i]) changed++;
    const d = orig[i] - mod[i];
    sq += d * d;
  }
  const mse = counted ? sq / counted : 0;
  const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);
  return { changed, mse, psnr };
}
