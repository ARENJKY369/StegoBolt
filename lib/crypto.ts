'use client';

/**
 * Zero-knowledge crypto core — 100% Web Crypto API, main-thread + worker friendly.
 * No key material, hash or ciphertext is ever transmitted anywhere.
 */

export const textEnc = new TextEncoder();
export const textDec = new TextDecoder();

export const PBKDF2_ITERATIONS = 100_000;

export const CIPHER = {
  RAW: 0,
  AES_256_GCM: 1,
  AES_256_CTR: 2,
} as const;
export type CipherId = (typeof CIPHER)[keyof typeof CIPHER];

export const CIPHER_LABELS: Record<number, string> = {
  [CIPHER.RAW]: 'None (raw LSB payload)',
  [CIPHER.AES_256_GCM]: 'AES-256-GCM',
  [CIPHER.AES_256_CTR]: 'AES-256-CTR',
};

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/* ---------- base64 / hex ---------- */

export function toB64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...Array.from(bytes.subarray(i, i + chunk)));
  }
  return btoa(bin);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i++) out += data[i].toString(16).padStart(2, '0');
  return out;
}

/* ---------- hashing / KDF ---------- */

export async function sha256Hex(data: ArrayBuffer | Uint8Array | Blob): Promise<string> {
  let buf: ArrayBuffer;
  if (data instanceof Blob) buf = await data.arrayBuffer();
  else if (data instanceof Uint8Array) buf = data.slice().buffer as ArrayBuffer;
  else buf = data;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return toHex(new Uint8Array(digest));
}

export async function deriveAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
  extractable: boolean = false
): Promise<CryptoKey> {
  // Payload keys are non-extractable by default; the vault session key opts in
  // to `extractable: true` only so it can be wrapped for biometric unlock.
  const iter = Math.max(1, Math.floor(iterations));
  const base = await crypto.subtle.importKey('raw', textEnc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: iter, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  );
}

/* ---------- low level AE ciphers ---------- */

export async function gcmEncrypt(key: CryptoKey, iv: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, plain as BufferSource);
  return new Uint8Array(ct);
}

export async function gcmDecrypt(key: CryptoKey, iv: Uint8Array, cipher: Uint8Array): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, cipher as BufferSource);
  return new Uint8Array(pt);
}

export async function ctrEncrypt(key: CryptoKey, counter: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: counter as BufferSource, length: 128 },
    key,
    plain as BufferSource
  );
  return new Uint8Array(ct);
}

export async function ctrDecrypt(key: CryptoKey, counter: Uint8Array, cipher: Uint8Array): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: counter as BufferSource, length: 128 },
    key,
    cipher as BufferSource
  );
  return new Uint8Array(pt);
}

/* ---------- payload sealing (used by Hide / Extract tabs) ----------
 * Sealed layout inside the LSB stream:
 *   [ salt (16) ][ iv (12 GCM/raw, 16 CTR) ][ body… ]
 * body = ciphertext||GCM tag when encrypted, plaintext when RAW.
 */

export function ivLenFor(cipher: number): number {
  return cipher === CIPHER.AES_256_CTR ? 16 : 12;
}

/** Reject anything that is not a known cipher id (container headers are untrusted). */
export function assertKnownCipher(cipher: number): void {
  if (cipher !== CIPHER.RAW && cipher !== CIPHER.AES_256_GCM && cipher !== CIPHER.AES_256_CTR) {
    throw new Error('BAD_FLAGS');
  }
}

export async function sealPayload(
  plain: Uint8Array,
  cipher: number,
  passphrase: string,
  sessionSalt?: Uint8Array
): Promise<Uint8Array> {
  assertKnownCipher(cipher);
  if (cipher === CIPHER.RAW) {
    const out = new Uint8Array(16 + 12 + plain.length);
    crypto.getRandomValues(out.subarray(0, 28)); // decoy noise so raw payloads still look random
    out.set(plain, 28);
    return out;
  }
  const salt = sessionSalt ?? randomBytes(16);
  const ivLen = ivLenFor(cipher);
  const iv = randomBytes(ivLen);
  const key = await deriveAesKey(passphrase, salt);
  const body =
    cipher === CIPHER.AES_256_CTR
      ? await ctrEncrypt(key, iv, plain)
      : await gcmEncrypt(key, iv, plain);
  const out = new Uint8Array(16 + ivLen + body.length);
  out.set(salt, 0);
  out.set(iv, 16);
  out.set(body, 16 + ivLen);
  return out;
}

export async function openPayload(
  sealed: Uint8Array,
  cipher: number,
  passphrase: string
): Promise<Uint8Array> {
  assertKnownCipher(cipher);
  if (cipher === CIPHER.RAW) {
    return sealed.subarray(28);
  }
  const ivLen = ivLenFor(cipher);
  if (sealed.length < 16 + ivLen + 1) throw new Error('TRUNCATED_PAYLOAD');
  const salt = sealed.subarray(0, 16);
  const iv = sealed.subarray(16, 16 + ivLen);
  const body = sealed.subarray(16 + ivLen);
  const key = await deriveAesKey(passphrase, salt);
  if (cipher === CIPHER.AES_256_CTR) return await ctrDecrypt(key, iv, body);
  return await gcmDecrypt(key, iv, body); // throws OperationError on tamper / wrong pass
}

/* ---------- master-key wrapping (biometric device binding) ---------- */

export async function exportKeyRaw(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}

export async function importAesKeyRaw(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}

export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const b of buffers) {
    try {
      b?.fill(0);
    } catch {
      /* detached buffer — already gone */
    }
  }
}
