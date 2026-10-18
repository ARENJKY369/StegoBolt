'use client';

/**
 * WebAuthn (Touch ID / Windows Hello / fingerprint) — a local unlock gesture
 * that releases the device-wrapped AES key living in this browser profile only.
 * No challenge ever leaves the page: the relying party id is the local origin.
 *
 * Assertions are CRYPTOGRAPHICALLY VERIFIED (not merely trusted): registration
 * stores the credential's COSE public key (SPKI when the browser exposes
 * getPublicKey(), otherwise parsed out of the attestation CBOR), and unlock
 * verifies the authenticator's ECDSA/RSA signature over
 * `authenticatorData || SHA-256(clientDataJSON)` plus the clientData type /
 * challenge / origin binding. Unlock fails closed if the key or signature is
 * missing, so a crafted JS caller cannot fake a biometric approval.
 */

export function webauthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof PublicKeyCredential !== 'undefined' &&
    !!navigator.credentials &&
    (!window.PublicKeyCredential || typeof window.PublicKeyCredential === 'function')
  );
}

export async function isUserVerifyingPlatform(): Promise<boolean> {
  if (!webauthnSupported()) return false;
  try {
    const avail = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return !!avail;
  } catch {
    return false;
  }
}

function challengeBytes(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32));
}

/* ------------------------------------------------------------------ */
/* encoding helpers                                                    */
/* ------------------------------------------------------------------ */

function b64urlFromBytes(bytes: Uint8Array): string {
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesFromB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/**
 * WebAuthn ES256 signatures are ASN.1/DER (`SEQUENCE { r INTEGER, s INTEGER }`)
 * while WebCrypto's ECDSA verify expects the raw fixed-width `r || s` form.
 */
export function derToRawEcdsa(der: Uint8Array, partLen = 32): Uint8Array<ArrayBuffer> | null {
  try {
    if (der[0] !== 0x30) return null;
    let pos = 2 + (der[1] & 0x80 ? der[1] & 0x7f : 0) > der.length ? 0 : 2 + (der[1] & 0x80 ? der[1] & 0x7f : 0);
    // Short-form length only for the outer sequence (sig is < 128+8 bytes).
    pos = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
    const readInt = (): Uint8Array<ArrayBuffer> | null => {
      if (der[pos++] !== 0x02) return null;
      let len = der[pos++];
      if (len & 0x80) return null; // integers here are always short-form
      let value = der.slice(pos, pos + len);
      pos += len;
      // Strip leading zero padding, then left-pad to partLen.
      let start = 0;
      while (start < value.length - 1 && value[start] === 0) start++;
      value = value.slice(start);
      if (value.length > partLen) return null;
      const padded = new Uint8Array(partLen);
      padded.set(value, partLen - value.length);
      return padded;
    };
    const r = readInt();
    const s = readInt();
    if (!r || !s) return null;
    const raw = new Uint8Array(partLen * 2);
    raw.set(r, 0);
    raw.set(s, partLen);
    return raw;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* stored public keys (public material only — safe in localStorage)    */
/* ------------------------------------------------------------------ */

interface StoredKey {
  alg: number; // COSE alg: -7 ES256, -257 RS256
  format: 'spki' | 'jwk';
  key: string; // base64 (spki) or JSON (jwk)
}

function pkStoreKey(credIdB64: string): string {
  return `sb.webauthn.pk.v1:${credIdB64}`;
}

function savePubKey(credIdB64: string, rec: StoredKey): void {
  try {
    localStorage.setItem(pkStoreKey(credIdB64), JSON.stringify(rec));
  } catch {
    /* storage full/blocked — unlock will fail closed until re-enrolled */
  }
}

function loadPubKey(credIdB64: string): StoredKey | null {
  try {
    const raw = localStorage.getItem(pkStoreKey(credIdB64));
    if (!raw) return null;
    const rec = JSON.parse(raw) as StoredKey;
    return rec && rec.key && rec.alg ? rec : null;
  } catch {
    return null;
  }
}

export function forgetPubKey(credIdB64: string): void {
  try {
    localStorage.removeItem(pkStoreKey(credIdB64));
  } catch {
    /* ignore */
  }
}

async function importStoredKey(rec: StoredKey): Promise<CryptoKey> {
  if (rec.format === 'spki') {
    return crypto.subtle.importKey(
      'spki',
      bytesFromB64(rec.key),
      rec.alg === -257 ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } : { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }
  const jwk = JSON.parse(rec.key) as JsonWebKey;
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    rec.alg === -257 ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } : { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

/* ------------------------------------------------------------------ */
/* minimal CBOR / COSE extraction (attestation fallback path)          */
/* ------------------------------------------------------------------ */

interface CoseKey {
  jwk: JsonWebKey;
  alg: number;
}

/** Tiny CBOR decoder — just enough for the attestation map + COSE key map. */
function cborDecode(buf: Uint8Array, pos: number): { value: unknown; next: number } | null {
  if (pos >= buf.length) return null;
  const ib = buf[pos++];
  const major = ib >> 5;
  let info = ib & 0x1f;
  let arg: number;
  if (info < 24) arg = info;
  else if (info === 24) arg = buf[pos++];
  else if (info === 25) arg = (buf[pos] << 8) | buf[pos + 1], (pos += 2);
  else if (info === 26) arg = ((buf[pos] << 24) >>> 0) + (buf[pos + 1] << 16) + (buf[pos + 2] << 8) + buf[pos + 3], (pos += 4);
  else return null; // indefinite/large — not needed here

  switch (major) {
    case 0:
      return { value: arg, next: pos };
    case 1:
      return { value: -1 - arg, next: pos };
    case 2:
      return { value: buf.slice(pos, pos + arg), next: pos + arg };
    case 3:
      return { value: new TextDecoder().decode(buf.slice(pos, pos + arg)), next: pos + arg };
    case 4: {
      const arr: unknown[] = [];
      for (let i = 0; i < arg; i++) {
        const item = cborDecode(buf, pos);
        if (!item) return null;
        arr.push(item.value);
        pos = item.next;
      }
      return { value: arr, next: pos };
    }
    case 5: {
      const map = new Map<unknown, unknown>();
      for (let i = 0; i < arg; i++) {
        const k = cborDecode(buf, pos);
        if (!k) return null;
        const v = cborDecode(buf, k.next);
        if (!v) return null;
        map.set(k.value, v.value);
        pos = v.next;
      }
      return { value: map, next: pos };
    }
    case 7:
      return { value: info === 20 ? false : info === 21 ? true : info === 22 ? null : arg, next: pos };
    default:
      return null;
  }
}

/** Pull the credential COSE public key out of an attestationObject. */
function coseFromAttestation(attObj: Uint8Array): CoseKey | null {
  const top = cborDecode(attObj, 0);
  if (!top || !(top.value instanceof Map)) return null;
  const authData = top.value.get('authData');
  if (!(authData instanceof Uint8Array)) return null;
  // authData: rpIdHash(32) flags(1) counter(4) [attestedCredentialData]
  if (authData.length < 37) return null;
  const flags = authData[32];
  if ((flags & 0x40) === 0) return null;
  let pos = 37 + 16; // + aaguid
  if (pos + 2 > authData.length) return null;
  const credIdLen = (authData[pos] << 8) | authData[pos + 1];
  pos += 2 + credIdLen;
  const key = cborDecode(authData, pos);
  if (!key || !(key.value instanceof Map)) return null;
  const m = key.value as Map<number, unknown>;
  const kty = m.get(1);
  const alg = m.get(3);
  if (typeof alg !== 'number') return null;
  if (kty === 2) {
    // EC2: -1 crv, -2 x, -3 y
    const crv = m.get(-1);
    const x = m.get(-2);
    const y = m.get(-3);
    if (crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) return null;
    return {
      alg,
      jwk: { kty: 'EC', crv: 'P-256', x: b64urlFromBytes(x), y: b64urlFromBytes(y), ext: true },
    };
  }
  if (kty === 3) {
    // RSA: -1 n, -2 e
    const n = m.get(-1);
    const e = m.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) return null;
    return { alg, jwk: { kty: 'RSA', n: b64urlFromBytes(n), e: b64urlFromBytes(e), ext: true } };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* registration / assertion                                            */
/* ------------------------------------------------------------------ */

export async function registerBiometric(displayName: string): Promise<string> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: challengeBytes(),
      rp: { name: 'StegoBolt — Zero-Knowledge Vault', id: window.location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: displayName || 'local-user',
        displayName: displayName || 'StegoBolt Local User',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      timeout: 60_000,
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'preferred',
      },
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Biometric registration was cancelled');
  const rawId = new Uint8Array(cred.rawId);
  let bin = '';
  rawId.forEach((b) => (bin += String.fromCharCode(b)));
  const credIdB64 = btoa(bin);

  // Persist the credential PUBLIC KEY so assertions can be verified later.
  const resp = cred.response as AuthenticatorAttestationResponse & {
    getPublicKey?: () => ArrayBuffer | null;
    getPublicKeyAlgorithm?: () => number;
  };
  let stored: StoredKey | null = null;
  if (typeof resp.getPublicKey === 'function') {
    const spki = resp.getPublicKey();
    const alg = typeof resp.getPublicKeyAlgorithm === 'function' ? resp.getPublicKeyAlgorithm() : -7;
    if (spki) {
      let s = '';
      new Uint8Array(spki).forEach((b) => (s += String.fromCharCode(b)));
      stored = { alg, format: 'spki', key: btoa(s) };
    }
  }
  if (!stored) {
    const cose = coseFromAttestation(new Uint8Array(resp.attestationObject));
    if (cose) stored = { alg: cose.alg, format: 'jwk', key: JSON.stringify(cose.jwk) };
  }
  if (!stored) {
    // Fail closed: without a stored public key we cannot verify assertions,
    // so refuse to enroll rather than degrade to gesture-only.
    throw new Error('Authenticator did not expose a verifiable public key — enrollment refused');
  }
  savePubKey(credIdB64, stored);
  return credIdB64;
}

export async function assertBiometric(credIdB64: string): Promise<boolean> {
  const stored = loadPubKey(credIdB64);
  if (!stored) return false; // fail closed — no key to verify against

  const challenge = challengeBytes();
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      timeout: 60_000,
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: bytesFromB64(credIdB64), transports: [] }],
    },
  })) as PublicKeyCredential | null;
  if (!assertion) return false;

  try {
    const resp = assertion.response as AuthenticatorAssertionResponse;
    const clientData = new Uint8Array(resp.clientDataJSON);
    const authData = new Uint8Array(resp.authenticatorData);
    const sigDer = new Uint8Array(resp.signature);

    // 1) clientData binding: type, challenge, origin.
    const client = JSON.parse(new TextDecoder().decode(clientData)) as { type?: string; challenge?: string; origin?: string };
    if (client.type !== 'webauthn.get') return false;
    if (client.challenge !== b64urlFromBytes(challenge)) return false;
    if (client.origin !== window.location.origin) return false;

    // 2) signature over authenticatorData || SHA-256(clientDataJSON).
    const clientHash = await sha256(clientData);
    const signedData = new Uint8Array(authData.length + clientHash.length);
    signedData.set(authData, 0);
    signedData.set(clientHash, authData.length);

    const key = await importStoredKey(stored);
    if (stored.alg === -257) {
      // RS256: PKCS#1 v1.5 over SHA-256.
      return crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sigDer, signedData);
    }
    // ES256: DER-encoded signature must be normalized to raw r||s.
    const raw = derToRawEcdsa(sigDer, 32);
    if (!raw) return false;
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, signedData);
  } catch {
    return false;
  }
}
