'use client';

/**
 * WebAuthn (Touch ID / Windows Hello / fingerprint) — used purely as a local
 * unlock gesture. A successful assertion releases the device-wrapped AES key
 * that lives in this browser profile only. No challenge ever leaves the page:
 * the relying party id is the local origin itself.
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
  return btoa(bin);
}

export async function assertBiometric(credIdB64: string): Promise<boolean> {
  let bin = atob(credIdB64);
  const rawId = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) rawId[i] = bin.charCodeAt(i);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: challengeBytes(),
      timeout: 60_000,
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: rawId, transports: [] }],
    },
  });
  return !!assertion;
}
