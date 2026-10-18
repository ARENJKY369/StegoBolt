/**
 * Typed client for the StegoBolt Engine v2.0 — the 100% Java (Spring Boot 3.x)
 * in-memory backend running at http://localhost:8080/api/v1/stego.
 *
 * The browser workspace stays zero-knowledge by default (local Web Crypto path).
 * This module is the delegation layer for operators who run the Java engine
 * alongside the UI: every call is multipart/form-data, and the engine guarantees
 * zero-disk processing (volatile RAM only, explicit buffer wiping, zero payload
 * logging) on its side.
 */

export const ENGINE_BASE = 'http://localhost:8080/api/v1/stego';

export type EngineMedium =
  | 'IMAGE'
  | 'AUDIO'
  | 'VIDEO'
  | 'DOCUMENT'
  | 'TEXT'
  | 'NETWORK';

export interface CapacityReport {
  medium: EngineMedium;
  carrierBytes: number;
  capacityBits: number;
  capacityBytes: number;
  maxPayloadTextChars: number;
  details?: string;
}

export interface HideResponse {
  medium: EngineMedium;
  stegoFileName: string;
  stegoBytes: number;
  payloadBytes: number;
  capacityUsedBits: number;
  psnrDb?: number;
  sha256: string;
}

export interface ExtractResponse {
  medium: EngineMedium;
  found: boolean;
  payloadText?: string;
  payloadBase64?: string;
  payloadBytes?: number;
  sha256?: string;
}

export interface ScanReport {
  medium: EngineMedium;
  carrierBytes: number;
  chiSquareStatistic: number;
  chiSquareProbability: number;
  spaEmbeddingRatio: number;
  lsbOnesRatio: number;
  lsbEntropy: number;
  containerSignatureFound: boolean;
  threatScore: number;
  indicators: string[];
  exifTags?: string[];
}

export interface CleanResponse {
  medium: EngineMedium;
  originalBytes: number;
  cleanedBytes: number;
  exifTagsRemoved: number;
  lsbBitsReRandomized: number;
  changedBits: number;
  psnrDb?: number;
}

export interface EngineError {
  error: string;
  message: string;
}

function form(fields: Record<string, string | Blob | undefined>): FormData {
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) fd.append(k, v);
  }
  return fd;
}

async function post<T>(path: string, fd: FormData): Promise<T> {
  const res = await fetch(`${ENGINE_BASE}${path}`, { method: 'POST', body: fd });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = (await res.json()) as Partial<EngineError>;
      detail = err.message ?? err.error ?? detail;
    } catch {
      /* zero-log engine may return an empty body */
    }
    throw new Error(`Engine ${path} failed (${res.status}): ${detail}`);
  }
  return (await res.json()) as T;
}

/** POST /capacity — how much secret data this carrier can hold. */
export function capacity(cover: File): Promise<CapacityReport> {
  return post('/capacity', form({ cover }));
}

/** POST /hide — encrypt payload with passphrase, embed into cover, return stego media. */
export async function hide(input: {
  cover: File;
  passphrase: string;
  payloadText?: string;
  payloadFile?: File;
}): Promise<{ report: HideResponse; stego: Blob }> {
  const fd = form({
    cover: input.cover,
    passphrase: input.passphrase,
    payload: input.payloadFile,
    payloadText: input.payloadText,
  });
  const res = await fetch(`${ENGINE_BASE}/hide`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`Engine /hide failed (${res.status})`);
  const report = JSON.parse(res.headers.get('X-StegoBolt-Report') ?? '{}') as HideResponse;
  return { report, stego: await res.blob() };
}

/** POST /extract — recover and decrypt the hidden payload. */
export function extract(cover: File, passphrase: string): Promise<ExtractResponse> {
  return post('/extract', form({ cover, passphrase }));
}

/** POST /scan — forensic steganalysis (chi-square, SPA, entropy, signatures). */
export function scan(cover: File): Promise<ScanReport> {
  return post('/scan', form({ cover }));
}

/** POST /clean — strip metadata + re-randomize LSB noise floor, return sanitized media. */
export async function clean(cover: File, randomizeLsb = true): Promise<{ report: CleanResponse; cleaned: Blob }> {
  const fd = form({ cover, randomizeLsb: String(randomizeLsb) });
  const res = await fetch(`${ENGINE_BASE}/clean`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`Engine /clean failed (${res.status})`);
  const report = JSON.parse(res.headers.get('X-StegoBolt-Report') ?? '{}') as CleanResponse;
  return { report, cleaned: await res.blob() };
}
