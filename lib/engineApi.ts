/**
 * Typed browser client for the StegoBolt Engine v2.0 (Java 17 / Spring Boot
 * 3.x). The UI delegates raw File objects directly to this client; it never
 * writes an upload, response or recovered payload to a server-side temp file.
 */

export const ENGINE_BASE = 'http://localhost:8080/api/v1/stego';

let engineBase = ENGINE_BASE;

/**
 * Accept either http://host:8080 or the full /api/v1/stego endpoint. Keeping
 * this in one place means Settings and every operation use the same target.
 */
export function setEngineBase(url: string): void {
  const trimmed = (url ?? '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    engineBase = ENGINE_BASE;
    return;
  }
  engineBase = /\/api\/v1\/stego$/.test(trimmed) ? trimmed : `${trimmed}/api/v1/stego`;
}

export function getEngineBase(): string {
  return engineBase;
}

/** The Java DTOs use title-case labels in JSON. */
export type EngineMedium = 'Image' | 'Audio' | 'Video' | 'Document' | 'Text' | 'Network';

function normalizeMedium(value: unknown): EngineMedium {
  switch (String(value ?? '').toLowerCase()) {
    case 'image':
      return 'Image';
    case 'audio':
      return 'Audio';
    case 'video':
      return 'Video';
    case 'document':
    case 'documents':
      return 'Document';
    case 'text':
    case 'text/code':
      return 'Text';
    case 'network':
      return 'Network';
    default:
      return 'Image';
  }
}

export interface CapacityReport {
  medium: EngineMedium;
  carrierBytes: number;
  capacityBits: number;
  /** Maximum plaintext payload bytes after the SBV2-J header and GCM tag. */
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
  psnrDb?: number | null;
  sha256: string;
}

export interface ExtractResponse {
  medium: EngineMedium;
  found: boolean;
  payloadText?: string | null;
  payloadBase64?: string | null;
  payloadBytes?: number;
  sha256?: string | null;
}

export interface ScanReport {
  medium: EngineMedium;
  carrierBytes: number;
  chiSquareStatistic: number;
  /** Pair-equalisation survival probability — rises with LSB replacement, not with texture. */
  chiSquareProbability: number;
  spaEmbeddingRatio: number;
  lsbOnesRatio: number;
  lsbEntropy: number;
  windowedEntropy: number;
  containerSignatureFound: boolean;
  threatScore: number;
  indicators: string[];
  exifTags?: string[];
  /** Calibrated verdict fields (present on engine v2.1+; older engines omit them). */
  level?: string;
  confidence?: string;
  summary?: string;
  analysisBasis?: string;
  /** False for media where LSB-plane statistics are not meaningful (documents, video, FLAC, text, PCAP). */
  sampleBased?: boolean;
  sampleSize?: number;
  verdict?: string;
}

export interface CleanResponse {
  medium: EngineMedium;
  originalBytes: number;
  cleanedBytes: number;
  exifTagsRemoved: number;
  lsbBitsReRandomized: number;
  changedBits: number;
  psnrDb?: number | null;
}

export interface EngineError {
  error?: string;
  message?: string;
}

function form(fields: Record<string, string | Blob | undefined>): FormData {
  const fd = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) fd.append(key, value);
  }
  return fd;
}

function normalizeCapacity(raw: CapacityReport): CapacityReport {
  return {
    medium: normalizeMedium(raw?.medium),
    carrierBytes: Number(raw?.carrierBytes ?? 0),
    capacityBits: Number(raw?.capacityBits ?? 0),
    capacityBytes: Math.max(0, Number(raw?.capacityBytes ?? 0)),
    maxPayloadTextChars: Math.max(0, Number(raw?.maxPayloadTextChars ?? 0)),
    details: raw?.details,
  };
}

function normalizeHide(raw: HideResponse): HideResponse {
  return {
    medium: normalizeMedium(raw?.medium),
    stegoFileName: String(raw?.stegoFileName ?? ''),
    stegoBytes: Number(raw?.stegoBytes ?? 0),
    payloadBytes: Number(raw?.payloadBytes ?? 0),
    capacityUsedBits: Number(raw?.capacityUsedBits ?? 0),
    psnrDb: raw?.psnrDb == null ? null : Number(raw.psnrDb),
    sha256: String(raw?.sha256 ?? ''),
  };
}

function normalizeExtract(raw: ExtractResponse): ExtractResponse {
  return {
    medium: normalizeMedium(raw?.medium),
    found: Boolean(raw?.found),
    payloadText: raw?.payloadText ?? null,
    payloadBase64: raw?.payloadBase64 ?? null,
    payloadBytes: raw?.payloadBytes == null ? 0 : Number(raw.payloadBytes),
    sha256: raw?.sha256 ?? null,
  };
}

function normalizeScan(raw: ScanReport): ScanReport {
  return {
    medium: normalizeMedium(raw?.medium),
    carrierBytes: Number(raw?.carrierBytes ?? 0),
    chiSquareStatistic: Number(raw?.chiSquareStatistic ?? 0),
    chiSquareProbability: Number(raw?.chiSquareProbability ?? 0),
    spaEmbeddingRatio: Number(raw?.spaEmbeddingRatio ?? 0),
    lsbOnesRatio: Number(raw?.lsbOnesRatio ?? 0),
    lsbEntropy: Number(raw?.lsbEntropy ?? 0),
    windowedEntropy: Number(raw?.windowedEntropy ?? 0),
    containerSignatureFound: Boolean(raw?.containerSignatureFound),
    threatScore: Number(raw?.threatScore ?? 0),
    indicators: Array.isArray(raw?.indicators) ? raw.indicators.map(String) : [],
    exifTags: Array.isArray(raw?.exifTags) ? raw.exifTags.map(String) : [],
    level: typeof raw?.level === 'string' ? raw.level.toUpperCase() : undefined,
    confidence: typeof raw?.confidence === 'string' ? raw.confidence.toUpperCase() : undefined,
    summary: typeof raw?.summary === 'string' ? raw.summary : undefined,
    analysisBasis: typeof raw?.analysisBasis === 'string' ? raw.analysisBasis : undefined,
    sampleBased: typeof raw?.sampleBased === 'boolean' ? raw.sampleBased : undefined,
    sampleSize: raw?.sampleSize == null ? undefined : Number(raw.sampleSize),
    verdict: typeof raw?.verdict === 'string' ? raw.verdict : undefined,
  };
}

function normalizeClean(raw: CleanResponse): CleanResponse {
  return {
    medium: normalizeMedium(raw?.medium),
    originalBytes: Number(raw?.originalBytes ?? 0),
    cleanedBytes: Number(raw?.cleanedBytes ?? 0),
    exifTagsRemoved: Number(raw?.exifTagsRemoved ?? 0),
    lsbBitsReRandomized: Number(raw?.lsbBitsReRandomized ?? 0),
    changedBits: Number(raw?.changedBits ?? 0),
    psnrDb: raw?.psnrDb == null ? null : Number(raw.psnrDb),
  };
}

async function responseError(res: Response, path: string): Promise<Error> {
  let detail = '';
  try {
    const body = (await res.json()) as Partial<EngineError>;
    detail = body.message ?? body.error ?? '';
  } catch {
    // The engine intentionally may return an empty body for an infrastructure
    // failure. Do not surface an HTML error page or a stack trace to the user.
  }
  const statusMessage: Record<number, string> = {
    400: 'The engine rejected the carrier or request fields.',
    405: 'This engine route only accepts POST requests.',
    415: 'The engine expects multipart/form-data with a carrier file.',
    413: 'The carrier exceeds the engine in-memory request limit.',
    500: 'The engine could not process this carrier. Check its format and the engine log without exposing the payload.',
  };
  return new Error(`Java engine ${path} failed (${res.status}): ${detail || statusMessage[res.status] || res.statusText || 'request rejected'}`);
}

async function post<T>(path: string, fd: FormData): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${engineBase}${path}`, { method: 'POST', body: fd });
  } catch {
    throw new Error(`Java engine is unreachable at ${engineBase}. Start the Java engine or switch Settings → Java Engine to “Local (in-browser)” for image carriers.`);
  }
  if (!res.ok) throw await responseError(res, path);
  try {
    return (await res.json()) as T;
  } catch {
    throw new Error(`Java engine ${path} returned an invalid JSON report.`);
  }
}

function reportHeader<T>(value: string | null, path: string, normalize: (raw: T) => T): T {
  if (!value) throw new Error(`Java engine ${path} completed without its X-StegoBolt-Report header.`);
  try {
    return normalize(JSON.parse(value) as T);
  } catch {
    throw new Error(`Java engine ${path} returned an invalid X-StegoBolt-Report header.`);
  }
}

function filenameFromDisposition(value: string | null): string | null {
  if (!value) return null;
  const encoded = value.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) {
    try {
      return decodeURIComponent(encoded.replace(/^"|"$/g, ''));
    } catch {
      return encoded.replace(/^"|"$/g, '');
    }
  }
  return value.match(/filename="?([^";]+)"?/i)?.[1] ?? null;
}

/** POST /capacity — report headroom before Hide is enabled. */
export async function capacity(cover: File): Promise<CapacityReport> {
  return normalizeCapacity(await post<CapacityReport>('/capacity', form({ cover })));
}

/** POST /hide — encrypt payload, embed it, and return the binary stego carrier. */
export async function hide(input: {
  cover: File;
  passphrase: string;
  payloadText?: string;
  payloadFile?: File;
}): Promise<{ report: HideResponse; stego: Blob; fileName: string | null }> {
  const fd = form({
    cover: input.cover,
    passphrase: input.passphrase,
    payload: input.payloadFile,
    payloadText: input.payloadText,
  });
  let res: Response;
  try {
    res = await fetch(`${engineBase}/hide`, { method: 'POST', body: fd });
  } catch {
    throw new Error(`Java engine is unreachable at ${engineBase}. Start the Java engine or switch to local mode.`);
  }
  if (!res.ok) throw await responseError(res, '/hide');
  const report = reportHeader<HideResponse>(res.headers.get('X-StegoBolt-Report'), '/hide', normalizeHide);
  return { report, stego: await res.blob(), fileName: filenameFromDisposition(res.headers.get('Content-Disposition')) };
}

/** POST /extract — recover and decrypt the hidden payload. */
export async function extract(cover: File, passphrase: string): Promise<ExtractResponse> {
  return normalizeExtract(await post<ExtractResponse>('/extract', form({ cover, passphrase })));
}

/** POST /scan — forensic scan for any supported medium. */
export async function scan(cover: File): Promise<ScanReport> {
  return normalizeScan(await post<ScanReport>('/scan', form({ cover })));
}

/** POST /clean — remove the hidden layer/metadata and return sanitized media. */
export async function clean(
  cover: File,
  randomizeLsb = true
): Promise<{ report: CleanResponse; cleaned: Blob; fileName: string | null }> {
  const fd = form({ cover, randomizeLsb: String(randomizeLsb) });
  let res: Response;
  try {
    res = await fetch(`${engineBase}/clean`, { method: 'POST', body: fd });
  } catch {
    throw new Error(`Java engine is unreachable at ${engineBase}. Start the Java engine or switch to local mode.`);
  }
  if (!res.ok) throw await responseError(res, '/clean');
  const report = reportHeader<CleanResponse>(res.headers.get('X-StegoBolt-Report'), '/clean', normalizeClean);
  return { report, cleaned: await res.blob(), fileName: filenameFromDisposition(res.headers.get('Content-Disposition')) };
}
