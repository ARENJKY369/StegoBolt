/**
 * Carrier types shared by every workspace operation.  The Java engine is the
 * implementation for every kind; the browser deliberately implements only
 * image carriers locally.
 */
export type CarrierKind = 'image' | 'audio' | 'video' | 'pdf' | 'docx' | 'text' | 'pcap' | 'other';

export const CARRIER_ACCEPT = [
  // Images
  'image/png',
  'image/bmp',
  'image/webp',
  'image/gif',
  'image/tiff',
  'image/jpeg',
  // Audio
  'audio/wav',
  'audio/x-wav',
  'audio/flac',
  'audio/x-flac',
  // Video
  'video/mp4',
  'video/x-matroska',
  'video/x-msvideo',
  // Documents
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  // Text and source code
  'text/plain',
  'text/markdown',
  'text/javascript',
  'application/javascript',
  'application/json',
  'text/csv',
  'text/x-java-source',
  'text/x-c',
  'text/x-c++src',
  'text/x-python',
  // Capture files are often reported as application/octet-stream, so their
  // extensions are included explicitly below as well.
  '.png,.bmp,.webp,.gif,.tif,.tiff,.jpg,.jpeg',
  '.wav,.flac',
  '.mp4,.mkv,.avi',
  '.pdf,.docx',
  '.txt,.md,.java,.js,.ts,.c,.cpp,.h,.hpp,.py,.json,.csv',
  '.pcap,.pcapng',
].join(',');

/** Extensions accepted by the product, without the leading dot. */
export const SUPPORTED_EXTENSIONS = new Set([
  'png',
  'bmp',
  'webp',
  'gif',
  'tif',
  'tiff',
  'jpg',
  'jpeg',
  'wav',
  'flac',
  'mp4',
  'mkv',
  'avi',
  'pdf',
  'docx',
  'txt',
  'md',
  'java',
  'js',
  'ts',
  'c',
  'cpp',
  'h',
  'hpp',
  'py',
  'json',
  'csv',
  'pcap',
  'pcapng',
]);

export function extensionOf(name: string): string {
  const last = name.split(/[\\/]/).pop() ?? name;
  const dot = last.lastIndexOf('.');
  return dot >= 0 ? last.slice(dot + 1).toLowerCase() : '';
}

export function kindForExtension(ext: string): CarrierKind {
  switch (ext.toLowerCase()) {
    case 'png':
    case 'bmp':
    case 'webp':
    case 'gif':
    case 'tif':
    case 'tiff':
    case 'jpg':
    case 'jpeg':
      return 'image';
    case 'wav':
    case 'flac':
      return 'audio';
    case 'mp4':
    case 'mkv':
    case 'avi':
      return 'video';
    case 'pdf':
      return 'pdf';
    case 'docx':
      return 'docx';
    case 'txt':
    case 'md':
    case 'java':
    case 'js':
    case 'ts':
    case 'c':
    case 'cpp':
    case 'h':
    case 'hpp':
    case 'py':
    case 'json':
    case 'csv':
      return 'text';
    case 'pcap':
    case 'pcapng':
      return 'pcap';
    default:
      return 'other';
  }
}

export function kindForMime(mime: string): CarrierKind {
  const type = mime.toLowerCase().split(';', 1)[0];
  switch (type) {
    case 'image/png':
    case 'image/bmp':
    case 'image/webp':
    case 'image/gif':
    case 'image/tiff':
    case 'image/jpeg':
      return 'image';
    case 'audio/wav':
    case 'audio/x-wav':
    case 'audio/flac':
    case 'audio/x-flac':
      return 'audio';
    case 'video/mp4':
    case 'video/x-matroska':
    case 'video/x-msvideo':
      return 'video';
    case 'application/pdf':
      return 'pdf';
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
      return 'docx';
    case 'text/plain':
    case 'text/markdown':
    case 'text/javascript':
    case 'application/javascript':
    case 'application/json':
    case 'text/csv':
    case 'text/x-java-source':
    case 'text/x-c':
    case 'text/x-c++src':
    case 'text/x-python':
      return 'text';
    default:
      return 'other';
  }
}

export function kindForFile(name: string, mime: string): CarrierKind {
  const byExtension = kindForExtension(extensionOf(name));
  return byExtension !== 'other' ? byExtension : kindForMime(mime);
}

export function isSupportedCarrier(name: string, mime: string): boolean {
  const ext = extensionOf(name);
  // A known extension is the strongest signal because browsers commonly label
  // FLAC, PCAP, DOCX and source files as application/octet-stream.
  if (ext) return SUPPORTED_EXTENSIONS.has(ext);
  return kindForMime(mime) !== 'other';
}

export function mediumLabel(kind: CarrierKind): string {
  switch (kind) {
    case 'image':
      return 'Image';
    case 'audio':
      return 'Audio';
    case 'video':
      return 'Video';
    case 'pdf':
    case 'docx':
      return 'Document';
    case 'text':
      return 'Text/code';
    case 'pcap':
      return 'Network capture';
    default:
      return 'This file type';
  }
}

/** Actionable local-mode message. Keep this specific rather than exposing a
 * browser exception or the engine's generic 500 wording. */
export function localEngineRequired(kind: CarrierKind, operation: string): string {
  return `${mediumLabel(kind)} ${operation} needs the Java engine — flip Settings → Java Engine to “Java engine” and start the engine.`;
}

/** Capacity guidance shown before an engine hide operation. */
export function capacityHint(kind: CarrierKind, name: string): string {
  const ext = extensionOf(name);
  if (kind === 'pcap') {
    return 'PCAP stores about one bit per IPv4 packet, so a 1 KB payload needs roughly 80 packets plus encrypted-container overhead.';
  }
  if (kind === 'video' && (ext === 'mp4' || ext === 'mkv')) {
    return 'MP4/MKV use container padding, so playback stays unchanged but the downloaded file grows by the hidden-container size.';
  }
  if (kind === 'video') {
    return 'AVI uses frame data; keep the original uncompressed carrier and avoid re-encoding after embedding.';
  }
  if (kind === 'image' && (ext === 'jpg' || ext === 'jpeg')) {
    return 'JPEG is lossy: later saves or recompression can destroy hidden data. Prefer PNG, BMP, TIFF or WebP when possible.';
  }
  if (kind === 'audio') {
    return 'WAV uses the PCM sample noise floor; FLAC uses structural padding. Avoid lossy audio conversion after embedding.';
  }
  if (kind === 'text') {
    return 'Text uses invisible characters by default. Keep the file as UTF-8 and do not normalize or strip whitespace afterward.';
  }
  if (kind === 'pdf' || kind === 'docx') {
    return 'The engine adds an invisible structural part while leaving the visible document unchanged.';
  }
  return 'Capacity is reported by the Java engine after it identifies the carrier format.';
}

export function vercelBodyLimitWarning(engineUrl: string, fileSize?: number): string | null {
  let host = '';
  try {
    host = new URL(engineUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host.endsWith('.vercel.app') && host !== 'vercel.app') return null;
  const limit = '4.5 MB';
  if (fileSize != null && fileSize > 4_500_000) {
    return `Vercel limits request and response bodies to ${limit}; this carrier is too large for that hosting path.`;
  }
  return `Vercel limits request and response bodies to ${limit}; use a smaller carrier or a direct Java engine host.`;
}
