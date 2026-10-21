'use client';

import { extensionOf, kindForFile, type CarrierKind } from './mediums';

/**
 * Canvas-based codec. All pixel access happens via ImageData — the browser
 * never uploads anything (no <form> posts, no fetches).
 */

export interface DecodedPixels {
  width: number;
  height: number;
  /** RGBA byte grid (Uint8ClampedArray view over a plain Uint8Array buffer) */
  data: Uint8Array;
}

export async function decodeImageData(blob: Blob): Promise<DecodedPixels> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    // Safari <15 fallback via HTMLImageElement
    bitmap = await new Promise<ImageBitmap>((resolve, reject) => {
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        const c = document.createElement('canvas');
        c.width = img.naturalWidth;
        c.height = img.naturalHeight;
        c.getContext('2d')!.drawImage(img, 0, 0);
        c.toBlob(async (b) => {
          URL.revokeObjectURL(url);
          if (b) resolve(await createImageBitmap(b));
          else reject(new Error('IMAGE_DECODE_FAILED'));
        });
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error('IMAGE_DECODE_FAILED'));
      };
      img.src = url;
    });
  }
  const width = bitmap.width;
  const height = bitmap.height;
  if (!width || !height) throw new Error('IMAGE_DECODE_FAILED');
  // Decompression-bomb guard: a crafted PNG can declare absurd dimensions.
  if (width * height > 64_000_000) {
    bitmap.close?.();
    throw new Error('IMAGE_TOO_LARGE');
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('CANVAS_UNAVAILABLE');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close?.();
  const img = ctx.getImageData(0, 0, width, height);
  // copy into a detachable Uint8Array (ImageData's buffer is clamped + owned by canvas)
  const data = new Uint8Array(img.data.byteLength);
  data.set(img.data);
  return { width, height, data };
}

export async function encodeBlob(width: number, height: number, data: Uint8Array, mime: 'image/png' | 'image/jpeg', quality = 0.95): Promise<Blob> {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('CANVAS_UNAVAILABLE');
  const clamped = new Uint8ClampedArray(data);
  ctx.putImageData(new ImageData(clamped, width, height), 0, 0);
  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error('CANVAS_ENCODE_FAILED'))),
      mime,
      mime === 'image/jpeg' ? quality : undefined
    );
  });
}

export interface ProbeInfo {
  kind: CarrierKind;
  type: string;
  width?: number;
  height?: number;
}

export async function probeFile(file: File): Promise<ProbeInfo> {
  const type = file.type || guessType(file.name);
  const kind = kindForFile(file.name, type);

  // Keep the browser probe useful even when a browser reports a generic MIME
  // type. The extension list is the product allow-list and is also what the
  // dropzone advertises to file pickers.
  if (kind === 'image') {
    try {
      const bmp = await createImageBitmap(file);
      const w = bmp.width;
      const h = bmp.height;
      bmp.close?.();
      return { kind, type, width: w, height: h };
    } catch {
      return { kind, type };
    }
  }
  return { kind, type };
}

function guessType(name: string): string {
  switch (extensionOf(name)) {
    case 'png':
      return 'image/png';
    case 'jpg':
    case 'jpeg':
      return 'image/jpeg';
    case 'bmp':
      return 'image/bmp';
    case 'webp':
      return 'image/webp';
    case 'gif':
      return 'image/gif';
    case 'tif':
    case 'tiff':
      return 'image/tiff';
    case 'wav':
      return 'audio/wav';
    case 'flac':
      return 'audio/flac';
    case 'mp4':
      return 'video/mp4';
    case 'mkv':
      return 'video/x-matroska';
    case 'avi':
      return 'video/x-msvideo';
    case 'pdf':
      return 'application/pdf';
    case 'docx':
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    case 'json':
      return 'application/json';
    case 'js':
      return 'text/javascript';
    case 'csv':
      return 'text/csv';
    case 'md':
      return 'text/markdown';
    case 'java':
      return 'text/x-java-source';
    case 'c':
    case 'h':
    case 'cpp':
    case 'hpp':
      return 'text/x-c';
    case 'py':
      return 'text/x-python';
    case 'txt':
      return 'text/plain';
    case 'pcap':
    case 'pcapng':
      return 'application/vnd.tcpdump.pcap';
    default:
      return 'application/octet-stream';
  }
}

export function extForMime(mime: string): string {
  return (
    {
      'image/png': 'png',
      'image/jpeg': 'jpg',
      'image/webp': 'webp',
      'image/bmp': 'bmp',
    }[mime] ?? 'img'
  );
}
