'use client';

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
  kind: 'image' | 'audio' | 'pdf' | 'text' | 'other';
  type: string;
  width?: number;
  height?: number;
}

export async function probeFile(file: File): Promise<ProbeInfo> {
  const type = file.type || guessType(file.name);
  if (/^image\//.test(type)) {
    try {
      const bmp = await createImageBitmap(file);
      const w = bmp.width;
      const h = bmp.height;
      bmp.close?.();
      return { kind: 'image', type, width: w, height: h };
    } catch {
      return { kind: 'image', type };
    }
  }
  if (/^audio\//.test(type) || /\.(wav|flac|mp3)$/i.test(file.name)) return { kind: 'audio', type };
  if (type === 'application/pdf' || /\.pdf$/i.test(file.name)) return { kind: 'pdf', type };
  if (/^text\//.test(type)) return { kind: 'text', type };
  return { kind: 'other', type };
}

function guessType(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase();
  switch (ext) {
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
    case 'wav':
      return 'audio/wav';
    case 'pdf':
      return 'application/pdf';
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
