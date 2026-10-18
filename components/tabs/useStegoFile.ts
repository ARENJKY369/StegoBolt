'use client';

import { useCallback, useRef, useState } from 'react';
import { sha256Hex } from '@/lib/crypto';
import { decodeImageData, probeFile, type DecodedPixels } from '@/lib/image';

export interface LoadedFile {
  file: File;
  name: string;
  size: number;
  type: string;
  previewUrl: string | null;
  hash: string;
  kind: 'image' | 'audio' | 'pdf' | 'text' | 'other';
  width?: number;
  height?: number;
  bytes?: ArrayBuffer;
}

/** Shared loader for every workspace tab: object-URL preview, SHA-256, dims,
 *  optional full ImageData decode for pixel operations. */
export function useStegoFile(opts: { decode?: boolean } = {}) {
  const [loaded, setLoaded] = useState<LoadedFile | null>(null);
  const [pixels, setPixels] = useState<DecodedPixels | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const urlRef = useRef<string | null>(null);

  const clear = useCallback(() => {
    if (urlRef.current) {
      URL.revokeObjectURL(urlRef.current);
      urlRef.current = null;
    }
    setLoaded(null);
    setPixels(null);
    setError(null);
  }, []);

  const load = useCallback(
    async (file: File) => {
      setLoading(true);
      setError(null);
      try {
        if (urlRef.current) URL.revokeObjectURL(urlRef.current);
        const isImage = /^image\//.test(file.type) || /\.(png|jpe?g|bmp|gif|webp|tiff?)$/i.test(file.name);
        const previewUrl = isImage ? URL.createObjectURL(file) : null;
        urlRef.current = previewUrl;
        const [hash, probe] = await Promise.all([sha256Hex(file), probeFile(file)]);
        let bytes: ArrayBuffer | undefined;
        try {
          bytes = await file.arrayBuffer();
        } catch {
          bytes = undefined;
        }
        setLoaded({
          file,
          name: file.name,
          size: file.size,
          type: file.type || probe.type,
          previewUrl,
          hash,
          kind: probe.kind,
          width: probe.width,
          height: probe.height,
          bytes,
        });
        if (opts.decode !== false && isImage) {
          try {
            const px = await decodeImageData(file);
            setPixels(px);
          } catch {
            setPixels(null);
            setError('Could not rasterize this image in-browser (huge or corrupt?). File stats are still available.');
          }
        } else {
          setPixels(null);
        }
        return true;
      } catch {
        setError('Failed to read file.');
        return false;
      } finally {
        setLoading(false);
      }
    },
    [opts.decode]
  );

  return { loaded, pixels, loading, error, setError, load, clear, setPixels };
}

export function typeBadge(name: string, mime: string): string {
  const m = mime.replace(/^image\//, '').replace(/^audio\//, '').toUpperCase();
  if (m && m !== 'OCTET-STREAM') return m;
  const ext = name.split('.').pop()?.toUpperCase();
  return ext ?? 'FILE';
}
