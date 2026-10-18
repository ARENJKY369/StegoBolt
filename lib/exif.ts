'use client';

/**
 * Minimal, fully client-side EXIF / metadata inspector. Parses just enough of
 * the JPEG APP1 TIFF structure (IFD0 + Exif sub-IFD + GPS sub-IFD) and PNG
 * ancillary chunks to show what a "Sanitize & Clean" pass will strip.
 */

export interface ExifTag {
  label: string;
  value: string;
}

export interface MetadataReport {
  format: 'JPEG' | 'PNG' | 'WEBP' | 'GIF' | 'BMP' | 'PDF' | 'OTHER';
  tags: ExifTag[];
  hasGps: boolean;
  textChunks: string[];
}

const IFD0_LABELS: Record<number, string> = {
  0x000e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'ModifyDate',
  0x013b: 'Artist',
  0x8298: 'Copyright',
  0x8769: 'ExifIFD→',
  0x8825: 'GPSInfo→',
};

const EXIF_SUB_LABELS: Record<number, string> = {
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x829a: 'ExposureTime',
  0x8822: 'ExposureProgram',
  0x8827: 'ISO',
  0x920a: 'FocalLength',
  0x927c: 'MakerNote',
  0xa430: 'CameraOwnerName',
  0xa431: 'BodySerialNumber',
  0xa433: 'LensInfo',
};

const GPS_SUB_LABELS: Record<number, string> = {
  0x0000: 'GPSVersionID',
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x0012: 'GPSMapDatum',
  0x001b: 'GPSProcessingMethod',
};

const TYPE_SIZES: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 2, 7: 1, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8 };

function ascii(u8: Uint8Array, off: number, len: number): string {
  let s = '';
  const end = Math.min(off + len, u8.length);
  for (let i = off; i < end; i++) {
    const c = u8[i];
    if (c === 0) break;
    if (c >= 32 && c < 127) s += String.fromCharCode(c);
  }
  return s.trim();
}

/** Parse a TIFF IFD located at `off` (relative to the tiff slice start). */
function parseIfd(
  tiff: Uint8Array,
  view: DataView,
  le: boolean,
  off: number,
  labels: Record<number, string>,
  depth: number,
  out: ExifTag[],
  gpsFlag: { found: boolean }
): void {
  if (depth > 2 || off <= 0 || off + 2 > view.byteLength) return;
  try {
    const n = view.getUint16(off, le);
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      if (e + 12 > view.byteLength) break;
      const id = view.getUint16(e, le);
      const type = view.getUint16(e + 2, le);
      const count = view.getUint32(e + 4, le);
      const size = (TYPE_SIZES[type] ?? 1) * count;
      const valOff = size <= 4 ? e + 8 : view.getUint32(e + 8, le);
      const label = labels[id];
      if (!label) continue;

      // pointers into sub-IFDs
      if (label === 'ExifIFD→') {
        parseIfd(tiff, view, le, valOff, EXIF_SUB_LABELS, depth + 1, out, gpsFlag);
        out.push({ label: 'Exif sub-IFD', value: 'present' });
        continue;
      }
      if (label === 'GPSInfo→') {
        gpsFlag.found = true;
        parseIfd(tiff, view, le, valOff, GPS_SUB_LABELS, depth + 1, out, gpsFlag);
        continue;
      }

      let value = '';
      const safe = (o: number, l: number) => o >= 0 && o + l <= tiff.length;
      if (type === 2 && safe(valOff, count)) {
        value = ascii(tiff, valOff, count);
      } else if (type === 3 && valOff + 2 <= view.byteLength) {
        value = String(view.getUint16(valOff, le));
      } else if (type === 4 && valOff + 4 <= view.byteLength) {
        value = String(view.getUint32(valOff, le));
      } else if ((type === 5 || type === 10) && safe(valOff, 8)) {
        const num = view.getInt32(valOff, le);
        const den = view.getInt32(valOff + 4, le);
        if (type === 5) value = den ? String(+(num / den).toFixed(5)) : `${num}/${den}`;
        else value = `${num}/${den}`;
      } else if (type === 7 && safe(valOff, count)) {
        value = `<${count} bytes binary>`;
      } else if (type === 9 && valOff + 4 <= view.byteLength) {
        value = String(view.getInt32(valOff, le));
      }

      if (value) out.push({ label, value: value.slice(0, 90) });
    }
  } catch {
    /* malformed metadata — report what parsed */
  }
}

function readTiff(buf: Uint8Array, tiffOff: number, report: MetadataReport): void {
  try {
    const slice = buf.subarray(tiffOff);
    const view = new DataView(slice.buffer, slice.byteOffset, slice.byteLength);
    const order = ascii(slice, 0, 2);
    let le: boolean;
    if (order === 'II') le = true;
    else if (order === 'MM') le = false;
    else return;
    if (view.getUint16(2, le) !== 42) return;
    const ifdOff = view.getUint32(4, le);
    const gpsFlag = { found: false };
    parseIfd(slice, view, le, ifdOff, IFD0_LABELS, 0, report.tags, gpsFlag);
    report.hasGps = gpsFlag.found || report.hasGps;
  } catch {
    /* ignore */
  }
}

export function inspectMetadata(buf: ArrayBuffer, _fileName = ''): MetadataReport {
  const u8 = new Uint8Array(buf);
  const report: MetadataReport = { format: 'OTHER', tags: [], hasGps: false, textChunks: [] };

  // JPEG
  if (u8.length > 4 && u8[0] === 0xff && u8[1] === 0xd8) {
    report.format = 'JPEG';
    let off = 2;
    while (off + 4 < u8.length) {
      if (u8[off] !== 0xff) {
        off++;
        continue;
      }
      const marker = u8[off + 1];
      if (marker === 0xda) break; // scan data — no more segments
      if ((marker >= 0xd0 && marker <= 0xd9) || marker === 0x01) {
        off += 2;
        continue;
      }
      const segLen = (u8[off + 2] << 8) | u8[off + 3];
      if (segLen < 2) break;
      if (off + 2 + segLen > u8.length) break; // truncated / spoofed segment length
      if (marker === 0xe1 && segLen > 8) {
        const start = off + 4;
        const sig = String.fromCharCode(u8[start], u8[start + 1], u8[start + 2], u8[start + 3], u8[start + 4], u8[start + 5]);
        if (sig === 'Exif\0\0') readTiff(u8, start + 6, report);
      }
      if (marker === 0xe0 && segLen > 6 && ascii(u8, off + 4, 5) === 'JFIF') {
        report.tags.push({ label: 'APP0/JFIF', value: 'camera format block' });
      }
      if (marker === 0xee && segLen > 12 && ascii(u8, off + 4, 11) === 'Adobe_CM') {
        report.tags.push({ label: 'APP14/Adobe', value: 'color profile hint' });
      }
      off += 2 + segLen;
    }
    return report;
  }

  // PNG
  if (u8.length > 8 && u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4e && u8[3] === 0x47) {
    report.format = 'PNG';
    let off = 8;
    while (off + 8 < u8.length) {
      const len = ((u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3]) >>> 0;
      if (len > 0x7fffffff || off + 12 + len > u8.length) break; // bounds first
      const type = ascii(u8, off + 4, 4);
      if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') {
        const keyword = ascii(u8, off + 8, Math.min(len, 40));
        report.textChunks.push(`${type}:${keyword || 'untitled'}`);
        report.tags.push({ label: type, value: keyword.slice(0, 60) || 'metadata entry' });
      }
      if (type === 'eXIf') readTiff(u8, off + 8, report);
      if (type === 'pHYs') report.tags.push({ label: 'pHYs', value: 'physical pixel size' });
      if (type === 'IEND') break;
      off += 12 + len;
    }
    return report;
  }

  if (u8.length > 12 && ascii(u8, 0, 4) === 'RIFF' && ascii(u8, 8, 4) === 'WEBP') report.format = 'WEBP';
  else if (ascii(u8, 0, 3) === 'GIF') report.format = 'GIF';
  else if (u8[0] === 0x42 && u8[1] === 0x4d) report.format = 'BMP';
  else if (ascii(u8, 0, 5) === '%PDF-') {
    report.format = 'PDF';
    report.tags.push({ label: 'PDF catalog', value: 'document info dictionary may contain author/producer' });
  }
  return report;
}

export function countStrippable(r: MetadataReport): number {
  return r.tags.length + r.textChunks.length + (r.hasGps ? 1 : 0);
}
