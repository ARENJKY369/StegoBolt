'use client';

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString('en-US');
}

export function timeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 45) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return m === 1 ? '1 min ago' : `${m} mins ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return h === 1 ? '1 hour ago' : `${h} hours ago`;
  const d = Math.floor(h / 24);
  if (d <= 1) return 'Yesterday';
  if (d < 7) return `${d} days ago`;
  return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function fmtClock(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}:${r.toString().padStart(2, '0')}`;
}

export function shortHash(hex: string, len = 14): string {
  if (!hex) return '…';
  if (hex.length <= len * 2) return hex;
  return `${hex.slice(0, len)}…${hex.slice(-6)}`;
}

export function fmtBytesExact(n: number): string {
  return `${Math.round(n).toLocaleString('en-US')} bytes`;
}

export function pct(n: number, digits = 1): string {
  return `${(n * 100).toFixed(digits)}%`;
}

export function fmtSci(n: number): string {
  if (n === 0) return '0';
  if (n < 1e-4 || n >= 1e5) {
    const e = Math.floor(Math.log10(Math.abs(n)));
    const m = n / Math.pow(10, e);
    return `${m.toFixed(2)}e${e}`;
  }
  return n.toFixed(4);
}
