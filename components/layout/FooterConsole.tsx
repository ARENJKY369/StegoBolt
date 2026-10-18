'use client';

/**
 * Footer Console (§5): collapsible hexadecimal/binary pixel inspector +
 * persistent system status bar. Reads whichever buffers the active tab last
 * touched via the session artifacts — RAM only, wiped at lock.
 */

import { ChevronUp, Copy, Terminal } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { fmtClock } from '@/lib/format';
import { useVault } from '@/lib/session';
import { vaultCount } from '@/lib/vault';

const ROWS = 16;

function hexRow(i: number): string {
  return i.toString(16).padStart(2, '0');
}

function Dump({ bytes, bits }: { bytes: Uint8Array; bits: boolean }) {
  const rows = useMemo(() => {
    const out: { off: number; hex: string; ascii: string; binary: string }[] = [];
    const limit = Math.min(bytes.length, ROWS * 16 * 4); // cap 1024 bytes
    for (let o = 0; o < limit; o += 16) {
      const slice = bytes.subarray(o, Math.min(o + 16, limit));
      const hex = Array.from(slice, hexRow).join(' ');
      const ascii = Array.from(slice, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
      const binary = Array.from(slice, (b) => b.toString(2).padStart(8, '0') + ' ').join('').trim();
      out.push({ off: o, hex: hex.padEnd(47, ' '), ascii, binary });
    }
    return out;
  }, [bytes]);

  if (bits) {
    return (
      <pre className="hex-cell overflow-x-auto whitespace-pre p-4 text-[10.5px] leading-[1.9] text-slate-400">
        <span className="text-slate-600">
          {rows
            .slice(0, 4)
            .map((r) => r.binary)
            .join('\n')}
        </span>
        {'  ←  each byte rendered as 8 bits; the highlighted '}
        <span className="rounded bg-brand/20 px-1 font-bold text-emerald-300">last bit</span>
        {' of R/G/B bytes is where StegoBolt writes the SBV2 stream'}
      </pre>
    );
  }
  return (
    <pre className="hex-cell overflow-x-auto whitespace-pre p-4 text-[11px] leading-relaxed">
      {rows
        .map(
          (r) =>
            `0x${r.off.toString(16).padStart(8, '0')}  ${r.hex}  |${r.ascii}|`
        )
        .join('\n')}
    </pre>
  );
}

export function FooterConsole() {
  const { artifacts, status, idleRemaining, storageLabel, workerMode, settings, logs, lock } = useVault();
  const [open, setOpen] = useState(false);
  const [source, setSource] = useState<'cover' | 'stego' | 'payload'>('cover');
  const [bits, setBits] = useState(false);
  const [count, setCount] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    const refresh = () => void vaultCount().then((c) => alive && setCount(c));
    refresh();
    const t = setInterval(refresh, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [logs[0]?.ts]);

  useEffect(() => {
    if (status !== 'unlocked') setOpen(false);
  }, [status]);

  const active: { name: string; bytes: Uint8Array | null | undefined; info?: string } =
    source === 'cover'
      ? { name: artifacts.coverName ?? '—', bytes: artifacts.coverBytes, info: artifacts.coverInfo }
      : source === 'stego'
      ? { name: artifacts.stegoName ?? '—', bytes: artifacts.stegoBytes, info: artifacts.stegoInfo }
      : { name: artifacts.payloadInfo ?? 'payload', bytes: artifacts.payloadBytes };

  const available = [
    { id: 'cover' as const, label: 'Input File', on: !!artifacts.coverBytes },
    { id: 'stego' as const, label: 'Output File', on: !!artifacts.stegoBytes },
    { id: 'payload' as const, label: 'Payload Bytes', on: !!artifacts.payloadBytes },
  ];

  return (
    <div className="z-30 border-t border-hair bg-[#0c1117]/95 backdrop-blur">
      {open && (
        <div className="border-b border-hair/70 bg-[#0a0f15]">
          <div className="flex items-center justify-between gap-2 px-4 pt-3">
            <div className="flex items-center gap-1">
              <span className="mr-1 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
                Byte Inspector
              </span>
              {available.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSource(a.id)}
                  disabled={!a.on}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                    source === a.id && a.on
                      ? 'bg-brand/15 text-emerald-300 shadow-[inset_0_0_0_1px_rgba(34,197,94,0.35)]'
                      : a.on
                      ? 'text-slate-400 hover:bg-panel2 hover:text-slate-200'
                      : 'cursor-not-allowed text-slate-700'
                  }`}
                  title={a.on ? `Inspect ${a.label}` : 'No data in RAM — run an operation first'}
                >
                  {a.label} {a.on ? '' : '(idle)'}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setBits((b) => !b)}
                className={`rounded-md px-2 py-1 text-[10.5px] font-semibold uppercase tracking-wide transition ${
                  bits ? 'bg-brand/15 text-emerald-300' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                LSB Bit View
              </button>
              {active.bytes && (
                <button
                  onClick={() => navigator.clipboard?.writeText(Array.from(active.bytes!.subarray(0, 64), hexRow).join(''))}
                  className="btn-ghost !py-1"
                  title="Copy first 64 bytes as hex"
                >
                  <Copy size={11} />
                </button>
              )}
            </div>
          </div>
          <div className="mx-4 my-3 h-[190px] overflow-auto rounded-lg border border-hair bg-black/40">
            {active.bytes ? (
              <Dump bytes={active.bytes} bits={bits} />
            ) : (
              <p className="flex h-full items-center justify-center text-[11.5px] text-slate-600">
                {active.name === '—'
                  ? 'Load a file in the workspace to inspect its raw bytes — nothing is ever fetched from a server.'
                  : `No ${active.name} buffered in RAM (flushed on lock by design).`}
              </p>
            )}
          </div>
        </div>
      )}

      <div className="flex h-9 items-center gap-3 overflow-hidden px-4 text-[10.5px] text-slate-500">
        <button
          id="sb-hexbtn"
          onClick={() => setOpen((o) => !o)}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-hair bg-panel2 px-2 py-0.5 font-semibold text-slate-300 transition hover:border-brand/40 hover:text-emerald-300"
          title="Toggle hexadecimal / LSB binary inspector"
        >
          <Terminal size={11} className="text-emerald-400" /> Console
          <ChevronUp size={11} className={`transition-transform ${open ? '' : 'rotate-180'}`} />
        </button>
        <span className="hidden items-center gap-1 sm:flex">
          <span className="h-1.5 w-1.5 animate-blink rounded-full bg-brand" />
          <b className="font-semibold text-slate-400">{status === 'unlocked' ? 'SESSION OK' : 'LOCKED'}</b>
        </span>
        <span className="hidden md:inline">
          Crypto: {settings.defaultCipher === 0 ? 'RAW (unencrypted!)' : settings.defaultCipher === 2 ? 'AES-256-CTR' : 'AES-256-GCM'} armed
        </span>
        <span className="hidden lg:inline">IndexedDB · {count ?? 0} vault records</span>
        <span className="hidden lg:inline">Workers: {workerMode === 'worker' ? 'inline LSB worker online' : 'main-thread fallback'}</span>
        <span className="hidden xl:inline">{storageLabel}</span>
        <span className="ml-auto flex shrink-0 items-center gap-3">
          {status === 'unlocked' && (
            <span className="hidden font-mono tabular-nums text-slate-600 sm:inline">idle-locks in {fmtClock(idleRemaining)}</span>
          )}
          <span className="rounded bg-panel2 px-1.5 py-0.5 font-semibold tracking-wide text-red-400/80">TELEMETRY: DISABLED</span>
          <span className="hidden font-semibold tracking-wide text-emerald-500/80 md:inline">0 BYTES UPLOADED</span>
        </span>
      </div>
      {open && <div className="px-4 pb-2 pt-0 text-[9.5px] leading-relaxed text-slate-600">
        {active.info ?? 'Raw memory view of the last buffer touched by the workspace. Volatile by design: closed & zeroized when the vault locks.'}
      </div>}
    </div>
  );
}
