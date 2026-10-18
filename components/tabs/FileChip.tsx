'use client';

import { Check, Copy, File as FileIcon, X } from 'lucide-react';
import { useState } from 'react';
import { fmtBytes } from '@/lib/format';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';
import { typeBadge, type LoadedFile } from './useStegoFile';

/** The carrier chip from the reference UI: thumbnail, name, stats, remove +
 *  the SHA-256 verification row with copy affordance. */
export function FileChip({
  loaded,
  onRemove,
  accent = 'brand',
}: {
  loaded: LoadedFile;
  onRemove: () => void;
  accent?: 'brand' | 'red';
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 rounded-lg border border-hair bg-panel2/70 p-2">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-md border border-hair bg-black/40">
          {loaded.previewUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={loaded.previewUrl} alt="" className="h-full w-full object-cover" />
          ) : (
            <FileIcon size={16} className="text-slate-500" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-[12.5px] font-semibold text-slate-100">{loaded.name}</p>
          <p className="mt-0.5 text-[10.5px] text-slate-500">
            {fmtBytes(loaded.size)} • {typeBadge(loaded.name, loaded.type)}
            {loaded.width && loaded.height ? ` • ${loaded.width}×${loaded.height}` : ''}
            {loaded.kind === 'image' && !loaded.width ? ' • image' : ''}
          </p>
        </div>
        <button onClick={onRemove} className="btn-ghost !px-2.5 !py-1 text-[11px]" title="Remove file">
          <X size={11} className="mr-1" /> Remove
        </button>
      </div>
      <div className="flex items-center gap-1.5">
        <span className="text-[9.5px] font-bold uppercase tracking-[0.14em] text-slate-600">
          SHA-256 <InfoTip text={TIPS.SHA} width={280} />
        </span>
        <code className={`min-w-0 flex-1 truncate rounded-md border px-2 py-1 font-mono text-[10px] ${accent === 'brand' ? 'border-brand/25 bg-brand/5 text-emerald-200/90' : 'border-red-500/25 bg-red-500/5 text-red-200/90'}`}>
          {loaded.hash || '…'}
        </code>
        <button
          onClick={() => {
            navigator.clipboard?.writeText(loaded.hash).then(
              () => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              },
              () => undefined
            );
          }}
          className="rounded-md border border-hair bg-panel2 p-1.5 text-slate-500 transition hover:text-slate-200"
          title="Copy fingerprint"
        >
          {copied ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
        </button>
      </div>
    </div>
  );
}
