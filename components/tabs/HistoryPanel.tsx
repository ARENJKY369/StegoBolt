'use client';

/**
 * "Local History & Backups" table (bottom of the workspace in the reference
 * UI). Live-backed by IndexedDB (Dexie useLiveQuery) so embeds, scans and
 * sanitizes appear reactively.
 */

import { ChevronDown, ChevronUp, Eye } from 'lucide-react';
import { useState } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { fmtBytes, timeAgo } from '@/lib/format';
import { db, deleteRecord, getRecordBlob, type VaultRecord } from '@/lib/vault';
import { useVault } from '@/lib/session';

export function downloadBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 8000);
}

export function HistoryPanel({ limit }: { limit?: number }) {
  const { log, refreshStorage } = useVault();
  const [expanded, setExpanded] = useState<number | null>(null);

  const rows = useLiveQuery(async () => {
    const all = await db().operations.orderBy('ts').reverse().toArray();
    return all as VaultRecord[];
  }, [limit === undefined ? 0 : limit]);

  const total = rows?.length ?? 0;
  const view = limit ? (rows ?? []).slice(0, limit) : rows ?? [];

  if (!rows) {
    return (
      <div className="card p-6 text-center text-[12px] text-slate-600">
        Opening local vault (IndexedDB)…
      </div>
    );
  }

  const act = async (r: VaultRecord) => {
    if (r.id == null) return;
    if (r.blob) {
      downloadBlob(r.blob, r.outName ?? `${r.coverName}.bin`);
      log(`Downloaded ${r.outName ?? 'artifact'} from local vault`, 'ok');
      return;
    }
    const live = await getRecordBlob(r.id);
    if (live) downloadBlob(live, r.outName ?? 'stegobolt-artifact');
    else log(r.demo ? 'Demo record — the original file bytes are not stored in this row.' : 'No file bytes stored for this record.', 'warn');
  };

  return (
    <section className="card overflow-hidden">
      <header className="flex items-center justify-between border-b border-hair px-4 py-3">
        <h3 className="card-title">Local History &amp; Backups</h3>
        <span className="text-[11.5px] text-slate-500">
          Showing {view.length} of {total} operations
        </span>
      </header>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <thead className="bg-panel2/60 text-[12px]">
            <tr>
              <th className="th">Timestamp</th>
              <th className="th">Operation</th>
              <th className="th">Cover File</th>
              <th className="th">Backup Status</th>
              <th className="th text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {view.map((r) => (
              <FragmentRow key={r.id} r={r} expanded={expanded === r.id} onToggle={() => setExpanded(expanded === r.id ? null : (r.id ?? null))} onAct={() => void act(r)} onDelete={() => r.id != null && void deleteRecord(r.id).then(() => { refreshStorage(); log(`Vault record #${r.id} deleted`, 'warn'); })} />
            ))}
            {view.length === 0 && (
              <tr>
                <td colSpan={5} className="td py-8 text-center text-slate-600">
                  No local operations yet — your history stays on this device, in this browser profile only.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FragmentRow({
  r,
  expanded,
  onToggle,
  onAct,
  onDelete,
}: {
  r: VaultRecord;
  expanded: boolean;
  onToggle: () => void;
  onAct: () => void;
  onDelete: () => void;
}) {
  const hasPayload = !!r.payloadPreview;
  return (
    <>
      <tr className="border-t border-hair/70 transition hover:bg-panel2/40">
        <td className="td whitespace-nowrap text-slate-300">{timeAgo(r.ts)}</td>
        <td className="td">
          <span
            className={`rounded-md px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-wide ${
              r.op === 'Hide'
                ? 'bg-brand/15 text-emerald-300'
                : r.op === 'Extract'
                ? 'bg-sky-500/15 text-sky-300'
                : r.op === 'Scan'
                ? 'bg-amber-500/15 text-amber-300'
                : r.op === 'Sanitize'
                ? 'bg-fuchsia-500/15 text-fuchsia-300'
                : 'bg-panel3 text-slate-400'
            }`}
          >
            {r.op}
          </span>
        </td>
        <td className="td font-mono text-[12px] text-slate-300">{r.coverName}</td>
        <td className="td">
          <span className={`${r.backup === 'Saved to local disk' ? 'text-emerald-400' : r.backup === 'Disk write failed' ? 'text-red-400' : 'text-slate-400'}`}>
            {r.backup}
            {r.size > 0 && <span className="ml-1.5 text-slate-600">· {fmtBytes(r.size)}</span>}
          </span>
        </td>
        <td className="td text-right">
          <span className="inline-flex items-center gap-3">
            <button onClick={onAct} className="link-green text-[12px]">
              Download
            </button>
            {hasPayload && (
              <button onClick={onToggle} className="link-green inline-flex items-center gap-0.5 text-[12px]">
                View Payload {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
              </button>
            )}
            {!hasPayload && (
              <button onClick={onToggle} className="inline-flex items-center gap-0.5 text-[12px] text-slate-500 transition hover:text-slate-300" title="Inspect metadata">
                <Eye size={11} /> Detail
              </button>
            )}
            <button onClick={onDelete} className="text-[12px] text-red-400/70 transition hover:text-red-300" title="Delete vault record">
              Delete
            </button>
          </span>
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-hair/40 bg-black/25">
          <td colSpan={5} className="px-4 py-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <p className="mb-1 text-[9.5px] font-bold uppercase tracking-[0.14em] text-slate-500">Recovered / embedded payload</p>
                <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-all rounded-md border border-hair bg-panel2/60 p-2.5 font-mono text-[11px] leading-relaxed text-emerald-100/90">
                  {r.payloadPreview ?? '— (payload bytes remain inside the media file; nothing stored here)'}
                </pre>
              </div>
              <div>
                <p className="mb-1 flex items-center gap-1 text-[9.5px] font-bold uppercase tracking-[0.14em] text-slate-500">
                  Integrity &amp; provenance
                </p>
                <p className="break-all font-mono text-[10px] leading-relaxed text-slate-400">
                  SHA-256 {r.hash || 'n/a'}
                </p>
                {r.meta && (
                  <p className="mt-1 font-mono text-[10px] leading-relaxed text-slate-500">
                    {Object.entries(r.meta)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join('  ·  ')}
                  </p>
                )}
                {r.demo && <p className="mt-1 text-[10px] italic text-amber-400/70">Sample entry — remove demo data in Settings.</p>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
