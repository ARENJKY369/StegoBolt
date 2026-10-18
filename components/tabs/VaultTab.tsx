'use client';

/**
 * Local Vault & Backups — IndexedDB (Dexie) history browser with live queries,
 * folder binding via the File System Access API, .stegvault export/import and
 * a one-click purge. Everything stays on the device.
 */

import { Database, FileDown, FileUp, FolderOpen, HardDrive, ShieldOff, Trash2 } from 'lucide-react';
import { useRef, useState } from 'react';
import { fmtBytes } from '@/lib/format';
import { backupDir, fsapiSupported, pickBackupDir } from '@/lib/fsaccess';
import { clearDemoHistory, exportVaultFile, importVaultFile } from '@/lib/vault';
import { useVault } from '@/lib/session';
import { HistoryPanel } from './HistoryPanel';
import { downloadBlob } from './HistoryPanel';

export function VaultTab() {
  const vault = useVault();
  const importRef = useRef<HTMLInputElement>(null);
  const [note, setNote] = useState<string | null>(null);
  const [confirmPurge, setConfirmPurge] = useState(false);

  const doExport = async () => {
    const blob = await exportVaultFile();
    downloadBlob(blob, 'stegobolt-backup.stegvault');
    setNote('Manifest exported — history metadata only; payloads stay inside your media files.');
  };

  const doImport = async (f: File | null) => {
    if (!f) return;
    try {
      const r = await importVaultFile(f);
      setNote(`Imported ${r.added} records from ${f.name}.`);
      vault.refreshStorage();
    } catch (e) {
      setNote(e instanceof Error ? `Import rejected: ${e.message}` : 'Import failed');
    } finally {
      if (importRef.current) importRef.current.value = '';
    }
  };

  const pick = async () => {
    try {
      const res = await pickBackupDir();
      if (res) {
        vault.updateSettings({ backupDirLabel: res.path });
        setNote(`Disk mirror bound to ${res.path} for this session (handle never persisted).`);
      }
    } catch {
      setNote('Directory picker blocked in this context.');
    }
  };

  return (
    <div className="space-y-4">
      <section className="card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 className="card-title flex items-center gap-2">
              <Database size={15} className="text-emerald-400" /> Local Vault &amp; Backups
            </h3>
            <p className="mt-1 max-w-[520px] text-[12px] leading-relaxed text-slate-500">
              Embeds, scans and sanitized exports are journaled in this browser&apos;s IndexedDB (Dexie). Attach a folder on your PC to
              mirror artifacts to disk. Neither destination is ever mirrored by a server — there is no server.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={() => void doExport()} className="btn-outline !py-2">
              <FileDown size={13} /> Export .stegvault
            </button>
            <button onClick={() => importRef.current?.click()} className="btn-outline !py-2">
              <FileUp size={13} /> Import
            </button>
            {confirmPurge ? (
              <button
                onClick={async () => {
                  await clearDemoHistory();
                  await vault.wipeAllLocal();
                  setConfirmPurge(false);
                  setNote('Purged. Re-arm the vault with a new master passphrase to continue.');
                }}
                className="inline-flex items-center gap-2 rounded-lg border border-red-500/50 bg-red-500/15 px-3 py-2 text-[12px] font-bold text-red-300 transition hover:bg-red-500/25"
              >
                <ShieldOff size={13} /> Confirm full wipe?
              </button>
            ) : (
              <button onClick={() => setConfirmPurge(true)} className="btn-outline !py-2 !text-red-400/90 hover:!border-red-500/40 hover:!text-red-300">
                <Trash2 size={13} /> Purge all local data
              </button>
            )}
            <input ref={importRef} type="file" accept=".stegvault,application/json" className="hidden" onChange={(e) => void doImport(e.target.files?.[0] ?? null)} />
          </div>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-hair bg-panel2/40 p-3.5">
            <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
              <HardDrive size={11} className="text-emerald-400" /> IndexedDB (local)
            </p>
            <p className="mt-1.5 font-mono text-[13px] text-slate-200">{vault.storageLabel}</p>
            <p className="mt-0.5 text-[10px] text-slate-600">Dexie store “StegoBoltVault” · this browser profile only</p>
          </div>
          <div className="rounded-lg border border-hair bg-panel2/40 p-3.5">
            <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
              <FolderOpen size={11} className="text-emerald-400" /> PC Mirror Folder
            </p>
            <p className="mt-1.5 truncate font-mono text-[12px] text-slate-200" title={backupDir.path || vault.settings.backupDirLabel}>
              {backupDir.handle ? backupDir.path : vault.settings.backupDirLabel || 'Not attached'}
            </p>
            <button
              onClick={() => void pick()}
              disabled={!fsapiSupported()}
              className="mt-2 rounded-md border border-hair2 bg-panel3 px-2.5 py-1 text-[11px] font-semibold text-slate-200 transition hover:border-brand/50 disabled:cursor-not-allowed disabled:opacity-50"
              title={fsapiSupported() ? 'Bind a real folder via File System Access API' : 'Requires Chromium-based desktop browser'}
            >
              {fsapiSupported() ? (backupDir.handle ? 'Change folder…' : 'Choose folder…') : 'Unsupported in this browser'}
            </button>
          </div>
          <div className="rounded-lg border border-hair bg-panel2/40 p-3.5">
            <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">Vault integrity</p>
            <p className="mt-1.5 font-mono text-[13px] text-slate-200">0 remote endpoints</p>
            <p className="mt-0.5 text-[10px] leading-relaxed text-slate-600">
              Records are deleted the instant you purge; disk mirror files are yours to shred.
            </p>
          </div>
        </div>

        {note && (
          <p className="mt-3 flex items-center gap-2 rounded-lg border border-brand/30 bg-brand/10 px-3 py-2 text-[11.5px] text-emerald-200">
            {note}
            <button onClick={() => setNote(null)} className="ml-auto text-emerald-300/70 hover:text-emerald-100">✕</button>
          </p>
        )}
        <p className="mt-3 text-[10.5px] text-slate-600">
          Mirror state: {fmtBytes(0)} sent to remote endpoints · {fsapiSupported() ? 'File System Access API ready' : 'File System Access API unavailable — IndexedDB + manual downloads only'}
        </p>
      </section>

      <HistoryPanel />
    </div>
  );
}
