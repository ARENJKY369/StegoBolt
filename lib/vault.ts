'use client';

/**
 * Local Vault — IndexedDB persistence via Dexie. Every record stays on this
 * device (browser storage). Export/import uses the open `.stegvault` JSON
 * container which the user keeps on their own disk.
 */

import Dexie, { type Table } from 'dexie';

export type OpKind = 'Hide' | 'Extract' | 'Scan' | 'Sanitize' | 'Import' | 'Delete';

export interface VaultRecord {
  id?: number;
  ts: number;
  op: OpKind;
  coverName: string;
  outName?: string;
  size: number;
  dims?: string;
  backup: 'Saved to local disk' | 'Saved' | 'No local download' | 'Disk write failed' | 'Local disk';
  hash: string; // sha-256 of the produced/consumed artifact
  payloadPreview?: string; // first 240 chars (or note) of the recovered/hidden payload
  meta?: Record<string, string | number>;
  blob?: Blob; // stego output kept locally for re-download
  demo?: boolean;
}

class StegoBoltDB extends Dexie {
  operations!: Table<VaultRecord, number>;

  constructor() {
    super('StegoBoltVault');
    this.version(1).stores({
      operations: '++id, ts, op, coverName',
    });
  }
}

let _db: StegoBoltDB | null = null;

export function db(): StegoBoltDB {
  if (typeof window === 'undefined') throw new Error('IndexedDB requires a browser context');
  if (!_db) _db = new StegoBoltDB();
  return _db;
}

export function idbAvailable(): boolean {
  try {
    return typeof indexedDB !== 'undefined';
  } catch {
    return false;
  }
}

export async function addRecord(rec: Omit<VaultRecord, 'id'>): Promise<number> {
  try {
    return await db().operations.add(rec as VaultRecord);
  } catch {
    return -1;
  }
}

export async function deleteRecord(id: number): Promise<void> {
  try {
    await db().operations.delete(id);
  } catch {
    /* vault already gone */
  }
}

export async function clearVault(): Promise<void> {
  try {
    await db().operations.clear();
  } catch {
    /* noop */
  }
}

export async function vaultCount(): Promise<number> {
  try {
    return await db().operations.count();
  } catch {
    return 0;
  }
}

export async function exportVaultFile(): Promise<Blob> {
  let rows: VaultRecord[] = [];
  try {
    rows = await db().operations.orderBy('ts').reverse().toArray();
  } catch {
    rows = [];
  }
  const container = {
    app: 'StegoBolt',
    format: 'stegvault/v1',
    exportedAt: new Date().toISOString(),
    zeroKnowledge: true,
    note: 'Local vault manifest. Contains history metadata only — hidden payloads are inside the media files themselves, never this document.',
    count: rows.length,
    records: rows.map((r) => ({
      ts: r.ts,
      op: r.op,
      coverName: r.coverName,
      outName: r.outName ?? null,
      size: r.size,
      dims: r.dims ?? null,
      backup: r.backup,
      hash: r.hash,
      payloadPreview: r.payloadPreview ?? null,
      meta: r.meta ?? null,
      embeddedFile: r.blob ? `${r.blob.size} bytes stored in this browser's IndexedDB` : null,
    })),
  };
  return new Blob([JSON.stringify(container, null, 2)], { type: 'application/json' });
}

export interface ImportResult {
  added: number;
  format: string;
}

export async function importVaultFile(file: File): Promise<ImportResult> {
  const text = await file.text();
  let data: {
    format?: string;
    records?: {
      ts?: number;
      op?: string;
      coverName?: string;
      outName?: string | null;
      size?: number;
      dims?: string | null;
      backup?: string;
      hash?: string;
      payloadPreview?: string | null;
      meta?: Record<string, string | number> | null;
    }[];
  };
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('Not a valid .stegvault JSON container');
  }
  if (data.format !== 'stegvault/v1') throw new Error('Unsupported vault format (expected stegvault/v1)');
  const rows = (data.records ?? []).slice(0, 500).map((r) => ({
    ts: typeof r.ts === 'number' ? r.ts : Date.now(),
    op: (r.op ?? 'Import') as OpKind,
    coverName: r.coverName ?? 'unknown',
    outName: r.outName ?? undefined,
    size: r.size ?? 0,
    dims: r.dims ?? undefined,
    backup: 'No local download',
    hash: r.hash ?? '',
    payloadPreview: r.payloadPreview ?? undefined,
    meta: { ...(r.meta ?? {}), importedFrom: file.name },
  }));
  if (!rows.length) return { added: 0, format: data.format };
  try {
    await db().operations.bulkAdd(rows as VaultRecord[]);
  } catch {
    throw new Error('IndexedDB unavailable — cannot import');
  }
  return { added: rows.length, format: data.format };
}

const DEMO_FLAG = 'sb.demo.v1';

/** Seed a handful of realistic demo history rows so the workspace mirrors the
 *  product screenshots on first run. Flagged `demo: true` — one click wipes them. */
export async function seedDemoHistory(): Promise<void> {
  try {
    const { lsGet, lsSet } = await import('./store');
    if (lsGet(DEMO_FLAG)) return;
    const n = await db().operations.count();
    if (n > 0) {
      lsSet(DEMO_FLAG, '1');
      return;
    }
    const now = Date.now();
    const min = 60_000;
    const mk = (
      minsAgo: number,
      op: OpKind,
      coverName: string,
      backup: VaultRecord['backup'],
      extra?: Partial<VaultRecord>
    ): VaultRecord => ({
      ts: now - minsAgo * min,
      op,
      coverName,
      size: extra?.size ?? Math.floor(200_000 + Math.random() * 3_000_000),
      dims: extra?.dims ?? '1920×1080',
      backup,
      hash: Array.from({ length: 64 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''),
      demo: true,
      ...extra,
    });
    const rows: VaultRecord[] = [
      mk(10, 'Hide', 'lake_view.png', 'Saved to local disk', { outName: 'lake_view.stego.png', payloadPreview: '••• encrypted payload (212 B) •••' }),
      mk(127, 'Extract', 'invoice_encrypted.png', 'No local download', { payloadPreview: 'Wire transfer approved — ref 88142.', size: 1_842_111 }),
      mk(60 * 26, 'Sanitize', 'contract_leak_test.pdf', 'Saved', { dims: undefined, size: 4_120_044 }),
      mk(60 * 30, 'Scan', 'suspect_photo.jpg', 'No local download', { meta: { 'Threat score': 87 } }),
      mk(60 * 34, 'Hide', 'team_photo.jpg', 'Saved to local disk', { outName: 'team_photo.stego.png' }),
      mk(60 * 49, 'Scan', 'server_rack.png', 'Saved', { meta: { 'Threat score': 12 } }),
      mk(60 * 52, 'Hide', 'sunset.bmp', 'No local download'),
      mk(60 * 55, 'Sanitize', 'phone_capture.jpg', 'Saved to local disk'),
      mk(60 * 74, 'Hide', 'audit_pages.pdf', 'Disk write failed'),
      mk(60 * 77, 'Extract', 'memo_final.png', 'No local download', { payloadPreview: 'Meet at pier 9, 22:00.' }),
      mk(60 * 98, 'Scan', 'press_kit.jpg', 'Saved'),
      mk(60 * 120, 'Hide', 'field_notes.png', 'Saved to local disk'),
      mk(60 * 141, 'Sanitize', 'old_report.tiff', 'Saved'),
      mk(60 * 170, 'Hide', 'warehouse_cam1.png', 'Saved to local disk'),
    ];
    await db().operations.bulkAdd(rows);
    lsSet(DEMO_FLAG, '1');
  } catch {
    /* IDB blocked — demo history is optional */
  }
}

export async function clearDemoHistory(): Promise<void> {
  try {
    // booleans can't be IDB keys — iterate instead (the vault is small by design)
    const rows = await db().operations.filter((r) => !!r.demo).toArray();
    if (rows.length) await db().operations.bulkDelete(rows.map((r) => r.id as number));
  } catch {
    /* noop */
  }
}

export async function getRecordBlob(id: number): Promise<Blob | null> {
  try {
    const r = await db().operations.get(id);
    return r?.blob ?? null;
  } catch {
    return null;
  }
}

export async function getRecord(id: number): Promise<VaultRecord | undefined> {
  try {
    return await db().operations.get(id);
  } catch {
    return undefined;
  }
}
