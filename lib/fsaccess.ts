'use client';

/**
 * File System Access API bridge — lets the user designate a real folder on
 * their PC (e.g. C:\Users\me\Documents\StegoBolt\Backups or /Users/me/...) as
 * the backup target. The directory handle is held in RAM only and re-picked
 * after a page reload.
 */

interface FSHandle {
  name: string;
  // deno-lint-ignore no-explicit-any
  [k: string]: any;
}

declare global {
  interface Window {
    showDirectoryPicker?: (options?: { mode?: 'read' | 'readwrite'; id?: string }) => Promise<FSHandle>;
  }
}

export function fsapiSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.showDirectoryPicker === 'function';
}

export interface PickedDir {
  handle: FSHandle;
  path: string; // display path (browsers only expose the folder name)
}

/** Live directory handle for the session (never persisted — re-pick after reload). */
export const backupDir: { handle: FSHandle | null; path: string } = { handle: null, path: '' };

export async function pickBackupDir(): Promise<PickedDir | null> {
  if (!fsapiSupported()) return null;
  try {
    const handle = await window.showDirectoryPicker!({ mode: 'readwrite', id: 'stegobolt-backups' });
    const path = `…/${handle.name}`;
    try {
      // request permission immediately so background saves never prompt mid-job
      const perm = await handle.requestPermission?.({ mode: 'readwrite' });
      void perm;
    } catch {
      /* permission handled at write time */
    }
    backupDir.handle = handle;
    backupDir.path = path;
    return { handle, path };
  } catch (err) {
    const e = err as { name?: string };
    if (e?.name === 'AbortError') return null;
    throw err;
  }
}

export async function writeToDir(dir: FSHandle, fileName: string, blob: Blob): Promise<boolean> {
  try {
    const fh = await dir.getFileHandle(fileName, { create: true });
    const writable = await fh.createWritable();
    await writable.write(blob);
    await writable.close();
    return true;
  } catch {
    return false;
  }
}

/** Suggested default path text for the UI (cosmetic — mirrors the OS). */
export function suggestedBackupPath(): string {
  if (typeof navigator === 'undefined') return '~/Documents/StegoBolt/Backups';
  const ua = navigator.userAgent;
  if (/Win/i.test(ua)) return 'C:\\Users\\me\\Documents\\StegoBolt\\Backups';
  if (/Mac/i.test(ua)) return '/Users/me/Documents/StegoBolt/Backups';
  return '/home/me/Documents/StegoBolt/Backups';
}
