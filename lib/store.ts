'use client';

/**
 * Storage helper with a hardened in-memory fallback.
 * If the browser blocks localStorage (sandboxed iframe / private mode),
 * StegoBolt keeps state in RAM for the lifetime of the tab. Nothing ever
 * leaves the device — this module performs zero network calls.
 */
const memory = new Map<string, string>();
let realAvailable: boolean | null = null;

function hasRealStorage(): boolean {
  if (realAvailable !== null) return realAvailable;
  try {
    const k = '__sb_probe__';
    window.localStorage.setItem(k, '1');
    window.localStorage.removeItem(k);
    realAvailable = true;
  } catch {
    realAvailable = false;
  }
  return realAvailable;
}

export function lsGet(key: string): string | null {
  try {
    if (hasRealStorage()) return window.localStorage.getItem(key);
  } catch {
    /* fall through */
  }
  return memory.get(key) ?? null;
}

export function lsSet(key: string, value: string): void {
  try {
    if (hasRealStorage()) {
      window.localStorage.setItem(key, value);
      memory.set(key, value);
      return;
    }
  } catch {
    /* fall through */
  }
  memory.set(key, value);
}

export function lsRemove(key: string): void {
  try {
    if (hasRealStorage()) window.localStorage.removeItem(key);
  } catch {
    /* fall through */
  }
  memory.delete(key);
}

export function lsGetJson<T>(key: string, fallback: T): T {
  const raw = lsGet(key);
  if (raw == null) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function lsSetJson(key: string, value: unknown): void {
  lsSet(key, JSON.stringify(value));
}
