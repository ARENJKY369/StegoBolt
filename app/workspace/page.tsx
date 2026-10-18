'use client';

import dynamic from 'next/dynamic';

/**
 * Workspace route. The shell is client-only (IndexedDB, Canvas, Web Crypto)
 * so it's mounted without SSR; the session provider in the root layout keeps
 * the in-RAM vault key alive across login ↔ workspace navigation.
 */
const WorkspaceShell = dynamic(() => import('@/components/workspace/WorkspaceShell'), {
  ssr: false,
  loading: () => (
    <div className="grid-bg flex min-h-screen items-center justify-center bg-ink">
      <p className="animate-pulse text-[12px] font-medium tracking-wide text-slate-500">mounting local-only workspace…</p>
    </div>
  ),
});

export default function WorkspacePage() {
  return <WorkspaceShell />;
}
