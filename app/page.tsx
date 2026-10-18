'use client';

/**
 * Route gate: unlocked sessions land in the workspace; everything else is
 * funneled through the dedicated Local Vault Lock Screen at /login (§2).
 */

import { Loader2, Zap } from 'lucide-react';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useVault } from '@/lib/session';

export default function StegoBoltGate() {
  const { status } = useVault();
  const router = useRouter();

  useEffect(() => {
    if (status === 'boot') return;
    router.replace(status === 'unlocked' ? '/workspace' : '/login');
  }, [status, router]);

  return (
    <div className="grid-bg flex min-h-screen items-center justify-center bg-ink">
      <div className="flex flex-col items-center gap-4">
        <span
          className="flex h-14 w-14 items-center justify-center rounded-2xl border border-brand/40"
          style={{ background: 'radial-gradient(circle at 35% 30%, rgba(34,197,94,0.3), rgba(10,14,19,0.95) 70%)' }}
        >
          <Zap size={26} className="text-emerald-400" />
        </span>
        <p className="text-[15px] font-bold tracking-tight text-slate-100">StegoBolt</p>
        <p className="flex items-center gap-2 text-[11px] text-slate-500">
          <Loader2 size={12} className="animate-spin text-emerald-500" /> checking local vault state — all checks are offline
        </p>
      </div>
    </div>
  );
}
