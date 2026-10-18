'use client';

import type { ReactNode } from 'react';
import { VaultProvider } from '@/lib/session';

/** Client-side state island hosting the session context across routes so the
 *  RAM-held AES key survives navigation between /login and /workspace. */
export function Providers({ children }: { children: ReactNode }) {
  return <VaultProvider>{children}</VaultProvider>;
}
