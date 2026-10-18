'use client';

import dynamic from 'next/dynamic';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useVault } from '@/lib/session';

const LockScreen = dynamic(() => import('@/components/auth/LockScreen').then((m) => m.LockScreen), {
  ssr: false,
  loading: () => <div className="grid-bg min-h-screen" />,
});

/** Dedicated local login route (§2 of the architecture spec). */
export default function LoginPage() {
  const { status } = useVault();
  const router = useRouter();
  useEffect(() => {
    if (status === 'unlocked') router.replace('/workspace');
  }, [status, router]);
  return <LockScreen />;
}
