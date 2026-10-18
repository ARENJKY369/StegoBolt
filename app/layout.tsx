import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { Providers } from '@/components/Providers';
import { FAVICON_URL } from '@/lib/brand';

export const metadata: Metadata = {
  title: 'StegoBolt',
  description:
    'Zero-knowledge, client-side steganography suite: hide encrypted payloads in images, extract them, run statistical steganalysis and sanitize EXIF metadata. Nothing ever leaves your browser.',
  applicationName: 'StegoBolt',
  icons: {
    icon: FAVICON_URL,
  },
};

export const viewport: Viewport = {
  themeColor: '#0a0e13',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-ink text-slate-200 antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
