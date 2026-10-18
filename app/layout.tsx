import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { Providers } from '@/components/Providers';

export const metadata: Metadata = {
  title: 'StegoBolt — Steganography Suite',
  description:
    'Zero-knowledge, client-side steganography suite: hide encrypted payloads in images, extract them, run statistical steganalysis and sanitize EXIF metadata. Nothing ever leaves your browser.',
  applicationName: 'StegoBolt',
  icons: {
    icon: [
      {
        url: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%230a0e13'/%3E%3Cpath d='M13 4.5 7.5 13h3.4L10.5 19.5 16.5 11h-3.4L13 4.5Z' fill='%2322c55e' stroke='%23bbf7d0' stroke-width='0.8' stroke-linejoin='round'/%3E%3C/svg%3E",
      },
    ],
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
