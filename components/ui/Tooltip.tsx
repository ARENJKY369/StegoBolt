'use client';

import { useState, type ReactNode } from 'react';
import { Info } from 'lucide-react';

/**
 * Hover tooltip used for every technical term in the product (§3.2 of spec).
 * Pure CSS hover reveal — no popper deps, no portals leaks, keyboard focusable.
 */
type Side = 'top' | 'bottom' | 'left' | 'right';

const SIDE_POS: Record<Side, string> = {
  top: 'bottom-full left-1/2 -translate-x-1/2 mb-2',
  bottom: 'top-full left-1/2 -translate-x-1/2 mt-2',
  left: 'right-full top-1/2 -translate-y-1/2 mr-2',
  right: 'left-full top-1/2 -translate-y-1/2 ml-2',
};

export function Tooltip({
  text,
  children,
  side = 'top',
  width = 264,
  className = '',
}: {
  text: ReactNode;
  children?: ReactNode;
  side?: Side;
  width?: number;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className={`group relative inline-flex align-middle ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      tabIndex={0}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          style={{ width }}
          className={`pointer-events-none absolute z-[70] animate-popin rounded-lg border border-hair2 bg-[#0d1219] px-3 py-2 text-left text-[11.5px] font-normal leading-relaxed text-slate-300 shadow-card ${SIDE_POS[side]}`}
        >
          {text}
        </span>
      )}
    </span>
  );
}

/** The `(?)` info badge that trails every technical term. */
export function InfoTip({ text, side = 'top', width = 264 }: { text: ReactNode; side?: Side; width?: number }) {
  return (
    <Tooltip text={text} side={side} width={width} className="ml-1">
      <span
        aria-label="definition"
        className="inline-flex h-[15px] w-[15px] cursor-help items-center justify-center rounded-full border border-hair2 bg-panel2 text-[9px] font-bold text-slate-400 transition hover:border-brand/60 hover:text-brand"
      >
        <Info size={9} strokeWidth={2.6} />
      </span>
    </Tooltip>
  );
}

/** Glossary entries (§3.2). */
export const TIPS = {
  LSB: 'LSB (Least Significant Bit): Replaces the lowest bit of pixel bytes to hide data invisibly',
  PSNR:
    'PSNR (Peak Signal-to-Noise Ratio): Measures the visual quality and imperceptibility of the stego file compared to the original. Values above 40 dB indicate imperceptible visual change.',
  AES: 'AES-256-GCM: Authenticated military-grade encryption ensuring payload confidentiality and tamper resistance.',
  EXIF: 'EXIF (Exchangeable Image File Format): Hidden camera metadata (location, camera model) stripped in Clean mode.',
  SHA: 'SHA-256: Cryptographic fingerprint of the file. Verify the hash to prove provenance without revealing content.',
  INDEXEDDB:
    'IndexedDB (Dexie): The browser\u2019s local database. Your vault history lives here, on this device — never on a server.',
  FSA: 'File System Access API: Grants StegoBolt a handle to a folder you pick on your own disk. Directories are only written when you enable disk backup.',
  CHI: 'Chi-Square Attack: Tests whether value pairs (2i, 2i+1) keep the binomial balance of natural images. Sequential LSB embedding skews it.',
  SSIM: 'SSIM (Structural Similarity Index): Perceptual similarity score between cover and stego. 1.0 = visually identical structures.',
  THREAT:
    'Threat Assessment Score (0–100): Blended evidence from chi-square pair tests, LSB balance, entropy and container-signature detection.',
  PBKDF2:
    'PBKDF2-SHA256 with 100,000 iterations + a random salt stretches your master passphrase into the AES-256 key held only in RAM.',
  AUTOSAVE:
    'Auto-Save: every embed/scan/sanitize result is mirrored into the local IndexedDB vault (and optionally your chosen disk folder).',
  ZEROLOG:
    'Zero-Knowledge Client Execution: encryption, LSB embedding, extraction and steganalysis all run in this browser tab. Nothing is uploaded.',
  CTR: 'AES-256-CTR: fast stream cipher without integrity tags — a bit-flip oracle remains possible. Prefer AES-256-GCM.',
} as const;
