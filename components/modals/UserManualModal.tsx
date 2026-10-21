'use client';

/**
 * "User Manual & Technical Glossary" — interactive tabbed documentation suite
 * (§4.B). Search filters both the operating guides and the glossary table.
 */

import { BookOpen, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Modal } from '@/components/ui/Modal';

interface Guide {
  id: string;
  title: string;
  steps: string[];
}

const GUIDES: Guide[] = [
  {
    id: 'hide',
    title: 'How to Hide (Encode)',
    steps: [
      'Open the Hide (Encode) tab and drop a cover file — a lossless PNG / BMP / TIFF / WebP / GIF works best (lossy JPEG recompression erases the LSB plane).',
      'Inspect the SHA-256 fingerprint of the chosen carrier so you can prove provenance later.',
      'Type your Secret Payload (or embed a file as raw bytes from the vault flow). The capacity meter warns before you exceed the carrier.',
      'Under Security Configuration keep “Encrypt Payload” ON: the payload is sealed with AES-256-GCM using a key stretched from your password (PBKDF2-SHA256, 100k iterations).',
      'Hit [ EMBED & BACKUP FILE ]. StegoBolt scatters the SBV2 bitstream over the lowest bit of every R/G/B byte, renders a lossless PNG, and reports PSNR / SSIM so you can confirm imperceptibility.',
      'The result is auto-saved to your Local Vault (IndexedDB) and — when enabled — written straight to your designated PC backup folder.',
    ],
  },
  {
    id: 'extract',
    title: 'How to Extract (Decode)',
    steps: [
      'Open the Extract (Decode) tab and load the suspect stego image.',
      'StegoBolt reads the SBV2 container header from the LSB plane; if no magic is found it tells you immediately.',
      'Enter the passphrase that protected the payload. PBKDF2 re-derives the AES key using the salt embedded in the carrier.',
      'Press EXTRACT. AES-GCM authentication doubles as a tamper check — a modified pixel, wrong password or resized carrier fails the tag instead of returning garbage.',
      'Recovered text is shown in RAM only: copy it, download it as .txt, or close the tab and it evaporates.',
    ],
  },
  {
    id: 'scan',
    title: 'How to Scan (Steganalysis)',
    steps: [
      'Open Forensic Scan and drop any image of unknown provenance.',
      'The scan first searches for a StegoBolt container signature (SBV2 in image LSB planes, SBV2-J on the engine path). Only a validated signature is reported as a confirmed container.',
      'Without a signature the Threat Assessment Score weighs two independent detector families — sample-pair analysis (SPA) and chi-square value-pair equalisation. A high chi-square probability on its own never raises the level; both must agree before the score can leave LOW.',
      'Study the visual histogram and LSB heatmap for context, not proof: natural covers can show imbalanced pairs and a busy LSB plane, which is why the verdict is never based on a single visual cue.',
      'Read the verdict: confirmed container (CRITICAL) · strong statistical suspicion (HIGH, no signature found) · inconclusive irregularity (ELEVATED) · no meaningful evidence (LOW). Sanitize anything above LOW before forwarding, or hand it to offline investigation.',
    ],
  },
  {
    id: 'clean',
    title: 'How to Clean (Sanitize)',
    steps: [
      'Open Sanitize & Clean and load the file you intend to publish.',
      'The inspector enumerates EXIF / XMP baggage: camera make & model, GPS latitude/longitude, software, timestamps, thumbnails.',
      'Keep “Strip EXIF & metadata” ON — the carrier is re-encoded through Canvas, which discards every ancillary chunk and tag.',
      'Keep “Randomize LSB noise floor” ON — every R/G/B lowest bit is re-drawn from the CSPRNG, destroying any prior embedded bitstream and any low-entropy artifact.',
      'Export the sanitized file and review the diff report (bytes touched, PSNR, entropy before/after). Everything stays on your device.',
    ],
  },
];

interface Term {
  term: string;
  definition: string;
}

const GLOSSARY: Term[] = [
  { term: 'Steganography', definition: 'The practice of concealing a file, message, image, or video within another file to hide its very existence.' },
  {
    term: 'Steganalysis',
    definition:
      'The counter-discipline: statistical attacks (chi-square, RS analysis, histogram moments) that detect hidden data carriers without ever extracting them.',
  },
  { term: 'Cover Medium', definition: 'The original, unaltered file (such as PNG, BMP, or WAV) used as a carrier to hide the secret data.' },
  { term: 'Stego Object', definition: 'The carrier after embedding — the modified file that secretly contains the payload.' },
  { term: 'Payload', definition: 'The secret message, encrypted data, or file that is being hidden within the cover medium.' },
  { term: 'Bit Depth', definition: 'Number of bits used per color channel (8 in standard images). LSB embedding only flips the final bit, keeping change ≤ 1/255.' },
  {
    term: 'LSB (Least Significant Bit)',
    definition: 'Replaces the lowest bit of pixel bytes to hide data invisibly — a single bit flips a channel value by at most 1, imperceptible to the eye.',
  },
  {
    term: 'PSNR (Peak Signal-to-Noise Ratio)',
    definition: 'A metric used to measure the visual quality and imperceptibility of the stego file compared to the original. Values above 40 dB indicate imperceptible visual change.',
  },
  {
    term: 'SSIM (Structural Similarity Index)',
    definition: 'Perceptual similarity (0–1) comparing luminance, contrast and structure between cover and stego. 1.0 means structurally identical.',
  },
  { term: 'EXIF Tags', definition: 'Metadata embedded in image files that can reveal GPS data, camera settings, and timestamps (frequently sanitized).' },
  {
    term: 'Chi-Square Analysis',
    definition:
      'Compares the population of value pairs (2i, 2i+1) against the equalised model that sequential LSB replacement produces. StegoBolt uses it as one corroborating detector: a high chi-square probability alone never raises the threat level, and natural photos routinely score high without carrying any payload.',
  },
  { term: 'Ciphertext', definition: 'The encrypted payload produced by AES-256-GCM before embedding. Random-looking, authenticated, and useless without the key.' },
  { term: 'AES-256-GCM', definition: 'Authenticated military-grade encryption ensuring payload confidentiality and tamper resistance.' },
  { term: 'PBKDF2-SHA256', definition: 'Key-stretching function (100,000 iterations in StegoBolt) that turns a human passphrase into a 256-bit AES key.' },
  { term: 'IndexedDB (Dexie)', definition: "The browser's local object database. StegoBolt's vault keeps history and backups there — on your device only." },
  { term: 'File System Access API', definition: 'Lets you grant StegoBolt a handle to a real backup folder on your hard drive; writes only happen when you enable disk backup.' },
  { term: 'WebAuthn', definition: 'Open standard for hardware-backed authentication — Touch ID, Windows Hello, or a security key unlock the local vault.' },
  { term: 'Zero-Knowledge Architecture', definition: 'A design contract: the operator holds no data, key or telemetry about you, because all execution is client-side.' },
];

function SectionCard({ g }: { g: Guide }) {
  return (
    <div className="rounded-lg border border-hair bg-panel2/50 p-4">
      <h4 className="text-[13px] font-semibold text-slate-100">{g.title}</h4>
      <ol className="mt-2 space-y-1.5">
        {g.steps.map((s, i) => (
          <li key={i} className="flex gap-2.5 text-[12px] leading-relaxed text-slate-400">
            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-brand/15 font-mono text-[9.5px] font-bold text-emerald-400">
              {i + 1}
            </span>
            <span>{s}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function UserManualModal({ onClose }: { onClose: () => void }) {
  const [tab, setTab] = useState<'guides' | 'glossary'>('guides');
  const [q, setQ] = useState('');

  const query = q.trim().toLowerCase();
  const guides = useMemo(
    () => (query ? GUIDES.filter((g) => (g.title + ' ' + g.steps.join(' ')).toLowerCase().includes(query)) : GUIDES),
    [query]
  );
  const terms = useMemo(
    () => (query ? GLOSSARY.filter((t) => (t.term + ' ' + t.definition).toLowerCase().includes(query)) : GLOSSARY),
    [query]
  );

  return (
    <Modal title="User Manual & Technical Glossary" subtitle="Everything the operator needs — searchable, offline, zero telemetry" onClose={onClose} wide>
      <div className="relative mb-4">
        <Search size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search terms..."
          className="input !rounded-lg pl-9"
          autoFocus
        />
      </div>

      <div className="mb-4 flex border-b border-hair">
        {(
          [
            ['guides', 'How-To Guides'],
            ['glossary', 'Technical Glossary'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`relative px-4 py-2 text-[12.5px] font-medium transition ${
              tab === id ? 'text-slate-100' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            {label}
            {tab === id && <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-brand" />}
          </button>
        ))}
      </div>

      {tab === 'guides' ? (
        <div className="space-y-3">
          {guides.length === 0 && (
            <p className="rounded-lg border border-hair bg-panel2/40 p-4 text-center text-[12px] text-slate-500">
              No guide matches “{q}”.
            </p>
          )}
          {guides.map((g) => (
            <SectionCard key={g.id} g={g} />
          ))}
          <p className="flex items-center gap-1.5 px-1 text-[11px] text-slate-500">
            <BookOpen size={11} /> Tip: restart the guided tour any time from Settings → “Replay onboarding tour”.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-hair">
          <table className="w-full border-collapse text-left">
            <thead className="bg-panel2/70">
              <tr>
                <th className="th !py-2 w-[36%]">Term</th>
                <th className="th !py-2">Definition</th>
              </tr>
            </thead>
            <tbody>
              {terms.map((t) => (
                <tr key={t.term} className="border-t border-hair align-top hover:bg-panel2/40">
                  <td className="td !py-2.5 font-medium text-slate-100">{t.term}</td>
                  <td className="td !py-2.5 text-[12px] leading-relaxed text-slate-400">{t.definition}</td>
                </tr>
              ))}
              {terms.length === 0 && (
                <tr className="border-t border-hair">
                  <td colSpan={2} className="td text-center text-slate-500">
                    No glossary match for “{q}”.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}
