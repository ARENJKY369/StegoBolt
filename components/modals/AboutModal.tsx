'use client';

/**
 * "About StegoBolt" — two-tier, human-first design (§3 of the Engine v2 brief).
 *
 * Tier 1  · "At a Glance"      — plain language for everyone (students, business
 *                                owners, journalists, casual users). No jargon.
 * Tier 2  · "Under the Hood"   — collapsible accordion
 *          "Technical Architecture & Security Specs (For Auditors)" with the
 *           deep specs tucked neatly inside.
 */

import {
  Activity,
  Boxes,
  ChevronDown,
  Clock3,
  Code2,
  Cpu,
  FileText,
  Fingerprint,
  Image as ImageIcon,
  LockKeyhole,
  Music,
  Network,
  Server,
  ShieldCheck,
  Sparkles,
  Video,
  Zap,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Modal } from '@/components/ui/Modal';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';

/* ------------------------------------------------------------------ */
/* Tier 1 — At a Glance                                               */
/* ------------------------------------------------------------------ */

function ProtectCard({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <div className="rounded-lg border border-hair bg-panel2/50 p-3">
      <div className="flex items-center gap-2">
        <span className="flex h-6 w-6 items-center justify-center rounded-md bg-emerald-500/15">
          <Icon size={13} className="text-emerald-400" />
        </span>
        <p className="text-[12.5px] font-semibold text-slate-200">{title}</p>
      </div>
      <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-400">{body}</p>
    </div>
  );
}

function MediumCard({
  icon: Icon,
  title,
  body,
  formats,
}: {
  icon: LucideIcon;
  title: string;
  body: string;
  formats: string;
}) {
  return (
    <div className="flex flex-col rounded-lg border border-hair bg-panel2/50 p-3">
      <div className="flex items-center gap-2">
        <span className="flex h-7 w-7 items-center justify-center rounded-md border border-hair2 bg-panel3">
          <Icon size={14} className="text-sky-400" />
        </span>
        <p className="text-[12px] font-semibold text-slate-200">{title}</p>
      </div>
      <p className="mt-1.5 flex-1 text-[11px] leading-relaxed text-slate-400">{body}</p>
      <p className="mt-2 font-mono text-[9.5px] uppercase tracking-wider text-slate-500">{formats}</p>
    </div>
  );
}

const PROTECTIONS = [
  {
    icon: ShieldCheck,
    title: '100% Private',
    body: 'Your files and secret messages never leave your computer or get saved on any external database.',
  },
  {
    icon: LockKeyhole,
    title: 'Double Lock',
    body: "Your message is encrypted with a password before it is hidden, so even if someone suspects a picture contains hidden data, they can't read it without your key.",
  },
  {
    icon: Clock3,
    title: 'No Trace Left Behind',
    body: 'When you close your browser tab or step away for 5 minutes, StegoBolt automatically locks itself and wipes all memory clean.',
  },
] as const;

/** Supported Mediums — the six stego carriers StegoBolt can hide data inside. */
const MEDIUMS = [
  {
    icon: ImageIcon,
    title: 'Photos',
    body: 'Hide secrets inside ordinary pictures. The pixels change so slightly that no eye — or camera — can tell.',
    formats: 'PNG · BMP · WebP',
  },
  {
    icon: Music,
    title: 'Music & Audio',
    body: 'Tuck messages into the quietest parts of a sound file — far below what any human ear can hear.',
    formats: 'WAV · FLAC',
  },
  {
    icon: Video,
    title: 'Videos',
    body: 'Conceal data between video frames, where players glide right past it without a flicker.',
    formats: 'MP4 · MKV · AVI',
  },
  {
    icon: FileText,
    title: 'Documents',
    body: 'Add invisible watermarks and hidden layers to everyday documents — the pages look untouched.',
    formats: 'PDF · DOCX',
  },
  {
    icon: Code2,
    title: 'Text & Code',
    body: 'Sprinkle invisible characters between the letters, or leave secret patterns at the end of lines.',
    formats: 'TXT · Java · JS · C++',
  },
  {
    icon: Network,
    title: 'Network Packets',
    body: 'Slip secrets into the tiny gaps of internet traffic — like whispering between the words of a conversation.',
    formats: 'PCAP · Traffic streams',
  },
] as const;

/* ------------------------------------------------------------------ */
/* Tier 2 — Under the Hood (accordion)                                */
/* ------------------------------------------------------------------ */

function TechSpec({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <div className="flex gap-3 rounded-lg border border-hair bg-panel2/40 p-3">
      <Icon size={15} className="mt-0.5 shrink-0 text-emerald-400" />
      <div>
        <p className="text-[12px] font-semibold text-slate-200">{title}</p>
        <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{body}</p>
      </div>
    </div>
  );
}

function UnderTheHood() {
  const [open, setOpen] = useState(false);

  return (
    <section className="overflow-hidden rounded-xl border border-hair2 bg-panel2/30">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-panel2/60"
      >
        <span className="flex items-center gap-2">
          <Cpu size={15} className="text-emerald-400" />
          <span>
            <span className="block text-[12.5px] font-semibold text-slate-200">Under the Hood</span>
            <span className="block text-[10.5px] text-slate-500">
              Technical Architecture &amp; Security Specs (For Auditors)
            </span>
          </span>
        </span>
        <ChevronDown
          size={16}
          className={`shrink-0 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <div className="space-y-2 border-t border-hair px-4 pb-4 pt-3">
          <TechSpec
            icon={Server}
            title="Java 17 / Spring Boot 3.x in-memory streaming backend"
            body="The StegoBolt Engine (stegobolt-engine) streams every upload through volatile RAM — multipart buffers, byte arrays and response streams only. Nothing is written to disk, /tmp, or a database; every buffer is explicitly zero-wiped in finally blocks and no payload or passphrase is ever logged. REST surface: /api/v1/stego (/hide, /extract, /scan, /clean, /capacity)."
          />
          <TechSpec
            icon={LockKeyhole}
            title="Client-Side Web Crypto API — AES-256-GCM + PBKDF2"
            body="Payloads are sealed with AES-256-GCM (authenticated encryption) using a key stretched from your password by PBKDF2 with 100,000 iterations (PBKDF2-SHA256). A wrong password or a single flipped pixel fails the authentication tag instead of returning garbage."
          />
          <TechSpec
            icon={Fingerprint}
            title="Hardware-bound biometrics via WebAuthn (cryptographically verified)"
            body="navigator.credentials.create/get with userVerification: required. The credential's COSE public key is pinned at enrollment (SPKI when exposed, else parsed from the attestation CBOR) and every assertion's ES256/RS256 signature is verified over authenticatorData || SHA-256(clientDataJSON), with clientData type/challenge/origin binding — unlock fails closed on any mismatch. The verified assertion releases a device-wrapped key; the master passphrase stays the only root secret, held in RAM and flushed on lock."
          />
          <TechSpec
            icon={Activity}
            title="Statistical Chi-Square & Sample Pair Analysis (SPA) steganalysis"
            body="Pure-Java forensic detectors: Westfeld chi-square value-pair attack, Dumitrescu sample-pair analysis for embedding-ratio estimation, LSB balance and windowed entropy — blended into a 0–100 Threat Assessment Score."
          />
          <TechSpec
            icon={Boxes}
            title="Local-first browser layer"
            body="The Next.js workspace keeps its zero-knowledge guarantees: Web Workers for LSB scatter/gather, IndexedDB (Dexie) for the local vault, File System Access API for opt-in PC backups, and zero network calls with user data."
          />

          <div className="flex flex-wrap gap-2 pt-1">
            <span className="chip">java.awt.image.BufferedImage</span>
            <span className="chip">javax.sound.sampled</span>
            <span className="chip">JCA / AES-GCM</span>
            <span className="chip">PBKDF2-SHA256 @ 100k</span>
            <span className="chip">WebAuthn</span>
            <span className="chip">Chi-Square + SPA</span>
            <span className="chip">Zero-disk RAM purge</span>
          </div>
        </div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Modal                                                              */
/* ------------------------------------------------------------------ */

export function AboutModal({ onClose }: { onClose: () => void }) {
  return (
    <Modal
      title="About StegoBolt"
      subtitle="v2.0 — hide secrets in plain sight, without leaving a trace"
      onClose={onClose}
      wide
    >
      <div className="space-y-6">
        {/* ============ Tier 1: At a Glance ============ */}
        <section>
          <p className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-emerald-400">
            <Sparkles size={11} /> At a Glance
          </p>

          <h3 className="card-title mt-2">What is StegoBolt?</h3>
          <p className="mt-2 text-[13px] leading-relaxed text-slate-300">
            StegoBolt is a <span className="font-medium text-slate-100">digital vault that lets you hide secret text
            messages or sensitive files inside ordinary photos, audio clips, and documents</span>. Think of it like{' '}
            <span className="font-medium text-emerald-300">digital invisible ink</span> — the file looks completely
            normal, but only someone with your password can reveal what&apos;s hidden inside.
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            <span className="chip">Hide · Embed a secret</span>
            <span className="chip">Extract · Reveal a secret</span>
            <span className="chip">Scan · Check for hidden data</span>
            <span className="chip">Clean · Erase every trace</span>
          </div>
        </section>

        <section>
          <h3 className="card-title flex items-center gap-2">
            <ShieldCheck size={15} className="text-emerald-400" /> How Does It Protect Me?
          </h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {PROTECTIONS.map((p) => (
              <ProtectCard key={p.title} icon={p.icon} title={p.title} body={p.body} />
            ))}
          </div>
        </section>

        <section>
          <h3 className="card-title flex items-center gap-2">
            <Zap size={15} className="text-emerald-400" /> What Can You Hide In?
            <span className="ml-1 rounded-md border border-hair bg-panel2 px-1.5 py-0.5 font-mono text-[9px] font-medium uppercase tracking-wider text-slate-400">
              Supported Mediums
            </span>
          </h3>
          <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
            Six kinds of everyday files can carry a secret — each hides data in a place nobody thinks to look.{' '}
            <InfoTip text={TIPS.LSB} width={300} />
          </p>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {MEDIUMS.map((m) => (
              <MediumCard key={m.title} icon={m.icon} title={m.title} body={m.body} formats={m.formats} />
            ))}
          </div>
        </section>

        {/* ============ Tier 2: Under the Hood ============ */}
        <UnderTheHood />

        <p className="rounded-lg border border-hair bg-panel2/40 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
          Lossless carriers work best (PNG, BMP, WebP, WAV, PDF…): lossy recompression — like saving over a JPEG — can
          disturb the hidden layer. Container format:{' '}
          <span className="font-mono">SBV2</span> framing, sealed with{' '}
          <span className="font-mono">AES-256-GCM</span> before it is hidden.
        </p>
      </div>
    </Modal>
  );
}
