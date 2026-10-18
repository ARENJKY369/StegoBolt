'use client';

import { Boxes, Cpu, Fingerprint, LockKeyhole, ShieldCheck, Terminal, Zap } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Modal } from '@/components/ui/Modal';
import { InfoTip, TIPS } from '@/components/ui/Tooltip';

function Spec({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <div className="flex gap-3 rounded-lg border border-hair bg-panel2/50 p-3">
      <Icon size={16} className="mt-0.5 shrink-0 text-emerald-400" />
      <div>
        <p className="text-[12.5px] font-semibold text-slate-200">{title}</p>
        <p className="mt-0.5 text-[11.5px] leading-relaxed text-slate-400">{body}</p>
      </div>
    </div>
  );
}

export function AboutModal({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="About StegoBolt" subtitle="v2.0 — open-source steganography & media sanitization suite" onClose={onClose} wide>
      <div className="space-y-6">
        <section>
          <h3 className="card-title flex items-center gap-2">
            <Zap size={15} className="text-emerald-400" /> Overview
          </h3>
          <p className="mt-2 text-[12.5px] leading-relaxed text-slate-400">
            StegoBolt is a production-grade, <span className="text-slate-200">zero-knowledge steganography and media sanitization
            suite</span> that runs entirely inside your browser. Hide encrypted payloads inside PNG/BMP carriers, extract them,
            audit suspicious media with statistical steganalysis, and scrub EXIF fingerprints — without a single byte of your
            secrets ever touching a server.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <span className="chip">Hide · LSB Embedding</span>
            <span className="chip">Extract · Recovery</span>
            <span className="chip">Scan · Steganalysis</span>
            <span className="chip">Clean · Metadata Sanitizer</span>
          </div>
        </section>

        <section>
          <h3 className="card-title flex items-center gap-2">
            <ShieldCheck size={15} className="text-emerald-400" /> Security Manifesto
          </h3>
          <div className="mt-2 space-y-2 text-[12.5px] leading-relaxed text-slate-400">
            <p>
              <span className="font-medium text-slate-200">Client-side execution model.</span> Every cryptographic and image
              operation — AES-256-GCM sealing <InfoTip text={TIPS.AES} width={300} />, PBKDF2 key derivation, LSB embedding{' '}
              <InfoTip text={TIPS.LSB} width={300} />, extraction and steganalysis — executes locally via the Web Crypto,
              Canvas and Web Worker APIs. Your cover files and payloads never leave this tab.
            </p>
            <p>
              <span className="font-medium text-slate-200">Zero server storage guarantee.</span> There is no backend database.
              No cookies, no analytics beacons, no telemetry pings, no crash reporters. This manifest ships with zero
              third-party scripts.
            </p>
            <p>
              <span className="font-medium text-slate-200">Hardware-bound biometric authentication.</span> Touch ID / Windows
              Hello act as a local gesture that releases a device-wrapped key — the master passphrase remains the only root
              secret, and the derived AES key is flushed from RAM on tab-hide or 5-minute inactivity.
            </p>
          </div>
        </section>

        <section>
          <h3 className="card-title flex items-center gap-2">
            <Cpu size={15} className="text-emerald-400" /> Architecture Specs
          </h3>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            <Spec
              icon={LockKeyhole}
              title="Web Crypto API"
              body="AES-256-GCM authenticated encryption, AES-CTR stream mode, PBKDF2-SHA256 @ 100,000 iterations and SHA-256 integrity hashing — all native browser primitives, constant-time C++ under the hood."
            />
            <Spec
              icon={Fingerprint}
              title="WebAuthn (platform authenticators)"
              body="navigator.credentials.create/get with userVerification: required. Credential IDs and the wrapped key blob stay in this browser profile; nothing is registered with a remote party."
            />
            <Spec
              icon={Boxes}
              title="IndexedDB vault (Dexie)"
              body="Local History & Backups, settings and stego artifacts persist in the browser's IndexedDB via Dexie. Export any moment to an open .stegvault manifest you own on disk."
            />
            <Spec
              icon={Terminal}
              title="File System Access API + Web Workers"
              body="Optional direct writes to a folder you designate (C:\\…\\StegoBolt\\Backups or /Users/…). LSB scatter/gather and noise randomization are offloaded to an inline Web Worker to keep the UI fluid."
            />
          </div>
        </section>

        <p className="rounded-lg border border-hair bg-panel2/40 px-3 py-2 text-[11px] leading-relaxed text-slate-500">
          Carriers supported: PNG, BMP, WebP, GIF, TIFF (lossless formats — lossy JPEG recompression destroys the LSB plane).
          Container format: <span className="font-mono">SBV2</span> framing over the R/G/B least-significant-bit plane.
        </p>
      </div>
    </Modal>
  );
}
