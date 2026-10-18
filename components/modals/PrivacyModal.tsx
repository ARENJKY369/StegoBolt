'use client';

/**
 * "Privacy Policy & Terms of Service" — the first-run notice from the
 * reference design. Acknowledgement is stored locally; nothing is signed to a
 * server because there is no server.
 */

import { Modal } from '@/components/ui/Modal';

function Section({ no, title, body }: { no: number; title: string; body: string }) {
  return (
    <section className="rounded-lg border border-hair bg-panel2/40 p-4">
      <h3 className="text-[13.5px] font-semibold text-slate-100">
        {no}. {title}
      </h3>
      <p className="mt-1.5 text-[12.5px] leading-relaxed text-slate-400">{body}</p>
    </section>
  );
}

export function PrivacyModal({ onClose, acked = true }: { onClose: () => void; acked?: boolean }) {
  return (
    <Modal
      title="Privacy Policy & Terms of Service"
      subtitle="Binding commitments of the StegoBolt local-only build"
      onClose={onClose}
      footer={
        <button onClick={onClose} className="btn-green !px-5 !py-2 normal-case tracking-normal">
          {acked ? 'Acknowledge & Close' : 'Close'}
        </button>
      }
    >
      <div className="space-y-4">
        <Section
          no={1}
          title="Zero-Knowledge Client Execution"
          body="All steganographic processes, encoding, and decoding occur strictly client-side. Your cover files and payloads never leave your browser."
        />
        <Section
          no={2}
          title="No Server Data Storage or Telemetry"
          body="We do not capture, track, or store your private data, images, or messages on any remote server. There are no accounts, no cookies, no analytics scripts and no crash reporters in this build."
        />
        <Section
          no={3}
          title="Local PC Storage Ownership"
          body="Backups, logs, and vaults are saved locally to your device and remain under your complete ownership and control. Delete them any time from Settings → Purge local data."
        />
        <Section
          no={4}
          title="Acceptable Use (Terms)"
          body="StegoBolt is designed for legitimate security research, forensic analysis, operational privacy and secure communication. You agree not to use it to conceal unlawful activity; operators may be legally compelled to surrender keys, which is why this build stores no key material outside your own device."
        />
        <Section
          no={5}
          title="Disclaimer (Terms)"
          body="The software is provided “as-is”, without warranty of any kind. StegoBolt assumes no liability for lost data or lost passphrase — a lost master passphrase is mathematically unrecoverable. You retain full responsibility for managing your local encryption keys, vault passphrase and backup folders."
        />
        <p className="px-1 text-[10.5px] leading-relaxed text-slate-600">
          By acknowledging, you accept the terms above. This notice is shown once and re-readable anytime from the “Privacy &
          Terms” header link.
        </p>
      </div>
    </Modal>
  );
}
