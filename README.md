# ⚡ StegoBolt v2.0 — Zero-Knowledge Steganography Suite

Production-grade steganography & media sanitization web app that runs **100% in the browser**.
No backend. No accounts. No telemetry. Your cover files, payloads and keys never leave the device.

Built with **Next.js (App Router) · TypeScript · Tailwind CSS · Lucide Icons · Web Crypto API · Canvas API · Web Workers · IndexedDB (Dexie) · WebAuthn · File System Access API**.

## Quick start

```bash
npm install
npm run dev        # http://localhost:3000 — first visit lands on the local vault lock screen
npm run build      # production build
node --experimental-strip-types scripts/pipeline-test.ts   # core engine verification suite
```

## Feature map

| Area | What ships |
| --- | --- |
| **Local Vault Lock Screen** (`/login`) | First-time master passphrase (min 8, PBKDF2-SHA256 @ 100k) + optional biometric (Touch ID / Windows Hello via WebAuthn) with device-bound key wrap. `STEGOBOLT VAULT LOCKED` card, biometric primary unlock, passphrase fallback, `.stegvault` import link. |
| **Auto-lock lifecycle** | Tab-hidden → instant lock & RAM key flush; 5-minute inactivity timer (user-tunable); buffers zeroized and tabs remounted on every lock cycle. |
| **Hide (Encode)** | Drag-drop cover (PNG/BMP/WebP/TIFF/GIF), SHA-256 fingerprint row, AES-256-GCM/CTR toggle + password, capacity meter, LSB scatter in an inline Web Worker, lossless PNG output, PSNR/SSIM report, IndexedDB + optional PC folder backup. |
| **Extract (Decode)** | SBV2 container sweep + GCM tag authentication (wrong pass / tampered pixels fail closed), recovered-text console, copy / save `.txt`. |
| **Forensic Scan** | Chi-square pair attack, LSB balance, windowed entropy, run analysis, SBV2 signature hunt → Threat Assessment Score (gauge), value-pair histogram & LSB-plane heatmap canvases. |
| **Sanitize & Clean** | EXIF/XMP tag enumeration (JPEG APP1 TIFF parser incl. GPS), canvas re-encode metadata strip, CSPRNG LSB noise-floor re-randomization, PSNR/changed-bits diff report. |
| **Onboarding tour** | 5-step spotlight tour (`components/onboarding/TourGuide.tsx`) auto-launched on first login: Mode Switcher → Dropzone/SHA-256 → Security & Encryption → Local Vault/PC Backup → Hex Inspector. Skippable, replayable from Settings. |
| **Hover tooltips** | `<Tooltip>`/`(?)` badge system on every technical term: LSB, PSNR, AES-256-GCM, EXIF, PBKDF2, IndexedDB, FSA, chi-square, SSIM, threat score. |
| **Docs & legal** | **About** modal (overview, security manifesto, architecture specs) · **User Manual & Technical Glossary** (searchable; How-To Guides + glossary table) · **Privacy Policy & Terms of Service** (first-run notice with *Acknowledge & Close*). |
| **Local Vault & Backups** | Live IndexedDB journal (Dexie `useLiveQuery`), history table with Download / View Payload / Delete, `.stegvault` export/import, PC folder binding via File System Access API, one-click purge. |
| **Footer console** | Collapsible hexadecimal + LSB-binary inspector of the last in-RAM buffers, plus persistent status bar (session, crypto, IndexedDB record count, worker mode, `TELEMETRY: DISABLED`). |

## Architecture notes

- `lib/crypto.ts` — PBKDF2 KDF, AES-GCM/CTR, SHA-256, sealed-payload format, key wrapping.
- `lib/lsbcore.ts` / `lib/worker.ts` — `SBV2` container over the R/G/B LSB plane; identical algorithm runs in an inline Blob Web Worker with a mirrored main-thread fallback.
- `lib/analysis.ts` — steganalysis statistics + PSNR/SSIM-lite quality metrics.
- `lib/exif.ts` — minimal TIFF/IFD0 + GPS sub-IFD reader for metadata previews.
- `lib/vault.ts` — Dexie IndexedDB journal, `.stegvault` manifest, demo history seeding.
- `lib/session.tsx` — the RAM-only key holder, auto-lock lifecycle, settings, artifacts and system log.

Zero network calls are made with user data: the app contains no `fetch`/XHR targets, no external fonts, no analytics.

## Security disclaimer

StegoBolt is provided **as-is**, for legitimate security research, forensics, and operational privacy. A lost master passphrase is mathematically unrecoverable — keep your `.stegvault` exports and media files safe.
