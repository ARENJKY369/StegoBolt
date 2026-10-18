# ⚡ StegoBolt v2.0 — Zero-Knowledge Steganography Suite

Production-grade steganography & media sanitization web app that runs **100% in the browser**.
No backend. No accounts. No telemetry. Your cover files, payloads and keys never leave the device.

Built with **Next.js (App Router) · TypeScript · Tailwind CSS · Lucide Icons · Web Crypto API · Canvas API · Web Workers · IndexedDB (Dexie) · WebAuthn · File System Access API** — plus the optional **StegoBolt Engine**, a 100% Java 17 / Spring Boot 3.x in-memory backend (`stegobolt-engine/`).

## Quick start

```bash
npm install
npm run dev        # http://localhost:3000 — first visit lands on the local vault lock screen
npm run build      # production build
npm test           # core engine + worker↔main parity fuzz verification suite
node --experimental-strip-types scripts/pipeline-test.ts   # same suite, explicit

# Optional — the Java engine (REST API on http://localhost:8080/api/v1/stego)
cd stegobolt-engine && mvn spring-boot:run
```

CI (`.github/workflows/ci.yml`) runs the TypeScript typecheck, the parity suite and the production build on every push/PR, plus `mvn -B test` for the Java engine.

## Feature map

| Area | What ships |
| --- | --- |
| **Local Vault Lock Screen** (`/login`) | First-time master passphrase (min 8, PBKDF2-SHA256 @ 100k) + optional biometric (Touch ID / Windows Hello via WebAuthn) with device-bound key wrap. Every assertion's ES256/RS256 signature is verified against the enrolled COSE public key (clientData type/challenge/origin bound — fails closed). `STEGOBOLT VAULT LOCKED` card, biometric primary unlock, passphrase fallback, `.stegvault` import link. |
| **Auto-lock lifecycle** | Tab-hidden → instant lock & RAM key flush; 5-minute inactivity timer (user-tunable); buffers zeroized and tabs remounted on every lock cycle. |
| **Hide (Encode)** | Drag-drop cover (PNG/BMP/WebP/TIFF/GIF), SHA-256 fingerprint row, AES-256-GCM/CTR toggle + password, capacity meter, LSB scatter in an inline Web Worker, lossless PNG output, PSNR/SSIM report, IndexedDB + optional PC folder backup. Optionally delegates to the Java engine (Settings → Java Engine). |
| **Extract (Decode)** | SBV2 container sweep + GCM tag authentication (wrong pass / tampered pixels fail closed), recovered-text console, copy / save `.txt`. Optionally delegates to the Java engine (Settings → Java Engine). |
| **Forensic Scan** | Chi-square pair attack, LSB balance, windowed entropy, run analysis, SBV2 signature hunt → Threat Assessment Score (gauge), value-pair histogram & LSB-plane heatmap canvases. |
| **Sanitize & Clean** | EXIF/XMP tag enumeration (JPEG APP1 TIFF parser incl. GPS), canvas re-encode metadata strip, CSPRNG LSB noise-floor re-randomization, PSNR/changed-bits diff report. |
| **Onboarding tour** | 5-step spotlight tour (`components/onboarding/TourGuide.tsx`) auto-launched on first login: Mode Switcher → Dropzone/SHA-256 → Security & Encryption → Local Vault/PC Backup → Hex Inspector. Skippable, replayable from Settings. |
| **Hover tooltips** | `<Tooltip>`/`(?)` badge system on every technical term: LSB, PSNR, AES-256-GCM, EXIF, PBKDF2, IndexedDB, FSA, chi-square, SSIM, threat score. |
| **Docs & legal** | **About** modal (two-tier: plain-language *At a Glance* — what it is, how it protects you, supported mediums grid — with *Under the Hood* technical specs in a collapsible auditor accordion) · **User Manual & Technical Glossary** (searchable; How-To Guides + glossary table) · **Privacy Policy & Terms of Service** (first-run notice with *Acknowledge & Close*). |
| **Local Vault & Backups** | Live IndexedDB journal (Dexie `useLiveQuery`), history table with Download / View Payload / Delete, `.stegvault` export/import, PC folder binding via File System Access API, one-click purge. |
| **Footer console** | Collapsible hexadecimal + LSB-binary inspector of the last in-RAM buffers, plus persistent status bar (session, crypto, IndexedDB record count, worker mode, `TELEMETRY: DISABLED`). |

## Architecture notes

- `lib/crypto.ts` — PBKDF2 KDF, AES-GCM/CTR, SHA-256, sealed-payload format, key wrapping.
- `lib/lsbcore.ts` / `lib/worker.ts` — `SBV2` container over the R/G/B LSB plane; identical algorithm runs in an inline Blob Web Worker with a mirrored main-thread fallback.
- `lib/analysis.ts` — steganalysis statistics + PSNR/SSIM-lite quality metrics.
- `lib/exif.ts` — minimal TIFF/IFD0 + GPS sub-IFD reader for metadata previews.
- `lib/vault.ts` — Dexie IndexedDB journal, `.stegvault` manifest, demo history seeding.
- `lib/session.tsx` — the RAM-only key holder, auto-lock lifecycle, settings, artifacts and system log.
- `lib/engineApi.ts` — typed client for the optional Java engine at `http://localhost:8080/api/v1/stego`; wired into Settings → Java Engine (Hide/Extract delegate when enabled).

Zero network calls are made with user data: the app contains no `fetch`/XHR targets, no external fonts, no analytics.

## StegoBolt Engine (Java 17 / Spring Boot 3.x)

`stegobolt-engine/` is the production-grade **100% Java** backend for operators who
want server-side steganography processing with zero-knowledge guarantees:

- **REST surface** — `POST /api/v1/stego/{hide,extract,scan,clean,capacity}` over `multipart/form-data`.
- **All six mediums** — Image (pixel LSB via `BufferedImage`/`ImageIO`), Audio (WAV sample LSB via `javax.sound.sampled`), Video (frame LSB / container padding), Documents (hidden PDF/DOCX streams), Text/Code (zero-width Unicode + trailing whitespace), Network (PCAP IP-ID header LSBs).
- **JCA crypto** — `PBKDF2WithHmacSHA256` @ 100k + `AES/GCM/NoPadding`, `SecureRandom` salts/IVs.
- **Pure-Java steganalysis** — Westfeld chi-square, sample-pair analysis (SPA), LSB entropy, `commons-imaging` EXIF enumeration.
- **Zero-disk / zero-log** — volatile RAM only (multipart threshold set to 2 GiB, uploads capped at 64 MiB), every buffer zero-wiped in `finally` blocks, no payload logging anywhere.
- **Verified** — the full source tree type-checks under ECJ (Eclipse Compiler for Java 3.39, `-source/-target 17`) against Spring/Jackson/slf4j/commons-imaging API stubs, the JUnit suite (24 tests) and a 34-check round-trip smoke matrix (PNG/WAV/FLAC/MP4/MKV/DOCX/PDF/PCAP + service-level end-to-end) run green on a real JVM, and CI runs `mvn -B test` on every push.

See [`stegobolt-engine/README.md`](stegobolt-engine/README.md) for the full API reference.

## Security disclaimer

StegoBolt is provided **as-is**, for legitimate security research, forensics, and operational privacy. A lost master passphrase is mathematically unrecoverable — keep your `.stegvault` exports and media files safe.
