# ⚡ StegoBolt v2.0 — Zero-Knowledge Steganography Suite

Production-grade, local-first steganography & media sanitization web app.
Image work runs **100% in the browser**; the optional Java 17 engine handles all six carrier families when explicitly enabled. No accounts. No telemetry. Local-mode cover files, payloads and keys never leave the device.

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
| **Hide (Encode)** | One dropzone accepts PNG/BMP/WebP/GIF/TIFF/JPEG, WAV/FLAC, MP4/MKV/AVI, PDF/DOCX, text/code and PCAP/PCAPNG. Images stay local with the Web Worker pipeline; the Java engine supplies capacity preflight and Hide for every medium. |
| **Extract (Decode)** | Local SBV2/GCM recovery for images; Java engine extraction for every supported medium, with the JSON recovery report surfaced in the console. |
| **Forensic Scan** | Local image scan or the Java engine’s medium-aware report for all six carrier families. Verdicts separate a *confirmed* SBV2/SBV2-J container from strong statistical suspicion, inconclusive irregularity and clean media — see [Forensic Scan verdicts](#forensic-scan-verdicts). |
| **Sanitize & Clean** | Local image metadata/LSB cleaning, or Java engine `/clean` for audio, video, documents, text/code and network captures; binary output plus the engine report is shown before download. |
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
- `lib/engineApi.ts` — typed client for the optional Java engine at `http://localhost:8080/api/v1/stego`; wired into Settings → Java Engine (capacity, Hide, Extract, Scan and Clean delegate when enabled).

Local mode makes no network calls with user data. Selecting Java engine mode explicitly sends the carrier to the configured Java service; the Java side is RAM-only and does not persist uploads, outputs or recovered payloads.

## Forensic Scan verdicts

Forensic Scan answers one question first: **was a StegoBolt container actually found?**
A signature hit is the only thing that can produce a confirmed verdict; everything
else is statistical suspicion and is worded that way.

| Level | Confidence | Verdict code | Meaning |
| --- | --- | --- | --- |
| `LOW` | `CLEAN` | `CLEAN` | No container and no meaningful statistical irregularity. |
| `LOW` | `INCONCLUSIVE` | `INCONCLUSIVE` | Sample too small, or the medium has no LSB sample plane — statistics cannot decide either way. |
| `ELEVATED` | `INCONCLUSIVE` | `INCONCLUSIVE` | Weak statistical irregularity only; no direct evidence of an embedded message. |
| `HIGH` | `SUSPICIOUS` | `STRONG_STATISTICAL_SUSPICION` | Two independent detectors agree on an embedding-like layer, but no signature: strong suspicion, never a confirmed payload. |
| `HIGH` | `SUSPICIOUS` | `DAMAGED_CONTAINER` | SBV2/SBV2-J magic present but the header is inconsistent — the carrier was modified or truncated. |
| `CRITICAL` | `CONFIRMED` | `CONFIRMED_CONTAINER` | A validated SBV2 (image) or SBV2-J (engine) container header was read from the medium. |

Calibration rules shared by `lib/analysis.ts` and `SteganalysisEngine`:

- The chi-square statistic is converted through the correct survival function
  (`Q(df/2, χ²/2)`) and then variance-gated (`z = (χ² − df)/√(2·df)`). A high
  chi-square probability is *not* evidence on its own and can never produce
  `ELEVATED` or `HIGH`.
- `ELEVATED`/`HIGH` require sample-pair analysis (SPA) **and** chi-square
  equalisation to agree, weighted by sample size, so one dominating detector
  cannot flag a carrier.
- Channel bias (e.g. an LSB ones ratio of 0.598), entropy near 1.0 and long-run
  anomalies are *supporting* signals only; they are shown as indicators but do
  not move the level without detector agreement.
- Statistics are only computed where a sample plane exists: image pixels, WAV
  PCM, uncompressed AVI frames. FLAC/MP4/MKV, PDF/DOCX, text/code and
  PCAP/PCAPNG carriers are judged structurally (padding blocks, hidden OPC parts,
  zero-width/trailing-whitespace runs, IPv4 ID LSBs) and report
  `sampleBased: false`.
- Absence of a signature is stated explicitly in the summary; no verdict claims
  an embedded message, only "confirmed container" (validated header) or
  "statistical suspicion" (no header found).

Regression fixtures for each of these rows live in `scripts/scan-fixtures.ts`
(TS pipeline suite) and `stegobolt-engine/src/test/java/.../MediaFixtures.java`
(Java suite: `ScanCalibrationTest`, `MediumScanMatrixTest`).

## StegoBolt Engine (Java 17 / Spring Boot 3.x)

`stegobolt-engine/` is the production-grade **100% Java** backend for operators who
want server-side steganography processing with zero-knowledge guarantees:

- **REST surface** — `POST /api/v1/stego/{hide,extract,scan,clean,capacity}` over `multipart/form-data`.
- **All six mediums** — Image (pixel LSB via `BufferedImage`/`ImageIO`), Audio (WAV sample LSB via `javax.sound.sampled`), Video (frame LSB / container padding), Documents (hidden PDF/DOCX streams), Text/Code (zero-width Unicode + trailing whitespace), Network (PCAP IP-ID header LSBs).
- **JCA crypto** — `PBKDF2WithHmacSHA256` @ 100k + `AES/GCM/NoPadding`, `SecureRandom` salts/IVs.
- **Pure-Java steganalysis** — Westfeld chi-square, sample-pair analysis (SPA), LSB entropy, `commons-imaging` EXIF enumeration.
- **Zero-disk / zero-log** — volatile RAM only (multipart threshold set to 2 GiB, uploads capped at 64 MiB), every buffer zero-wiped in `finally` blocks, no payload logging anywhere.
- **Verified** — the full source tree compiles under ECJ (Eclipse Compiler for Java 3.39, `-source/-target 17`) against Spring/Jackson/slf4j/commons-imaging API stubs. The JUnit suite now holds 49 tests: 42 analysis/core/crypto/engine tests (including the `ScanCalibrationTest` false-positive regressions and the `MediumScanMatrixTest` six-medium scan matrix) execute green on a real JVM through a reflective runner, and the 7 Spring `MockMvc` tests compile against the same stubs. CI runs `mvn -B test` on every push.

See [`stegobolt-engine/README.md`](stegobolt-engine/README.md) for the full API reference.

## Security disclaimer

StegoBolt is provided **as-is**, for legitimate security research, forensics, and operational privacy. A lost master passphrase is mathematically unrecoverable — keep your `.stegvault` exports and media files safe.
