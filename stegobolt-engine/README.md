# ⚡ StegoBolt Engine v2.0 — Java Backend

**100% Java 17 / Spring Boot 3.x** in-memory steganography engine for StegoBolt.
No Node.js, no Python, no serverless routes — the Next.js workspace is a pure
client layer that may delegate to `http://localhost:8080/api/v1/stego`.

## Privacy contract (enforced in code)

| Rule | How it is enforced |
| --- | --- |
| **Zero-disk / zero-knowledge** | Uploads stay in RAM (`spring.servlet.multipart.file-size-threshold=2147483647`), all engine I/O uses `java.io.ByteArrayInputStream` / `ByteArrayOutputStream` only. No JPA, no files, no `/tmp`. |
| **Volatile RAM purging** | Every media/payload `byte[]` is registered in a `StegoService.WorkResult` and overwritten with `Arrays.fill(buf, (byte) 0)` in `finally` blocks — for binary endpoints immediately after the response stream is written (`StreamingResponseBody` lambda). |
| **Zero payload logging** | Loggers report operation, medium and byte counts only. Payload contents, passphrases and raw bit matrices never reach the log. Error bodies carry safe status strings. |

## Quick start

```bash
cd stegobolt-engine
mvn spring-boot:run        # http://localhost:8080
mvn test                   # unit + REST integration suite
```

## REST API (`multipart/form-data`)

`GET /` returns a small non-sensitive health page. Client-shaped mistakes are
mapped to friendly `400`, `405`, `413` or `415` JSON bodies instead of the
catch-all engine failure response.

| Endpoint | Fields | Response |
| --- | --- | --- |
| `POST /api/v1/stego/hide` | `cover` (file), `payload` (file) **or** `payloadText`, `passphrase`, `textMode?` | stego media (`application/octet-stream`) + `X-StegoBolt-Report` JSON header |
| `POST /api/v1/stego/extract` | `cover`, `passphrase`, `textMode?` | `ExtractReport` JSON (recovered text/base64) |
| `POST /api/v1/stego/scan` | `cover`, `textMode?` | `ScanReport` JSON (verdict + level/confidence/summary, chi-square, SPA, entropy, threat score, EXIF) |
| `POST /api/v1/stego/clean` | `cover`, `randomizeLsb?`, `textMode?` | sanitized media + `X-StegoBolt-Report` JSON header |
| `POST /api/v1/stego/capacity` | `cover`, `textMode?` | `CapacityReport` JSON |

### `ScanReport` and how the verdict is derived

`/scan` reports the raw numbers *and* the classification, so an operator can audit
the decision instead of trusting a single score:

```
medium, carrierBytes,
chiSquareStatistic, chiSquareProbability, spaEmbeddingRatio,
lsbOnesRatio, lsbEntropy, windowedEntropy,
containerSignatureFound, threatScore,
indicators[], exifTags[],
level, confidence, summary, analysisBasis, sampleBased, sampleSize, verdict
```

| `verdict` | `level` / `confidence` | Meaning |
| --- | --- | --- |
| `CONFIRMED_CONTAINER` | `CRITICAL` / `CONFIRMED` | A validated SBV2-J container was extracted (score ≥ 90). |
| `DAMAGED_CONTAINER` | `HIGH` / `SUSPICIOUS` | `SB2J` magic present, header inconsistent; payload unreadable. |
| `STRONG_STATISTICAL_SUSPICION` | `HIGH` / `SUSPICIOUS` | SPA **and** chi-square equalisation agree, no signature found. Capped at 88. |
| `INCONCLUSIVE` | `ELEVATED` / `INCONCLUSIVE` | Weak statistical irregularity, or a structural medium with no embedding layer. |
| `CLEAN` | `LOW` / `CLEAN` | No container and no meaningful anomaly. |

- `chiSquareProbability` is `Q(df/2, χ²/2)`, i.e. the probability of an *even
  better* pair fit — a high value is **not** evidence of embedding and is never
  used alone. `SteganalysisEngine.Stats.chiEqualization()` applies
  `z = (χ² − df)/√(2·df)`, a sample-size gate and a degrees-of-freedom gate
  before chi-square contributes to the level.
- `ELEVATED`/`HIGH` require SPA ≥ 0.6 **and** corrobating equalisation, so a
  single dominating detector cannot raise the level. Channel imbalance
  (`lsbOnesRatio` ≈ 0.6), entropy ≈ 1.0 and long-run anomalies appear in
  `indicators` as supporting evidence only.
- `sampleBased` is `false` for PDF/DOCX, text/code, FLAC, MP4/MKV and PCAP/PCAPNG
  captures: those carriers are judged structurally (hidden OPC part, zero-width
  run, PADDING block, `free`/`Void` element, IPv4 ID LSBs) and the image-style
  numbers must be ignored. Such carriers report score 8, `LOW`, `INCONCLUSIVE`
  unless a signature is found.
- The summary always states whether a container was found; weak evidence is
  worded as "inconclusive", never as an embedded message.

CORS allows local Next.js origins plus the supported Vercel and Arena preview origins; the engine does not use CORS as an authentication boundary.

## The six supported mediums

1. **Image (PNG, BMP, WebP, GIF, TIFF, JPEG)** — `ImageStegoEngine`: LSB of R/G/B pixel channels via `java.awt.image.BufferedImage` + `javax.imageio.ImageIO`, always re-encoded as lossless PNG.
2. **Audio (WAV, FLAC)** — `AudioStegoEngine`: WAV secrets ride the PCM sample noise floor (`javax.sound.sampled`); FLAC secrets live in a hidden PADDING metadata block.
3. **Video (MP4, MKV, AVI)** — `VideoStegoEngine`: uncompressed AVI frames get frame-LSB embedding; MP4/MKV use hidden structural padding (`free` box / EBML Void) so playback stays bit-perfect.
4. **Document (PDF, DOCX)** — `DocumentStegoEngine`: DOCX gets a hidden OPC part (`word/stegobolt.bin`); PDF gets an invisible metadata stream via a spec-correct incremental update (xref + `/Prev` trailer).
5. **Text & source code (TXT, MD, Java, JS, TS, C, C++, H, HPP, PY, JSON, CSV)** — `TextStegoEngine`: zero-width Unicode (`\u200B`=0, `\u200C`=1) or trailing-whitespace bits (space=0, tab=1). Extraction is self-synchronizing (SB2J magic hunt).
6. **Network / covert channels (PCAP, PCAPNG)** — `NetworkStegoEngine`: one secret bit per IPv4 packet in the LSB of the IP Identification header field (the classic TCP/IP header-padding channel). The packet-timing variant is documented below.

## Container format — SBV2-J

```
offset  size  field
0       4     magic 'S''B''2''J'
4       1     version 0x02
5       1     medium id
6       1     flags (bit0 = AES-256-GCM sealed)
7       1     reserved
8       4     ciphertext length (big-endian)
12      16    PBKDF2 salt
28      12    AES-GCM IV
40      n     ciphertext (incl. 16-byte GCM tag)
```

## Crypto (JCA only)

- `PBKDF2WithHmacSHA256` @ **100,000 iterations**, 256-bit key, 16-byte salt (`java.security.SecureRandom`).
- `AES/GCM/NoPadding`, 128-bit tag, 96-bit IV. Wrong passphrase or a single tampered carrier bit fails the GCM tag — never garbage.
- Derived keys wiped with `Arrays.fill(..., (byte) 0)` in `finally` blocks.

## Forensic steganalysis (pure Java math)

- **Chi-Square (Westfeld value-pair attack)** — pair populations (2i, 2i+1), statistic mapped through a hand-rolled regularized incomplete gamma.
- **Sample Pair Analysis (SPA)** — Dumitrescu-style pair-category estimator (type A: poised pair with even smaller value erodes into identical pairs; type B scatters). First-order, one-shot sequential replacement model — treated as supporting evidence alongside chi-square.
- **LSB noise/entropy** — ones-ratio, binary entropy, windowed Shannon entropy.
- **EXIF** — `org.apache.commons.imaging` tag enumeration for `/scan` and `/clean` (clean re-encodes through ImageIO, dropping every ancillary tag).

## Notes & limits

- The covert **timing channel** (packet-arrival intervals) requires an active network tap; the offline PCAP path embeds in IP-ID header LSBs instead.
- Lossy formats (JPEG recompression, re-encoded MP3) destroy embedding layers by nature — use lossless carriers.
- PDF incremental updates keep the original bytes untouched; `clean` truncates the appended StegoBolt update. For full forensic resanitization, re-export the PDF through a renderer.
