package com.stegobolt.engine.service;

import com.stegobolt.engine.analysis.SteganalysisEngine;
import com.stegobolt.engine.api.dto.CleanReport;
import com.stegobolt.engine.api.dto.ExtractReport;
import com.stegobolt.engine.api.dto.ScanReport;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.Sniffer;
import com.stegobolt.engine.core.StegoException;
import com.stegobolt.engine.crypto.CryptoEngine;
import com.stegobolt.engine.engine.AudioStegoEngine;
import com.stegobolt.engine.engine.DocumentStegoEngine;
import com.stegobolt.engine.engine.ImageStegoEngine;
import com.stegobolt.engine.engine.NetworkStegoEngine;
import com.stegobolt.engine.engine.StegoEngine;
import com.stegobolt.engine.engine.TextStegoEngine;
import com.stegobolt.engine.engine.VideoStegoEngine;
import com.stegobolt.engine.exif.ExifSanitizer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Orchestration layer — routes carriers to the six medium engines, seals/opens
 * payloads through {@link CryptoEngine}, and owns the volatile-RAM purge.
 *
 * <p>Every method returns a {@link WorkResult} that tracks <b>all</b> sensitive
 * buffers allocated during the call (inputs included). The controller MUST call
 * {@link WorkResult#close()} in a {@code finally} block — or immediately after
 * the response stream is written — at which point every tracked buffer is
 * overwritten with {@code Arrays.fill(buf, (byte) 0)}.
 */
public final class StegoService {

    private final ImageStegoEngine imageEngine = new ImageStegoEngine();
    private final AudioStegoEngine audioEngine = new AudioStegoEngine();
    private final VideoStegoEngine videoEngine = new VideoStegoEngine();
    private final DocumentStegoEngine documentEngine = new DocumentStegoEngine();
    private final NetworkStegoEngine networkEngine = new NetworkStegoEngine();

    /**
     * One processed request: the response media/report plus every buffer that
     * must be purged from RAM. {@link #close()} is the single wipe point.
     */
    public static final class WorkResult implements AutoCloseable {
        private final List<byte[]> tracked = new ArrayList<>();
        private byte[] out;
        private Object report;
        private String fileName = "stego.bin";

        void track(byte[]... buffers) {
            for (byte[] buffer : buffers) {
                if (buffer != null) {
                    tracked.add(buffer);
                }
            }
        }

        public byte[] out() {
            return out;
        }

        @SuppressWarnings("unchecked")
        public <T> T report() {
            return (T) report;
        }

        public String fileName() {
            return fileName;
        }

        /** Zero-wipe every tracked buffer — idempotent. */
        @Override
        public void close() {
            MemoryHygiene.wipe(tracked.toArray(new byte[0][]));
            tracked.clear();
            out = null;
            report = null;
        }
    }

    /* ------------------------------------------------------------------ */
    /* /hide                                                               */
    /* ------------------------------------------------------------------ */

    public WorkResult hide(byte[] cover, byte[] payload, char[] passphrase,
                           String coverName, String textMode) {
        WorkResult work = new WorkResult();
        boolean handedOff = false;
        try {
            if (payload == null || payload.length == 0) {
                throw new StegoException("A payload is required (payload file or payloadText)");
            }
            if (passphrase == null || passphrase.length == 0) {
                throw new StegoException("A passphrase is required");
            }
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);
            long capacity = engine.capacityBits(cover);
            // The capacity contract is plaintext bytes. SBV2-J contributes a
            // 40-byte frame and AES-GCM contributes its 16-byte tag.
            long needed = (payload.length + Packet.PLAINTEXT_OVERHEAD) * 8L;
            if (needed > capacity) {
                throw new StegoException("Payload too large for this " + medium.label().toLowerCase()
                        + " — capacity is " + Math.max(0, capacity / 8 - Packet.PLAINTEXT_OVERHEAD)
                        + " plaintext bytes after the SBV2-J frame and GCM tag");
            }

            Packet packet = CryptoEngine.seal(payload, passphrase, medium);
            byte[] container = null;
            try {
                container = packet.serialize();
                byte[] stego = engine.hide(cover, container);

                Double psnr = null;
                if (medium == Medium.IMAGE) {
                    psnr = ImageStegoEngine.psnr(cover, stego);
                }
                String name = stegoFileName(stego, medium, coverName);
                work.out = stego;
                work.fileName = name;
                work.report = new com.stegobolt.engine.api.dto.HideReport(
                        medium.label(),
                        name,
                        stego.length,
                        payload.length,
                        (long) container.length * 8L,
                        psnr,
                        sha256(stego));
                work.track(cover, payload, container, stego);
                handedOff = true;
                return work;
            } finally {
                MemoryHygiene.wipe(container);
                packet.wipe();
            }
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover, payload);
                work.close();
            }
            throw e;
        }
    }

    /* ------------------------------------------------------------------ */
    /* /extract                                                            */
    /* ------------------------------------------------------------------ */

    public WorkResult extract(byte[] cover, char[] passphrase, String coverName, String textMode) {
        WorkResult work = new WorkResult();
        boolean handedOff = false;
        byte[] container = null;
        byte[] plaintext = null;
        try {
            if (passphrase == null || passphrase.length == 0) {
                throw new StegoException("A passphrase is required");
            }
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);
            container = engine.extract(cover);
            if (container == null) {
                work.report = new ExtractReport(medium.label(), false, null, null, 0, null);
                work.track(cover);
                handedOff = true;
                return work;
            }
            Packet packet = Packet.parse(container, 0);
            try {
                plaintext = CryptoEngine.open(packet, passphrase);
                String text = looksLikeUtf8(plaintext) ? new String(plaintext, StandardCharsets.UTF_8) : null;
                String b64 = Base64.getEncoder().encodeToString(plaintext);
                work.report = new ExtractReport(
                        medium.label(), true, text, b64, plaintext.length, sha256(plaintext));
                work.out = plaintext;
                work.track(cover, container, plaintext);
                handedOff = true;
                return work;
            } finally {
                packet.wipe();
            }
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover, container, plaintext);
                work.close();
            }
            throw e;
        }
    }

    /* ------------------------------------------------------------------ */
    /* /scan                                                               */
    /* ------------------------------------------------------------------ */

    public WorkResult scan(byte[] cover, String coverName, String textMode) {
        WorkResult work = new WorkResult();
        boolean handedOff = false;
        byte[] sampleStream = null;   // stream used by the statistical detectors
        byte[] probeStream = null;    // bit-plane stream used by the signature probe
        byte[] embedded = null;
        try {
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);

            boolean sampleBased = false;
            String mediumNoun = medium.label().toLowerCase(java.util.Locale.ROOT);
            String basis;
            long structuralSamples = 0;

            boolean pixelDecodeFailed = false;
            switch (medium) {
                case IMAGE -> {
                    try {
                        sampleStream = ImageStegoEngine.embeddableSamples(cover);
                    } catch (RuntimeException e) {
                        // Some variants (e.g. WebP without a decoder plugin) cannot be
                        // rasterised by ImageIO. Fall back to a structural report
                        // instead of failing the whole scan.
                        sampleStream = null;
                        pixelDecodeFailed = true;
                    }
                    if (sampleStream != null) {
                        probeStream = sampleStream;
                        sampleBased = true;
                        basis = "Pixel LSB plane · R/G/B channels · " + (sampleStream.length / 3)
                                + " pixels (" + sampleStream.length + " bit slots)";
                        structuralSamples = sampleStream.length;
                    } else {
                        basis = "Image container structure only (this image variant is not decodable by the "
                                + "built-in rasterizer, so pixel LSB statistics are unavailable)";
                    }
                }
                case AUDIO -> {
                    if (AudioStegoEngine.isFlac(cover)) {
                        basis = "FLAC metadata padding layer (structural inspection — compressed frames are not LSB-analysed)";
                    } else {
                        sampleStream = AudioStegoEngine.sampleStream(cover);
                        probeStream = sampleStream;
                        sampleBased = true;
                        basis = "PCM sample LSB plane · " + sampleStream.length + " sample bytes";
                        structuralSamples = sampleStream.length;
                    }
                }
                case VIDEO -> {
                    sampleStream = VideoStegoEngine.frameSampleStream(cover);
                    if (sampleStream == null) {
                        basis = "MP4/MKV container padding (structural inspection — compressed video frames are not LSB-analysed)";
                    } else {
                        probeStream = sampleStream;
                        sampleBased = true;
                        basis = "AVI uncompressed frame LSB plane · " + sampleStream.length + " frame bytes";
                        structuralSamples = sampleStream.length;
                    }
                }
                case DOCUMENT -> basis = "PDF/DOCX hidden structural stream (structural inspection — file bytes are not LSB-analysed)";
                case TEXT -> basis = "Zero-width Unicode / trailing-whitespace covert layer (structural inspection — text bytes are not LSB-analysed)";
                case NETWORK -> {
                    probeStream = NetworkStegoEngine.ipIdSamples(cover);
                    structuralSamples = probeStream.length;
                    basis = "IPv4 Identification header LSBs · " + probeStream.length
                            + " packets (header bit plane only — capture bytes are not LSB-analysed)";
                }
                default -> basis = "Structural inspection";
            }

            // ---- statistical detectors (only where they are meaningful) ----
            SteganalysisEngine.Stats stats;
            if (sampleStream != null) {
                stats = SteganalysisEngine.analyze(sampleStream);
            } else if (medium == Medium.NETWORK) {
                stats = SteganalysisEngine.Stats.structural(probeStream == null ? 0 : probeStream.length,
                        SteganalysisEngine.lsbOnesRatio(probeStream));
            } else {
                stats = SteganalysisEngine.Stats.structural(0);
            }

            // ---- container signature ----------------------------------------
            try {
                embedded = engine.extract(cover);
            } catch (RuntimeException e) {
                // An unreadable container layer must never abort the report; the
                // verdict then rests on the structural evidence that remains.
                embedded = null;
            }
            SteganalysisEngine.SignatureState signature;
            if (embedded != null) {
                signature = SteganalysisEngine.SignatureState.CONFIRMED;
            } else if (probeStream != null) {
                signature = SteganalysisEngine.probeBitPlane(probeStream);
            } else if (medium == Medium.DOCUMENT && DocumentStegoEngine.hasHiddenLayer(cover)) {
                signature = SteganalysisEngine.SignatureState.MALFORMED;
            } else if (medium == Medium.TEXT) {
                TextStegoEngine.TextInspection text = TextStegoEngine.inspect(cover);
                signature = text.sb2jMarkerPresent()
                        ? SteganalysisEngine.SignatureState.MALFORMED
                        : SteganalysisEngine.SignatureState.ABSENT;
            } else {
                signature = SteganalysisEngine.probeStructuralBytes(cover);
            }

            SteganalysisEngine.Verdict verdict =
                    SteganalysisEngine.assess(stats, signature, mediumNoun, basis);

            // ---- medium-appropriate indicators -------------------------------
            List<String> indicators = new ArrayList<>();
            switch (signature) {
                case CONFIRMED -> indicators.add(
                        "SBV2-J container signature found and validated in the " + layerDescription(medium) + ".");
                case MALFORMED -> indicators.add(
                        "SBV2-J framing detected in the " + layerDescription(medium)
                                + " but the header is inconsistent — the carrier was probably modified or truncated.");
                case ABSENT -> {
                    // fall through to the per-medium evidence below
                }
            }
            if (signature != SteganalysisEngine.SignatureState.CONFIRMED) {
                switch (medium) {
                    case IMAGE, AUDIO -> {
                        if (sampleBased) {
                            addStatisticalIndicators(indicators, stats);
                        } else {
                            indicators.add("No SB2J marker in the FLAC padding metadata blocks.");
                        }
                    }
                    case VIDEO -> {
                        if (sampleBased) {
                            addStatisticalIndicators(indicators, stats);
                        } else {
                            indicators.add("No SB2J marker in MP4 free boxes or MKV Void elements.");
                        }
                    }
                    case DOCUMENT -> indicators.add(
                            "No hidden SB2J stream in the PDF incremental-update area or the DOCX package parts.");
                    case TEXT -> {
                        TextStegoEngine.TextInspection text = TextStegoEngine.inspect(cover);
                        indicators.add("Zero-width characters: " + text.zeroWidthChars()
                                + " · trailing-whitespace lines: " + text.trailingWhitespaceLines()
                                + " · SB2J framing: " + (text.sb2jMarkerPresent() ? "present" : "absent") + ".");
                        if (text.zeroWidthChars() == 0 && text.trailingWhitespaceLines() == 0) {
                            indicators.add("No covert-text layer detected — the document is plain text/code.");
                        }
                    }
                    case NETWORK -> indicators.add("IPv4 ID header LSB ones ratio "
                            + String.format("%.3f", stats.lsbOnesRatio()) + " over "
                            + structuralSamples + " packets · no SB2J framing in the header bit plane.");
                }
            }
            if (verdict.level() == SteganalysisEngine.Level.ELEVATED) {
                indicators.add("Statistical irregularities are inconclusive — no StegoBolt container was found.");
            }
            if (pixelDecodeFailed) {
                indicators.add("Pixel LSB statistics are unavailable for this image variant; "
                        + "no StegoBolt container signature was found in the container structure.");
            }

            List<String> exifTags = medium == Medium.IMAGE ? ExifSanitizer.listTags(cover) : List.of();
            work.report = new ScanReport(
                    medium.label(),
                    cover.length,
                    stats.chiSquareStatistic(),
                    stats.chiSquareProbability(),
                    stats.spaEmbeddingRatio(),
                    stats.lsbOnesRatio(),
                    stats.lsbEntropy(),
                    stats.windowedEntropy(),
                    signature == SteganalysisEngine.SignatureState.CONFIRMED,
                    verdict.score(),
                    indicators,
                    exifTags,
                    verdict.level().name(),
                    verdict.confidence().name(),
                    verdict.summary(),
                    verdict.basis(),
                    stats.sampleBased(),
                    stats.sampleBased() ? stats.samples() : structuralSamples,
                    verdict.code());
            work.track(cover, sampleStream, probeStream == sampleStream ? null : probeStream, embedded);
            handedOff = true;
            return work;
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover, sampleStream, probeStream == sampleStream ? null : probeStream, embedded);
                work.close();
            }
            throw e;
        }
    }

    /** Human-readable name of the layer a container would occupy. */
    private static String layerDescription(Medium medium) {
        return switch (medium) {
            case IMAGE -> "pixel LSB plane";
            case AUDIO -> "audio sample/padding layer";
            case VIDEO -> "video frame or padding layer";
            case DOCUMENT -> "hidden document stream";
            case TEXT -> "covert text layer (zero-width/whitespace)";
            case NETWORK -> "IPv4 ID header bit plane";
        };
    }

    /**
     * Medium-appropriate statistical indicators. A single detector is always
     * described as an isolated, inconclusive observation — never as embedding.
     */
    private static void addStatisticalIndicators(List<String> indicators, SteganalysisEngine.Stats stats) {
        double eq = stats.chiEqualization();
        double spa = stats.spaEvidence();
        if (eq >= 0.55 && spa >= 0.55) {
            indicators.add("Two independent detectors agree: value pairs are equalised (p="
                    + String.format("%.2e", stats.chiSquareProbability())
                    + ") and sample-pair analysis estimates an embedding rate of "
                    + String.format("%.2f", stats.spaEmbeddingRatio()) + ".");
        } else {
            if (eq >= 0.3) {
                indicators.add("Value pairs are partially equalised (p="
                        + String.format("%.2e", stats.chiSquareProbability())
                        + ") — a single indicator, inconclusive on its own.");
            }
            if (spa >= 0.3) {
                indicators.add("Sample-pair analysis estimates an embedding rate of "
                        + String.format("%.2f", stats.spaEmbeddingRatio())
                        + " — a single indicator, uncorroborated.");
            }
        }
        if (Math.abs(stats.lsbOnesRatio() - 0.5) > 0.06) {
            indicators.add("LSB ones ratio " + String.format("%.3f", stats.lsbOnesRatio())
                    + " deviates from 0.500 — normal for textured, quantised or saturated media and not "
                    + "embedding evidence on its own.");
        }
        if (indicators.isEmpty()) {
            indicators.add("No statistical evidence of steganographic embedding.");
        }
    }

    /* ------------------------------------------------------------------ */
    /* /clean                                                              */
    /* ------------------------------------------------------------------ */

    public WorkResult clean(byte[] cover, boolean randomizeLsb, String coverName, String textMode) {
        WorkResult work = new WorkResult();
        boolean handedOff = false;
        byte[] current = cover;
        try {
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);

            int exifRemoved = 0;
            if (medium == Medium.IMAGE) {
                exifRemoved = ExifSanitizer.listTags(cover).size();
                current = ExifSanitizer.strip(cover);
            }
            StegoEngine.SanitizeOutcome outcome = engine.sanitize(current, randomizeLsb);
            Double psnr = medium == Medium.IMAGE ? ImageStegoEngine.psnr(cover, outcome.cleaned()) : null;

            work.out = outcome.cleaned();
            work.fileName = stegoFileName(outcome.cleaned(), medium, coverName);
            work.report = new CleanReport(
                    medium.label(),
                    cover.length,
                    outcome.cleaned().length,
                    exifRemoved,
                    outcome.reRandomizedBits(),
                    outcome.changedBits(),
                    psnr);
            work.track(cover, current, outcome.cleaned());
            handedOff = true;
            return work;
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover, current == cover ? null : current);
                work.close();
            }
            throw e;
        }
    }

    /* ------------------------------------------------------------------ */
    /* /capacity                                                           */
    /* ------------------------------------------------------------------ */

    public WorkResult capacity(byte[] cover, String coverName, String textMode) {
        WorkResult work = new WorkResult();
        boolean handedOff = false;
        try {
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);
            long capacityBits = engine.capacityBits(cover);
            // Report usable plaintext headroom, not raw container room. This
            // keeps the UI's preflight result exactly aligned with /hide.
            long capacityBytes = capacityBits / 8 - Packet.PLAINTEXT_OVERHEAD;
            if (capacityBytes < 0) {
                capacityBytes = 0;
            }
            String details = switch (medium) {
                case IMAGE -> "R/G/B pixel channel LSB plane";
                case AUDIO -> "PCM sample noise floor (FLAC: hidden padding block)";
                case VIDEO -> "frame LSB layer (AVI) / container padding (MP4, MKV)";
                case DOCUMENT -> "hidden structural metadata stream";
                case TEXT -> TextStegoEngine.MODE_TRAILING_WS.equals(textMode)
                        ? "trailing whitespace (1 bit per line)"
                        : "zero-width Unicode spaces";
                case NETWORK -> "IPv4 Identification header LSBs (1 bit per packet)";
            };
            work.report = new com.stegobolt.engine.api.dto.CapacityReport(
                    medium.label(),
                    cover.length,
                    capacityBits,
                    capacityBytes,
                    capacityBytes * 4, // rough UTF-8 char allowance
                    details);
            work.track(cover);
            handedOff = true;
            return work;
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover);
                work.close();
            }
            throw e;
        }
    }

    /* ------------------------------------------------------------------ */
    /* helpers                                                             */
    /* ------------------------------------------------------------------ */

    private StegoEngine engineFor(Medium medium, String textMode) {
        return switch (medium) {
            case IMAGE -> imageEngine;
            case AUDIO -> audioEngine;
            case VIDEO -> videoEngine;
            case DOCUMENT -> documentEngine;
            case TEXT -> new TextStegoEngine(textMode);
            case NETWORK -> networkEngine;
        };
    }

    private static byte[] sampleStream(Medium medium, byte[] cover) {
        return switch (medium) {
            case IMAGE -> ImageStegoEngine.embeddableSamples(cover);
            case AUDIO -> AudioStegoEngine.sampleStream(cover);
            default -> cover;
        };
    }

    private static boolean looksLikeUtf8(byte[] data) {
        String decoded = new String(data, StandardCharsets.UTF_8);
        return decoded.indexOf('\uFFFD') < 0; // no replacement chars → valid UTF-8
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new StegoException("SHA-256 unavailable", e);
        }
    }

    private static String stegoFileName(byte[] stego, Medium medium, String coverName) {
        String inputExt = extensionOf(coverName);
        String ext = switch (medium) {
            case IMAGE -> ".png"; // ImageStegoEngine deliberately re-encodes losslessly.
            case AUDIO -> inputExt.equals(".flac") ? ".flac" : ".wav";
            case VIDEO -> switch (inputExt) {
                case ".mp4", ".mkv", ".avi" -> inputExt;
                default -> ".bin";
            };
            case DOCUMENT -> switch (inputExt) {
                case ".pdf", ".docx" -> inputExt;
                default -> ".bin";
            };
            case TEXT -> inputExt.isEmpty() ? ".txt" : inputExt;
            case NETWORK -> inputExt.equals(".pcapng") ? ".pcapng" : ".pcap";
        };
        String hash = sha256(stego).substring(0, 12);
        return "stegobolt-" + hash + ext;
    }

    private static String extensionOf(String name) {
        if (name == null) {
            return "";
        }
        int dot = name.lastIndexOf('.');
        return dot < 0 ? "" : name.substring(dot).toLowerCase(java.util.Locale.ROOT);
    }
}
