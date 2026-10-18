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
            long needed = payload.length * 8L + (long) Packet.HEADER * 8L;
            if (needed > capacity) {
                throw new StegoException("Payload too large for this " + medium.label().toLowerCase()
                        + " — capacity is " + (capacity / 8) + " bytes including the 40-byte container header");
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
                String name = stegoFileName(stego, medium);
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
        byte[] samples = null;
        byte[] embedded = null;
        try {
            Medium medium = Sniffer.sniff(cover, coverName);
            StegoEngine engine = engineFor(medium, textMode);
            samples = sampleStream(medium, cover);
            SteganalysisEngine.Stats stats = SteganalysisEngine.analyze(samples);

            embedded = engine.extract(cover);
            boolean signature = embedded != null;
            int threat = SteganalysisEngine.threatScore(stats, signature);

            List<String> indicators = new ArrayList<>();
            if (stats.chiSquareProbability() > 0.95) {
                indicators.add("Value pairs strongly equalized — chi-square embedding probability "
                        + String.format("%.2f", stats.chiSquareProbability()));
            }
            if (stats.spaEmbeddingRatio() > 0.25) {
                indicators.add("Sample-pair analysis estimates an embedding ratio of "
                        + String.format("%.2f", stats.spaEmbeddingRatio()));
            }
            if (Math.abs(0.5 - stats.lsbOnesRatio()) > 0.1) {
                indicators.add("LSB plane imbalance — ones ratio "
                        + String.format("%.2f", stats.lsbOnesRatio()));
            }
            if (signature) {
                indicators.add("SBV2-J container signature found in the embedding layer");
            }
            if (indicators.isEmpty()) {
                indicators.add("No statistical evidence of steganographic embedding");
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
                    signature,
                    threat,
                    indicators,
                    exifTags);
            work.track(cover, samples, embedded);
            handedOff = true;
            return work;
        } catch (RuntimeException e) {
            if (!handedOff) {
                work.track(cover, samples, embedded);
                work.close();
            }
            throw e;
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
            work.fileName = stegoFileName(outcome.cleaned(), medium);
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
            long capacityBytes = capacityBits / 8 - Packet.HEADER;
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

    private static String stegoFileName(byte[] stego, Medium medium) {
        String ext = switch (medium) {
            case IMAGE -> ".png";
            case AUDIO -> ".wav";
            case VIDEO -> ".bin";
            case DOCUMENT -> ".bin";
            case TEXT -> ".txt";
            case NETWORK -> ".pcap";
        };
        String hash = sha256(stego).substring(0, 12);
        return "stegobolt-" + hash + ext;
    }
}
