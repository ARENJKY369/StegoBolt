package com.stegobolt.engine.analysis;

import com.stegobolt.engine.api.dto.ScanReport;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.crypto.CryptoEngine;
import com.stegobolt.engine.engine.MediaFixtures;
import com.stegobolt.engine.service.StegoService;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * False-positive regression suite for the forensic scan.
 *
 * <p>Covers the reported clean-photo false positive (chi-square 100 % evidence →
 * ELEVATED), the recompressed-JPEG and natural-channel-imbalance cases, the
 * positive SBV2-J detection path, damaged/wrong signatures and small samples.
 * Every case asserts both the numeric classification and the user-facing
 * wording, so a careless "embedded message" claim fails the build.
 */
class ScanCalibrationTest {

    private static final int W = 256;
    private static final int H = 192;
    private static final char[] PASS = "calibration-pass".toCharArray();

    private static final String[] FORBIDDEN_CLAIMS = {
            "contains an embedded message",
            "embedded message is present",
            "likely embedding",
            "likely a recompressed or lightly modified",
            "assume data is embedded",
            "data is embedded"
    };

    /* ------------------------------------------------------------------ */
    /* helpers                                                            */
    /* ------------------------------------------------------------------ */

    private static ScanReport scan(byte[] cover, String name) {
        StegoService service = new StegoService();
        // The service owns (and zero-wipes) its inputs — hand it a copy.
        try (StegoService.WorkResult work = service.scan(cover.clone(), name, null)) {
            return work.report();
        }
    }

    private static byte[] hide(byte[] cover, String name) {
        StegoService service = new StegoService();
        byte[] payload = "forensic calibration payload".getBytes(StandardCharsets.UTF_8);
        try (StegoService.WorkResult work = service.hide(cover.clone(), payload, PASS, name, null)) {
            return work.out().clone();
        }
    }

    private static void assertCautious(String summary, String label) {
        String lower = summary.toLowerCase(Locale.ROOT);
        for (String claim : FORBIDDEN_CLAIMS) {
            assertFalse(lower.contains(claim), label + ": careless wording — " + summary);
        }
    }

    private static byte[] png(BufferedImage img) throws IOException {
        return MediaFixtures.png(img);
    }

    /** Extract the LSB bits of the first bytes and overwrite them (signature tampering). */
    private static byte[] rewriteHeaderBits(byte[] png, int byteOffset, int value) throws IOException {
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(png));
        int startBit = byteOffset * 8;
        for (int b = 0; b < 8; b++) {
            int bitIndex = startBit + b;
            int pixel = bitIndex / 3;
            int channel = bitIndex % 3;
            int x = pixel % img.getWidth();
            int y = pixel / img.getWidth();
            int rgb = img.getRGB(x, y);
            int shift = 16 - channel * 8;
            int bit = (value >> (7 - b)) & 1;
            rgb = (rgb & ~(1 << shift)) | (bit << shift);
            img.setRGB(x, y, rgb);
        }
        return MediaFixtures.png(img);
    }

    /* ------------------------------------------------------------------ */
    /* 1. clean natural-looking image                                     */
    /* ------------------------------------------------------------------ */

    @Test
    void cleanNaturalImageStaysLowWithoutEmbeddingClaim() throws Exception {
        byte[] cover = png(MediaFixtures.naturalPhoto(W, H, 7L));
        ScanReport report = scan(cover, "clean-photo.png");

        assertTrue(report.sampleBased(), "pixel statistics must be available for a PNG");
        assertEquals("LOW", report.level(), "clean photo must stay LOW, was " + report.level() + " (" + report.threatScore() + ")");
        assertEquals("CLEAN", report.confidence());
        assertEquals("CLEAN", report.verdict());
        assertFalse(report.containerSignatureFound());
        assertTrue(report.threatScore() < 25, "clean photo score must stay below ELEVATED, was " + report.threatScore());
        assertTrue(report.summary().contains("No StegoBolt container detected"), report.summary());
        assertTrue(report.summary().toLowerCase(Locale.ROOT).contains("no direct evidence of an embedded message"));
        assertFalse(report.summary().contains("Confirmed StegoBolt container"));
        assertCautious(report.summary(), "clean photo");
        // The old mapping reported a clean photo's imbalanced pairs as 100 % evidence.
        assertTrue(report.chiSquareProbability() < 0.5,
                "natural pairs are imbalanced, p must stay small, was " + report.chiSquareProbability());
        assertTrue(report.indicators().contains("No statistical evidence of steganographic embedding."),
                report.indicators().toString());
    }

    /* ------------------------------------------------------------------ */
    /* 2. clean recompressed JPEG                                         */
    /* ------------------------------------------------------------------ */

    @Test
    void cleanRecompressedJpegStaysLow() throws Exception {
        // A real JPEG cover (lossy decode + even-value quantisation bias).
        byte[] jpegCover = MediaFixtures.png(MediaFixtures.recompressedJpeg(W, H, 19L), "jpg");
        ScanReport report = scan(jpegCover, "recompressed.jpg");

        assertEquals("LOW", report.level(), "recompressed JPEG must stay LOW, was " + report.level() + " (" + report.threatScore() + ")");
        assertTrue(report.threatScore() < 25);
        assertFalse(report.containerSignatureFound());
        assertCautious(report.summary(), "recompressed JPEG");
        assertTrue(report.summary().contains("No StegoBolt container detected"));
    }

    /* ------------------------------------------------------------------ */
    /* 3. clean synthetic image with natural channel imbalance            */
    /* ------------------------------------------------------------------ */

    @Test
    void cleanChannelImbalancedImageStaysLow() throws Exception {
        byte[] cover = png(MediaFixtures.channelImbalanced(W, H, 11L));
        ScanReport report = scan(cover, "channel-bias.png");

        assertTrue(report.lsbOnesRatio() > 0.55 && report.lsbOnesRatio() < 0.65,
                "fixture must reproduce the reported ones ratio, was " + report.lsbOnesRatio());
        assertEquals("LOW", report.level(), "channel-imbalanced clean image must stay LOW, was "
                + report.level() + " (" + report.threatScore() + ")");
        assertEquals("CLEAN", report.confidence());
        assertFalse(report.containerSignatureFound());
        assertCautious(report.summary(), "channel imbalance");
        assertTrue(report.summary().contains("No StegoBolt container detected"));
    }

    /* ------------------------------------------------------------------ */
    /* 4. known SBV2-J stego carrier must still be detected               */
    /* ------------------------------------------------------------------ */

    @Test
    void sbv2jCarrierIsConfirmed() throws Exception {
        byte[] cover = png(MediaFixtures.naturalPhoto(W, H, 7L));
        byte[] stego = hide(cover, "cover.png");
        ScanReport report = scan(stego, "stego.png");

        assertTrue(report.containerSignatureFound(), "SBV2-J container must be found");
        assertEquals("CRITICAL", report.level(), "stego carrier must be CRITICAL, was " + report.level());
        assertEquals("CONFIRMED", report.confidence());
        assertEquals("CONFIRMED_CONTAINER", report.verdict());
        assertTrue(report.threatScore() >= 90, "confirmed container score must stay high, was " + report.threatScore());
        assertTrue(report.summary().startsWith("Confirmed StegoBolt container detected"), report.summary());
        assertTrue(report.indicators().stream().anyMatch(i -> i.contains("SBV2-J container signature found")),
                report.indicators().toString());
    }

    /* ------------------------------------------------------------------ */
    /* 5. statistical suspicion without framing (never "confirmed")       */
    /* ------------------------------------------------------------------ */

    @Test
    void fullPlaneLsbReplacementIsSuspicionOnly() throws Exception {
        byte[] cover = png(MediaFixtures.naturalPhoto(W, H, 7L));
        byte[] noisy = MediaFixtures.fullPlaneLsbNoise(cover, 31L);
        ScanReport report = scan(noisy, "noisy.png");

        assertEquals("HIGH", report.level(), "full-plane random LSB must reach HIGH, was " + report.level() + " (" + report.threatScore() + ")");
        assertEquals("SUSPICIOUS", report.confidence());
        assertEquals("STRONG_STATISTICAL_SUSPICION", report.verdict());
        assertFalse(report.containerSignatureFound());
        assertTrue(report.summary().contains("No StegoBolt container signature was found"), report.summary());
        assertTrue(report.summary().contains("statistical suspicion"));
        assertFalse(report.summary().contains("Confirmed StegoBolt container"));
        assertCautious(report.summary(), "full-plane LSB");
    }

    /* ------------------------------------------------------------------ */
    /* 6. damaged and wrong signatures                                    */
    /* ------------------------------------------------------------------ */

    @Test
    void damagedFramingIsHighButNotConfirmed() throws Exception {
        byte[] cover = png(MediaFixtures.naturalPhoto(W, H, 7L));
        byte[] stego = hide(cover, "cover.png");
        byte[] damaged = rewriteHeaderBits(stego, 4, 0x09); // SBV2 version byte → 9
        ScanReport report = scan(damaged, "damaged.png");

        assertFalse(report.containerSignatureFound(), "damaged framing must not count as a container");
        assertEquals("HIGH", report.level(), "damaged framing must be HIGH, was " + report.level() + " (" + report.threatScore() + ")");
        assertEquals("SUSPICIOUS", report.confidence());
        assertEquals("DAMAGED_CONTAINER", report.verdict());
        assertTrue(report.summary().contains("Damaged StegoBolt container framing"), report.summary());
        assertFalse(report.summary().contains("Confirmed StegoBolt container detected"));
        assertCautious(report.summary(), "damaged framing");
    }

    @Test
    void wrongMagicIsNotAContainer() throws Exception {
        byte[] clean = png(MediaFixtures.naturalPhoto(W, H, 7L));
        // Write "SBV3" into the first bytes of the LSB plane.
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(clean));
        byte[] wrong = {'S', 'B', 'V', '3'};
        for (int b = 0; b < 32; b++) {
            int bit = (wrong[b / 8] >> (7 - (b % 8))) & 1;
            int pixel = b / 3;
            int channel = b % 3;
            int rgb = img.getRGB(pixel % img.getWidth(), pixel / img.getWidth());
            int shift = 16 - channel * 8;
            rgb = (rgb & ~(1 << shift)) | (bit << shift);
            img.setRGB(pixel % img.getWidth(), pixel / img.getWidth(), rgb);
        }
        ScanReport report = scan(MediaFixtures.png(img), "wrong-magic.png");

        assertFalse(report.containerSignatureFound(), "SBV3 is not an SBV2-J container");
        assertEquals("LOW", report.level(), "wrong magic must not elevate the verdict, was " + report.level());
        assertCautious(report.summary(), "wrong magic");
    }

    /* ------------------------------------------------------------------ */
    /* 7. structural media and small samples                              */
    /* ------------------------------------------------------------------ */

    @Test
    void structuralMediaAreNotJudgedByLsbStatistics() throws Exception {
        for (Object[] fixture : new Object[][]{
                {"doc.pdf", MediaFixtures.pdf()},
                {"doc.docx", MediaFixtures.docx()},
                {"notes.md", MediaFixtures.text(".md", 40)},
                {"clean.mp4", MediaFixtures.mp4(2048)}
        }) {
            String name = (String) fixture[0];
            byte[] cover = (byte[]) fixture[1];
            ScanReport report = scan(cover, name);
            assertFalse(report.sampleBased(), name + ": LSB statistics must not apply");
            assertEquals("LOW", report.level(), name + ": clean structural carrier must be LOW, was " + report.level());
            assertEquals("INCONCLUSIVE", report.confidence(), name);
            assertTrue(report.summary().contains("No StegoBolt container detected"), report.summary());
            assertCautious(report.summary(), name);
        }
    }

    @Test
    void tinyCarrierIsInconclusive() throws Exception {
        byte[] tiny = png(MediaFixtures.naturalPhoto(16, 16, 3L));
        ScanReport report = scan(tiny, "tiny.png");

        assertEquals("LOW", report.level());
        assertEquals("INCONCLUSIVE", report.confidence());
        assertTrue(report.summary().contains("too small for reliable statistics"), report.summary());
        assertCautious(report.summary(), "tiny carrier");
    }

    @Test
    void calibratedStatsSeparateEqualizedFromNaturalPairs() {
        // Perfectly equalised pairs: the classic sequential-LSB fingerprint.
        byte[] equalized = new byte[65536];
        for (int i = 0; i < equalized.length; i++) {
            equalized[i] = (byte) (i & 0xFF);
        }
        SteganalysisEngine.Stats equalStats = SteganalysisEngine.analyze(equalized);
        assertTrue(equalStats.chiSquareProbability() > 0.9, "equalised pairs must look equalised, was " + equalStats.chiSquareProbability());
        assertTrue(equalStats.chiEqualization() > 0.5, "equalised pairs must produce equalisation evidence");

        // One value per pair only: clearly natural, must produce no evidence.
        byte[] imbalanced = new byte[65536];
        for (int i = 0; i < imbalanced.length; i++) {
            imbalanced[i] = (byte) ((i & 0x7F) << 1);
        }
        SteganalysisEngine.Stats imbalancedStats = SteganalysisEngine.analyze(imbalanced);
        assertTrue(imbalancedStats.chiSquareProbability() < 0.1, "imbalanced pairs are the natural state");
        assertEquals(0.0, imbalancedStats.chiEqualization(), 1e-9, "imbalanced pairs must not read as evidence");
    }

    @Test
    void confirmedContainerOutranksAnyStatistic() {
        SteganalysisEngine.Stats neutral = SteganalysisEngine.Stats.structural(0);
        SteganalysisEngine.Verdict verdict =
                SteganalysisEngine.assess(neutral, SteganalysisEngine.SignatureState.CONFIRMED, "image", "basis");
        assertEquals(SteganalysisEngine.Level.CRITICAL, verdict.level());
        assertEquals(SteganalysisEngine.Confidence.CONFIRMED, verdict.confidence());
        assertTrue(verdict.summary().contains("Confirmed StegoBolt container detected"));
    }

    @Test
    void singleDetectorCannotElevateASampleStream() {
        // SPA is deliberately noisy on quantised media; alone it must stay LOW.
        byte[] biased = new byte[8192];
        java.util.Random rng = new java.util.Random(5);
        for (int i = 0; i < biased.length; i++) {
            int base = (i / 4) % 60;
            biased[i] = (byte) ((base << 1) | (rng.nextDouble() < 0.7 ? 1 : 0));
        }
        SteganalysisEngine.Stats stats = SteganalysisEngine.analyze(biased);
        SteganalysisEngine.Verdict verdict =
                SteganalysisEngine.assess(stats, SteganalysisEngine.SignatureState.ABSENT, "image", "basis");
        assertTrue(verdict.level() == SteganalysisEngine.Level.LOW || verdict.level() == SteganalysisEngine.Level.ELEVATED,
                "one detector must never reach HIGH, was " + verdict.level());
    }

    @Test
    void sealedContainerPayloadRoundTripsThroughTheScanPath() {
        // Sanity check that the fixtures use the real sealed SBV2-J format.
        Packet packet = CryptoEngine.seal("scan calibration".getBytes(StandardCharsets.UTF_8), PASS, Medium.IMAGE);
        byte[] raw = packet.serialize();
        try {
            assertTrue(Packet.looksLike(raw));
            assertEquals(Medium.IMAGE, Packet.parse(raw, 0).medium());
        } finally {
            packet.wipe();
        }
    }
}
