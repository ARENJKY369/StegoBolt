package com.stegobolt.engine.engine;

import com.stegobolt.engine.api.dto.ScanReport;
import com.stegobolt.engine.service.StegoService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Forensic-scan smoke matrix across all six medium families.
 *
 * <p>For every supported carrier family the test asserts that
 * <ul>
 *   <li>a clean carrier is {@code LOW} and explicitly states that no StegoBolt
 *       container was found (never a confirmed/embedded claim), and</li>
 *   <li>a real StegoBolt carrier (produced by the same {@code /hide} service the
 *       REST API uses) is {@code CRITICAL} / {@code CONFIRMED}.</li>
 * </ul>
 * Non-image media additionally have to report {@code sampleBased == false} where
 * LSB statistics are meaningless, so image-style evidence can never leak into
 * documents, text, container padding or PCAP captures.
 */
class MediumScanMatrixTest {

    private static final int W = 128;
    private static final int H = 96;
    private static final char[] PASS = "matrix-pass".toCharArray();
    private static final byte[] PAYLOAD = "matrix payload".getBytes(StandardCharsets.UTF_8);

    private record Carrier(String label, String fileName, byte[] bytes, boolean stegoCapable) {
    }

    private static final String[] FORBIDDEN_CLAIMS = {
            "contains an embedded message",
            "embedded message is present",
            "likely embedding",
            "likely a recompressed or lightly modified",
            "assume data is embedded",
            "data is embedded"
    };

    /* ------------------------------------------------------------------ */
    /* service helpers                                                    */
    /* ------------------------------------------------------------------ */

    private static ScanReport scan(byte[] cover, String name) {
        StegoService service = new StegoService();
        try (StegoService.WorkResult work = service.scan(cover.clone(), name, null)) {
            return work.report();
        }
    }

    private static byte[] hide(byte[] cover, String name) {
        StegoService service = new StegoService();
        try (StegoService.WorkResult work = service.hide(cover.clone(), PAYLOAD, PASS, name, null)) {
            return work.out().clone();
        }
    }

    private static void assertCautious(String summary, String label) {
        String lower = summary.toLowerCase(Locale.ROOT);
        for (String claim : FORBIDDEN_CLAIMS) {
            assertFalse(lower.contains(claim), label + ": careless wording — " + summary);
        }
    }

    /* ------------------------------------------------------------------ */
    /* fixtures                                                           */
    /* ------------------------------------------------------------------ */

    private static List<Carrier> carriers() throws Exception {
        List<Carrier> list = new ArrayList<>();
        // ---- Image: PNG, BMP, WebP, GIF, TIFF, JPEG ----------------------
        byte[] photo = MediaFixtures.png(MediaFixtures.naturalPhoto(W, H, 7L));
        list.add(new Carrier("PNG", "cover.png", photo, true));
        list.add(new Carrier("BMP", "cover.bmp", MediaFixtures.png(MediaFixtures.naturalPhoto(W, H, 8L), "bmp"), true));
        // ImageIO ships no WebP codec: cover the structural/decode-fallback path only.
        list.add(new Carrier("WebP", "cover.webp", minimalWebp(), false));
        list.add(new Carrier("GIF", "cover.gif", MediaFixtures.png(MediaFixtures.naturalPhoto(W, H, 9L), "gif"), true));
        list.add(new Carrier("TIFF", "cover.tiff", MediaFixtures.png(MediaFixtures.naturalPhoto(W, H, 10L), "tiff"), true));
        list.add(new Carrier("JPEG", "cover.jpg", MediaFixtures.png(MediaFixtures.naturalPhoto(W, H, 11L), "jpg"), true));
        // ---- Audio: WAV, FLAC -------------------------------------------
        list.add(new Carrier("WAV", "cover.wav", MediaFixtures.wav(24000, 13L), true));
        list.add(new Carrier("FLAC", "cover.flac", MediaFixtures.flac(8192, 14L), true));
        // ---- Video: MP4, MKV, AVI ---------------------------------------
        list.add(new Carrier("MP4", "cover.mp4", MediaFixtures.mp4(4096), true));
        list.add(new Carrier("MKV", "cover.mkv", MediaFixtures.mkv(4096), true));
        list.add(new Carrier("AVI", "cover.avi", MediaFixtures.avi(4096), true));
        // ---- Documents: PDF, DOCX ---------------------------------------
        list.add(new Carrier("PDF", "cover.pdf", MediaFixtures.pdf(), true));
        list.add(new Carrier("DOCX", "cover.docx", MediaFixtures.docx(), true));
        // ---- Text/code: TXT, MD, Java, JS, TS, C, C++, H, HPP, PY, JSON, CSV
        for (String ext : MediaFixtures.TEXT_EXTENSIONS) {
            list.add(new Carrier("TEXT" + ext, "cover" + ext, MediaFixtures.text(ext, 200), true));
        }
        // ---- Network: PCAP, PCAPNG --------------------------------------
        list.add(new Carrier("PCAP", "cover.pcap", MediaFixtures.pcap(600, 17L), true));
        list.add(new Carrier("PCAPNG", "cover.pcapng", MediaFixtures.pcapng(600, 18L), true));
        return list;
    }

    /** Smallest RIFF/WEBP container the sniffer recognises (not decodable by ImageIO). */
    private static byte[] minimalWebp() {
        byte[] header = new byte[30];
        byte[] riff = "RIFF".getBytes(StandardCharsets.US_ASCII);
        byte[] webp = "WEBP".getBytes(StandardCharsets.US_ASCII);
        byte[] vp8 = "VP8 ".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(riff, 0, header, 0, 4);
        header[4] = 22;
        System.arraycopy(webp, 0, header, 8, 4);
        System.arraycopy(vp8, 0, header, 12, 4);
        header[16] = 2;
        header[17] = 0;
        header[18] = 0;
        header[19] = 0;
        return header;
    }

    /* ------------------------------------------------------------------ */
    /* tests                                                              */
    /* ------------------------------------------------------------------ */

    @Test
    void everyCleanMediumIsLowAndNeverClaimsEmbedding() throws Exception {
        for (Carrier carrier : carriers()) {
            ScanReport report = scan(carrier.bytes(), carrier.fileName());
            assertEquals("LOW", report.level(),
                    carrier.label() + ": clean carrier must be LOW, was " + report.level()
                            + " (" + report.threatScore() + ")");
            assertFalse(report.containerSignatureFound(), carrier.label());
            assertTrue(report.summary().contains("No StegoBolt container detected"),
                    carrier.label() + ": summary must state the container is absent — " + report.summary());
            assertFalse(report.summary().contains("Confirmed StegoBolt container"), carrier.label());
            assertCautious(report.summary(), carrier.label());
            assertTrue(report.threatScore() < 25, carrier.label() + ": clean score must stay below ELEVATED");

            boolean sampleMedium = carrier.label().equals("PNG") || carrier.label().equals("BMP")
                    || carrier.label().equals("GIF") || carrier.label().equals("TIFF")
                    || carrier.label().equals("JPEG") || carrier.label().equals("WAV")
                    || carrier.label().equals("AVI");
            assertEquals(sampleMedium, report.sampleBased(),
                    carrier.label() + ": LSB statistics must only be used where they are meaningful");
        }
    }

    @Test
    void everyStegoCarrierIsConfirmed() throws Exception {
        for (Carrier carrier : carriers()) {
            if (!carrier.stegoCapable()) {
                continue; // WebP has no ImageIO encoder — covered by the clean scan path
            }
            byte[] stego = hide(carrier.bytes(), carrier.fileName());
            ScanReport report = scan(stego, "stego" + carrier.fileName());
            assertEquals("CRITICAL", report.level(),
                    carrier.label() + ": stego carrier must be CRITICAL, was " + report.level()
                            + " (" + report.threatScore() + ")");
            assertEquals("CONFIRMED", report.confidence(), carrier.label());
            assertEquals("CONFIRMED_CONTAINER", report.verdict(), carrier.label());
            assertTrue(report.containerSignatureFound(), carrier.label() + ": container signature must be reported");
            assertTrue(report.summary().startsWith("Confirmed StegoBolt container detected"),
                    carrier.label() + ": " + report.summary());
            assertTrue(report.threatScore() >= 90, carrier.label());
        }
    }

    @Test
    void structuralMediaReportStructuralEvidence() throws Exception {
        ScanReport pdf = scan(MediaFixtures.pdf(), "clean.pdf");
        assertEquals("INCONCLUSIVE", pdf.confidence());
        assertFalse(pdf.analysisBasis().isEmpty());
        assertTrue(pdf.analysisBasis().toLowerCase(Locale.ROOT).contains("structural"), pdf.analysisBasis());

        ScanReport text = scan(MediaFixtures.text(".java", 60), "Clean.java");
        assertTrue(text.indicators().stream().anyMatch(i -> i.contains("Zero-width characters")), text.indicators().toString());
        assertTrue(text.indicators().stream().anyMatch(i -> i.contains("SB2J framing: absent")), text.indicators().toString());

        ScanReport pcapReport = scan(MediaFixtures.pcap(200, 5L), "clean.pcap");
        assertFalse(pcapReport.sampleBased());
        assertTrue(pcapReport.indicators().stream().anyMatch(i -> i.contains("IPv4 ID header LSB ones ratio")),
                pcapReport.indicators().toString());
    }

    @Test
    void corruptedStructuralSignatureIsDamagedNotConfirmed() {
        byte[] clean = MediaFixtures.pdf();
        byte[] marker = "SB2J".getBytes(StandardCharsets.US_ASCII);
        byte[] tainted = new byte[clean.length + marker.length + 24];
        System.arraycopy(clean, 0, tainted, 0, clean.length);
        System.arraycopy(marker, 0, tainted, clean.length, marker.length);

        ScanReport report = scan(tainted, "tainted.pdf");
        assertFalse(report.containerSignatureFound(), "damaged framing is not a container");
        assertEquals("HIGH", report.level(), "damaged framing must be HIGH, was " + report.level());
        assertEquals("SUSPICIOUS", report.confidence());
        assertEquals("DAMAGED_CONTAINER", report.verdict());
        assertTrue(report.summary().contains("Damaged StegoBolt container framing"), report.summary());
        assertCautious(report.summary(), "tainted PDF");
    }

    @Test
    void undecodableImageVariantFallsBackToStructure() {
        ScanReport report = scan(minimalWebp(), "cover.webp");
        assertEquals("LOW", report.level());
        assertEquals("INCONCLUSIVE", report.confidence());
        assertFalse(report.sampleBased(), "no pixel statistics for an undecodable variant");
        assertTrue(report.summary().contains("No StegoBolt container detected"), report.summary());
        assertTrue(report.indicators().stream().anyMatch(i -> i.contains("Pixel LSB statistics are unavailable")),
                report.indicators().toString());
        assertCautious(report.summary(), "WebP structural fallback");
    }
}
