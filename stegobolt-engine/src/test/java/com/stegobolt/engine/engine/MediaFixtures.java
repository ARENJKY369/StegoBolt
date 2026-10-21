package com.stegobolt.engine.engine;

import javax.imageio.ImageIO;
import javax.sound.sampled.AudioFileFormat;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Deterministic carrier fixtures for the forensic-scan regression matrix.
 *
 * <p>Every medium family is generated in memory from a fixed seed: images with
 * natural structure or a JPEG-like quantisation fingerprint, WAV/FLAC audio,
 * MP4/MKV/AVI video, PDF/DOCX documents, every supported text/code extension and
 * classic/next-generation PCAP captures with real IPv4 ID headers.
 *
 * <p>No binary assets are stored in the repository and nothing touches disk.
 */
public final class MediaFixtures {

    static final int W = 96;
    static final int H = 72;

    private MediaFixtures() {
    }

    /* ------------------------------------------------------------------ */
    /* Images                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Clean "photograph": multi-octave smooth structure plus fine sensor grain
     * and small per-channel gains. Deliberately not a flat colour field.
     */
    public static BufferedImage naturalPhoto(int w, int h, long seed) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Random rng = new Random(seed);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                double u = (double) x / w;
                double v = (double) y / h;
                double glow = 0.55 + 0.35 * Math.sin(u * 6.1 + 0.7) * Math.cos(v * 4.3 - 0.2);
                double base = 0.5 * glow + 0.5 * smooth(u, v, seed);
                double grain = (rng.nextDouble() - 0.5) * 0.06;
                double shade = clamp01(base + grain);
                int r = (int) Math.round(255 * clamp01(shade * 1.02 + 0.01));
                int g = (int) Math.round(255 * clamp01(shade));
                int b = (int) Math.round(255 * clamp01(shade * 0.97 + 0.02));
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }

    /** Smooth value noise (four octaves) in [0,1] — deterministic. */
    private static double smooth(double u, double v, long seed) {
        double sum = 0;
        double amp = 1;
        double norm = 0;
        for (int o = 0; o < 4; o++) {
            int scale = 1 << o;
            double fx = u * 6 * scale;
            double fy = v * 6 * scale;
            int x0 = (int) Math.floor(fx);
            int y0 = (int) Math.floor(fy);
            double tx = fx - x0;
            double ty = fy - y0;
            double sx = tx * tx * (3 - 2 * tx);
            double sy = ty * ty * (3 - 2 * ty);
            double v00 = hash(x0, y0, seed + o);
            double v10 = hash(x0 + 1, y0, seed + o);
            double v01 = hash(x0, y0 + 1, seed + o);
            double v11 = hash(x0 + 1, y0 + 1, seed + o);
            double top = v00 + (v10 - v00) * sx;
            double bottom = v01 + (v11 - v01) * sx;
            sum += (top + (bottom - top) * sy) * amp;
            norm += amp;
            amp *= 0.5;
        }
        return sum / norm;
    }

    private static double hash(int x, int y, long seed) {
        long h = x * 374761393L + y * 668265263L + seed * 2246822519L;
        h = (h ^ (h >>> 13)) * 1274126177L;
        h = h ^ (h >>> 16);
        return (h & 0xFFFFFF) / (double) 0xFFFFFF;
    }

    /**
     * Recompressed-JPEG model: 8×8 block quantisation with the even-value bias a
     * DCT quantiser leaves behind. Value pairs are unevenly populated, which the
     * old inverted chi-square mapping reported as 100 % evidence.
     */
    public static BufferedImage recompressedJpeg(int w, int h, long seed) {
        BufferedImage source = naturalPhoto(w, h, seed);
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        int block = 8;
        for (int by = 0; by < h; by += block) {
            for (int bx = 0; bx < w; bx += block) {
                long[] sums = new long[3];
                int n = 0;
                for (int y = by; y < Math.min(h, by + block); y++) {
                    for (int x = bx; x < Math.min(w, bx + block); x++) {
                        int rgb = source.getRGB(x, y);
                        sums[0] += (rgb >>> 16) & 0xFF;
                        sums[1] += (rgb >>> 8) & 0xFF;
                        sums[2] += rgb & 0xFF;
                        n++;
                    }
                }
                double[] means = {sums[0] / (double) n, sums[1] / (double) n, sums[2] / (double) n};
                for (int y = by; y < Math.min(h, by + block); y++) {
                    for (int x = bx; x < Math.min(w, bx + block); x++) {
                        int rgb = source.getRGB(x, y);
                        int ringing = (((x * 5 + y * 3) & 3) == 0) ? 1 : 0;
                        int[] out = new int[3];
                        int[] in = {(rgb >>> 16) & 0xFF, (rgb >>> 8) & 0xFF, rgb & 0xFF};
                        for (int c = 0; c < 3; c++) {
                            double q = Math.round((means[c] + (in[c] - means[c]) * 0.3) / 6.0) * 6.0;
                            int v = (int) q + ringing;
                            out[c] = Math.max(0, Math.min(255, (v & 0xFE) | (ringing == 1 && (v & 2) == 0 ? 1 : 0)));
                        }
                        img.setRGB(x, y, (out[0] << 16) | (out[1] << 8) | out[2]);
                    }
                }
            }
        }
        return img;
    }

    /**
     * Clean image with a deliberate natural channel imbalance: the red channel is
     * coarsely quantised and the blue channel saturates, pushing the LSB ones
     * ratio to ≈ 0.60 — the shape of the reported false positive.
     */
    public static BufferedImage channelImbalanced(int w, int h, long seed) {
        BufferedImage source = naturalPhoto(w, h, seed);
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Random rng = new Random(seed + 5);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int rgb = source.getRGB(x, y);
                int r = ((rgb >>> 16) & 0xFF) & 0xFE;
                int g = ((rgb >>> 8) & 0xFF) & 0xFE;
                int b = (rgb & 0xFF) & 0xFE;
                r |= rng.nextDouble() < 0.7 ? 1 : 0;
                g |= rng.nextDouble() < 0.56 ? 1 : 0;
                b |= rng.nextDouble() < 0.53 ? 1 : 0;
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }

    /** Full-plane LSB replacement with no SBV2-J framing (statistical-suspicion case). */
    public static byte[] fullPlaneLsbNoise(byte[] png, long seed) throws IOException {
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(png));
        Random rng = new Random(seed);
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int r = ((rgb >>> 16) & 0xFF) & 0xFE | (rng.nextBoolean() ? 1 : 0);
                int g = ((rgb >>> 8) & 0xFF) & 0xFE | (rng.nextBoolean() ? 1 : 0);
                int b = (rgb & 0xFF) & 0xFE | (rng.nextBoolean() ? 1 : 0);
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return png(img);
    }

    /** Encode an image as PNG bytes. */
    public static byte[] png(BufferedImage img) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (!ImageIO.write(img, "png", out)) {
            throw new IOException("PNG encoder unavailable");
        }
        return out.toByteArray();
    }

    public static byte[] png(BufferedImage img, String format) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (!ImageIO.write(img, format, out)) {
            throw new IOException(format + " encoder unavailable");
        }
        return out.toByteArray();
    }

    /* ------------------------------------------------------------------ */
    /* Audio                                                              */
    /* ------------------------------------------------------------------ */

    /** 16-bit mono 8 kHz PCM WAV with a deterministic noise-floor waveform. */
    public static byte[] wav(int frames, long seed) throws IOException {
        AudioFormat format = new AudioFormat(8000f, 16, 1, true, false);
        byte[] pcm = new byte[frames * 2];
        Random rng = new Random(seed);
        for (int i = 0; i < frames; i++) {
            double t = (double) i / 8000.0;
            double tone = 0.35 * Math.sin(2 * Math.PI * 440 * t);
            double noise = (rng.nextDouble() - 0.5) * 0.02;
            short sample = (short) Math.round(Short.MAX_VALUE * (tone + noise));
            pcm[i * 2] = (byte) (sample & 0xFF);
            pcm[i * 2 + 1] = (byte) ((sample >>> 8) & 0xFF);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (AudioInputStream ais = new AudioInputStream(new ByteArrayInputStream(pcm), format, frames)) {
            AudioSystem.write(ais, AudioFileFormat.Type.WAVE, out);
        }
        return out.toByteArray();
    }

    /** Minimal but valid FLAC container: STREAMINFO metadata + opaque frame bytes. */
    public static byte[] flac(int totalCapacityBytes, long seed) {
        Random rng = new Random(seed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("fLaC".getBytes(StandardCharsets.US_ASCII));
        // STREAMINFO (type 0), 34 bytes, marked as the last metadata block.
        out.write(0x80);
        out.write(0);
        out.write(0);
        out.write(34);
        out.writeBytes(new byte[34]);
        byte[] frames = new byte[Math.max(4096, totalCapacityBytes)];
        rng.nextBytes(frames);
        out.writeBytes(frames);
        return out.toByteArray();
    }

    /* ------------------------------------------------------------------ */
    /* Video                                                              */
    /* ------------------------------------------------------------------ */

    /** Minimal MP4 (ISO-BMFF): ftyp + mdat. */
    public static byte[] mp4(int payloadBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // ftyp box: 8-byte header (size + type) + 16 bytes of brand data
        writeInt(out, 24);
        out.writeBytes("ftyp".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes("isom".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(new byte[4]);
        out.writeBytes("isom".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes("mp41".getBytes(StandardCharsets.US_ASCII));
        // mdat box: 8-byte header + payload
        writeInt(out, 8 + payloadBytes);
        out.writeBytes("mdat".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(new byte[payloadBytes]);
        return out.toByteArray();
    }

    /** Minimal Matroska/WebM EBML header followed by opaque cluster bytes. */
    public static byte[] mkv(int payloadBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x1A);
        out.write(0x45);
        out.write(0xDF);
        out.write(0xA3);
        out.writeBytes(new byte[]{(byte) 0x85, 0x42, (byte) 0x86, (byte) 0x81, 0x01});
        out.writeBytes(new byte[payloadBytes]);
        return out.toByteArray();
    }

    /** Minimal AVI with one uncompressed 00db frame chunk (RIFF/LIST movi). */
    public static byte[] avi(int frameBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("RIFF".getBytes(StandardCharsets.US_ASCII));
        writeIntLE(out, 4 + 8 + 4 + 8 + frameBytes + (frameBytes & 1));
        out.writeBytes("AVI ".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes("LIST".getBytes(StandardCharsets.US_ASCII));
        writeIntLE(out, 4 + 8 + frameBytes + (frameBytes & 1));
        out.writeBytes("movi".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes("00db".getBytes(StandardCharsets.US_ASCII));
        writeIntLE(out, frameBytes);
        byte[] frame = new byte[frameBytes];
        new Random(11).nextBytes(frame);
        out.writeBytes(frame);
        if ((frameBytes & 1) == 1) {
            out.write(0);
        }
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeIntLE(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 24) & 0xFF);
    }

    /* ------------------------------------------------------------------ */
    /* Documents                                                          */
    /* ------------------------------------------------------------------ */

    /** Minimal single-page PDF with a trailer, /Root and startxref. */
    public static byte[] pdf() {
        String body = "%PDF-1.4\n"
                + "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                + "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
                + "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n";
        return body.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Minimal DOCX (OPC zip) with a document part and content types. */
    public static byte[] docx() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            zip.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zip.write(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                    + "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
                    .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("word/document.xml"));
            zip.write(("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
                    + "<w:body><w:p><w:r><w:t>Clean minutes of meeting.</w:t></w:r></w:p></w:body></w:document>")
                    .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return out.toByteArray();
    }

    /* ------------------------------------------------------------------ */
    /* Text / source code                                                 */
    /* ------------------------------------------------------------------ */

    public static final String[] TEXT_EXTENSIONS = {
            ".txt", ".md", ".java", ".js", ".ts", ".c", ".cpp", ".h", ".hpp", ".py", ".json", ".csv"
    };

    /** A clean text/code document for the given extension (all map to Medium.TEXT). */
    public static byte[] text(String extension, int lines) {
        StringBuilder sb = new StringBuilder();
        boolean code = !extension.equals(".txt") && !extension.equals(".md") && !extension.equals(".json")
                && !extension.equals(".csv");
        for (int i = 0; i < lines; i++) {
            if (code) {
                sb.append("// line ").append(i).append(" — deterministic fixture, no payload here\n");
                sb.append("public static int value").append(i).append("() { return ").append(i).append("; }\n");
            } else if (extension.equals(".json")) {
                sb.append("  \"key").append(i).append("\": \"value ").append(i).append("\",\n");
            } else if (extension.equals(".csv")) {
                sb.append("row").append(i).append(",value ").append(i).append(",healthy\n");
            } else {
                sb.append("Paragraph ").append(i).append(": a clean document with no hidden text layer.\n");
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /* ------------------------------------------------------------------ */
    /* Network captures                                                   */
    /* ------------------------------------------------------------------ */

    /** Classic libpcap capture with {@code packets} IPv4/UDP packets (little-endian). */
    public static byte[] pcap(int packets, long seed) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeIntLE(out, 0xA1B2C3D4);
        writeShortLE(out, 2);
        writeShortLE(out, 4);
        writeIntLE(out, 0);
        writeIntLE(out, 0);
        writeIntLE(out, 65535);
        writeIntLE(out, 1); // LINKTYPE_ETHERNET
        Random rng = new Random(seed);
        for (int i = 0; i < packets; i++) {
            byte[] frame = ethernetIpv4(i, rng);
            writeIntLE(out, i / 1000);
            writeIntLE(out, (i % 1000) * 1000);
            writeIntLE(out, frame.length);
            writeIntLE(out, frame.length);
            out.writeBytes(frame);
        }
        return out.toByteArray();
    }

    /** pcapng capture (SHB + IDB + Enhanced Packet Blocks). */
    public static byte[] pcapng(int packets, long seed) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Section Header Block
        writeIntLE(out, 0x0A0D0D0A);
        writeIntLE(out, 28);
        writeIntLE(out, 0x1A2B3C4D);
        writeShortLE(out, 1);
        writeShortLE(out, 0);
        writeIntLE(out, -1); // section length (64-bit): high word
        writeIntLE(out, -1); // section length (64-bit): low word
        writeIntLE(out, 28);
        // Interface Description Block (Ethernet)
        writeIntLE(out, 1);
        writeIntLE(out, 20);
        writeShortLE(out, 1);
        writeShortLE(out, 0);
        writeIntLE(out, 65535);
        writeIntLE(out, 20);
        Random rng = new Random(seed);
        for (int i = 0; i < packets; i++) {
            byte[] frame = ethernetIpv4(i, rng);
            int padded = (frame.length + 3) & ~3;
            int total = 32 + padded;
            writeIntLE(out, 6); // Enhanced Packet Block
            writeIntLE(out, total);
            writeIntLE(out, 0); // interface id
            writeIntLE(out, i / 1000);
            writeIntLE(out, (i % 1000) * 1000);
            writeIntLE(out, frame.length);
            writeIntLE(out, frame.length);
            out.writeBytes(frame);
            for (int p = frame.length; p < padded; p++) {
                out.write(0);
            }
            writeIntLE(out, total);
        }
        return out.toByteArray();
    }

    /** Ethernet + IPv4/UDP frame; the IPv4 Identification field is sequential. */
    private static byte[] ethernetIpv4(int index, Random rng) {
        byte[] payload = new byte[12];
        rng.nextBytes(payload);
        byte[] frame = new byte[14 + 20 + 8 + payload.length];
        // Ethernet
        for (int i = 0; i < 12; i++) {
            frame[i] = (byte) (0x02 * (i % 3));
        }
        frame[12] = 0x08; // IPv4 ethertype
        frame[13] = 0x00;
        int ip = 14;
        frame[ip] = 0x45; // IPv4, IHL 5
        frame[ip + 1] = 0;
        int totalLength = 20 + 8 + payload.length;
        frame[ip + 2] = (byte) (totalLength >>> 8);
        frame[ip + 3] = (byte) totalLength;
        frame[ip + 4] = (byte) (index >>> 8);  // Identification high byte
        frame[ip + 5] = (byte) (index & 0xFF); // Identification low byte (seed bit here)
        frame[ip + 6] = 0x40;
        frame[ip + 7] = 0;
        frame[ip + 8] = 64; // TTL
        frame[ip + 9] = 17; // UDP
        frame[ip + 12] = 10;
        frame[ip + 13] = 0;
        frame[ip + 14] = 0;
        frame[ip + 15] = (byte) (index & 0xFF);
        frame[ip + 16] = 10;
        frame[ip + 17] = 0;
        frame[ip + 18] = 0;
        frame[ip + 19] = 1;
        int udp = ip + 20;
        frame[udp] = 0x1F;
        frame[udp + 1] = (byte) 0x90;
        frame[udp + 2] = 0x1F;
        frame[udp + 3] = (byte) 0x91;
        int udpLength = 8 + payload.length;
        frame[udp + 4] = (byte) (udpLength >>> 8);
        frame[udp + 5] = (byte) udpLength;
        System.arraycopy(payload, 0, frame, udp + 8, payload.length);
        return frame;
    }

    private static void writeShortLE(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >>> 8) & 0xFF);
    }

    private static double clamp01(double v) {
        return Math.max(0, Math.min(1, v));
    }
}
