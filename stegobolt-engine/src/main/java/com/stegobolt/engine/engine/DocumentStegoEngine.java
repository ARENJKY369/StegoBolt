package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.core.StegoException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Document Steganography (PDF, DOCX) — §4.2.
 *
 * <p><b>DOCX (OPC/ZIP)</b> — the payload becomes a hidden structural metadata
 * part ({@code word/stegobolt.bin}) inside the package. The part is not
 * referenced from any relationship, so Word renders the document untouched.
 *
 * <p><b>PDF</b> — the payload is injected as an invisible metadata stream via a
 * proper incremental update (new xref table + trailer with {@code /Prev}),
 * appended after the final {@code %%EOF}. Readers that don't know the
 * {@code /StegoBolt} subtype never render it; the visible pages are unchanged.
 */
public final class DocumentStegoEngine implements StegoEngine {

    private static final String DOCX_PART = "word/stegobolt.bin";
    private static final String PDF_MARK = "/Subtype /StegoBolt";
    private static final String PDF_BEGIN = "% STEGOBOLT-BEGIN";

    @Override
    public Medium medium() {
        return Medium.DOCUMENT;
    }

    @Override
    public long capacityBits(byte[] cover) {
        if (isZip(cover)) {
            return 8L * 1024 * 1024 * 8L; // 8 MiB hidden part budget
        }
        return 8L * 1024 * 1024 * 8L;
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        return isZip(cover) ? hideDocx(cover, container) : hidePdf(cover, container);
    }

    @Override
    public byte[] extract(byte[] cover) {
        return isZip(cover) ? extractDocx(cover) : extractPdf(cover);
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        byte[] hidden = extract(cover);
        long removed = hidden == null ? 0 : hidden.length * 8L;
        if (hidden != null) {
            MemoryHygiene.wipe(hidden);
        }
        byte[] cleaned = isZip(cover) ? sanitizeDocx(cover) : sanitizePdf(cover);
        return new SanitizeOutcome(cleaned, removed, removed);
    }

    /**
     * Structural probe for the forensic scan: true when a DOCX package carries
     * the hidden {@code word/stegobolt.bin} part (or a PDF carries the StegoBolt
     * incremental-update marker) even if extraction cannot complete.
     */
    public static boolean hasHiddenLayer(byte[] cover) {
        if (cover == null) {
            return false;
        }
        if (isZip(cover)) {
            Map<String, byte[]> parts = readZip(cover);
            try {
                return parts.containsKey(DOCX_PART);
            } finally {
                for (byte[] part : parts.values()) {
                    MemoryHygiene.wipe(part);
                }
            }
        }
        if (isPdf(cover)) {
            String text = new String(cover, StandardCharsets.ISO_8859_1);
            return text.contains(PDF_MARK) || text.contains(PDF_BEGIN);
        }
        return false;
    }

    /* ------------------------------------------------------------------ */
    /* DOCX — hidden structural part inside the OPC package                */
    /* ------------------------------------------------------------------ */

    private static boolean isZip(byte[] cover) {
        return cover.length > 4
                && cover[0] == 'P' && cover[1] == 'K' && cover[2] == 0x03 && cover[3] == 0x04;
    }

    private static byte[] hideDocx(byte[] cover, byte[] container) {
        Map<String, byte[]> parts = readZip(cover);
        parts.put(DOCX_PART, container);
        return writeZip(parts);
    }

    private static byte[] extractDocx(byte[] cover) {
        Map<String, byte[]> parts = readZip(cover);
        return parts.get(DOCX_PART);
    }

    private static byte[] sanitizeDocx(byte[] cover) {
        Map<String, byte[]> parts = readZip(cover);
        parts.remove(DOCX_PART);
        return writeZip(parts);
    }

    /** Fully in-memory ZIP read (zero-disk: java.util.zip over byte arrays only). */
    private static Map<String, byte[]> readZip(byte[] cover) {
        Map<String, byte[]> parts = new LinkedHashMap<>();
        long totalUncompressed = 0;
        int entries = 0;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(cover))) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                if (++entries > 4096) {
                    throw new StegoException("DOCX package rejected — too many zip entries");
                }
                if (!entry.isDirectory()) {
                    byte[] data = zin.readAllBytes();
                    totalUncompressed += data.length;
                    if (totalUncompressed > 256L * 1024 * 1024) {
                        MemoryHygiene.wipe(data);
                        throw new StegoException("DOCX package rejected — zip bomb guard (256 MiB uncompressed ceiling)");
                    }
                    parts.put(entry.getName(), data);
                }
                zin.closeEntry();
            }
        } catch (IOException e) {
            throw new StegoException("DOCX package could not be read", e);
        }
        return parts;
    }

    private static byte[] writeZip(Map<String, byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zout = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> part : parts.entrySet()) {
                zout.putNextEntry(new ZipEntry(part.getKey()));
                zout.write(part.getValue());
                zout.closeEntry();
            }
        } catch (IOException e) {
            throw new StegoException("DOCX package could not be rebuilt", e);
        }
        return out.toByteArray();
    }

    /* ------------------------------------------------------------------ */
    /* PDF — invisible metadata stream via incremental update              */
    /* ------------------------------------------------------------------ */

    private static byte[] hidePdf(byte[] cover, byte[] container) {
        if (!isPdf(cover)) {
            throw new StegoException("Document is neither DOCX (OPC zip) nor PDF");
        }
        String text = new String(cover, StandardCharsets.ISO_8859_1);
        TrailerInfo info = parseTrailer(text);
        int objNum = info.size();
        java.nio.charset.Charset iso = StandardCharsets.ISO_8859_1;

        ByteArrayOutputStream out = new ByteArrayOutputStream(cover.length + container.length + 256);
        out.write(cover, 0, cover.length);
        byte[] begin = ("\n" + PDF_BEGIN + "\n").getBytes(iso);
        out.write(begin, 0, begin.length);

        int newObjOffset = out.size();
        byte[] head = (objNum + " 0 obj\n<< " + PDF_MARK + " /Length " + container.length + " >>\nstream\n")
                .getBytes(iso);
        out.write(head, 0, head.length);
        out.write(container, 0, container.length);
        byte[] tail = "\nendstream\nendobj\n".getBytes(iso);
        out.write(tail, 0, tail.length);

        int xrefOffset = out.size();
        String xref = "xref\n0 1\n0000000000 65535 f \n"
                + objNum + " 1\n"
                + String.format("%010d 00000 n \n", newObjOffset)
                + "trailer\n<< /Size " + (objNum + 1) + " /Root " + info.rootRef()
                + " /Prev " + info.startXref() + " >>\nstartxref\n" + xrefOffset
                + "\n%%EOF\n";
        byte[] xrefBytes = xref.getBytes(iso);
        out.write(xrefBytes, 0, xrefBytes.length);
        return out.toByteArray();
    }

    private static byte[] extractPdf(byte[] cover) {
        String text = new String(cover, StandardCharsets.ISO_8859_1);
        int mark = text.indexOf(PDF_MARK);
        if (mark < 0) {
            return null;
        }
        int stream = text.indexOf("stream\n", mark);
        if (stream < 0) {
            return null;
        }
        int dataStart = stream + "stream\n".length();
        int dataEnd = text.indexOf("\nendstream", dataStart);
        if (dataEnd < 0) {
            return null;
        }
        return Arrays.copyOfRange(cover, dataStart, dataEnd);
    }

    /** Truncate the incremental update we appended at {@code % STEGOBOLT-BEGIN}. */
    private static byte[] sanitizePdf(byte[] cover) {
        String text = new String(cover, StandardCharsets.ISO_8859_1);
        int mark = text.indexOf(PDF_BEGIN);
        if (mark < 0) {
            return cover.clone(); // nothing of ours to strip
        }
        return Arrays.copyOfRange(cover, 0, mark);
    }

    private static boolean isPdf(byte[] cover) {
        return cover.length > 4
                && cover[0] == '%' && cover[1] == 'P' && cover[2] == 'D' && cover[3] == 'F';
    }

    private record TrailerInfo(String rootRef, int size, int startXref) {
    }

    private static TrailerInfo parseTrailer(String text) {
        int trailerAt = text.lastIndexOf("trailer");
        if (trailerAt < 0) {
            throw new StegoException("PDF trailer not found — cannot append incremental update");
        }
        int dictEnd = text.indexOf(">>", trailerAt);
        String dict = text.substring(trailerAt, Math.min(text.length(), dictEnd + 2));

        String rootRef = extractRef(dict, "/Root");
        String sizeStr = extractNumber(dict, "/Size");
        if (rootRef == null || sizeStr == null) {
            throw new StegoException("PDF trailer is missing /Root or /Size");
        }
        int sx = text.lastIndexOf("startxref");
        if (sx < 0) {
            throw new StegoException("PDF startxref not found");
        }
        int lineStart = text.indexOf('\n', sx);
        int startXref;
        try {
            startXref = Integer.parseInt(text.substring(lineStart + 1, text.indexOf('\n', lineStart + 1)).trim());
        } catch (RuntimeException e) {
            throw new StegoException("PDF startxref value unreadable", e);
        }
        return new TrailerInfo(rootRef, Integer.parseInt(sizeStr.trim()), startXref);
    }

    private static String extractRef(String dict, String key) {
        int at = dict.indexOf(key);
        if (at < 0) {
            return null;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile(java.util.regex.Pattern.quote(key) + "\\s+(\\d+\\s+\\d+\\s+R)")
                .matcher(dict);
        return m.find() ? m.group(1) : null;
    }

    private static String extractNumber(String dict, String key) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile(java.util.regex.Pattern.quote(key) + "\\s+(\\d+)")
                .matcher(dict);
        return m.find() ? m.group(1) : null;
    }
}
