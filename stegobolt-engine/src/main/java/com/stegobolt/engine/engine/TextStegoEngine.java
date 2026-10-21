package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.BitIO;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Text &amp; Source-Code Steganography (TXT, Java, JS, C++, …) — §4.2.
 *
 * <p><b>ZERO_WIDTH mode</b> — binary payload bits are encoded with zero-width
 * Unicode spaces: {@code \u200B} = 0, {@code \u200C} = 1. The invisible stream
 * is appended after the visible text and starts with the {@code SB2J} magic, so
 * extraction is self-synchronizing even when the cover already contains stray
 * zero-width characters.
 *
 * <p><b>TRAILING_WS mode</b> — every line ends with a one-bit whitespace
 * pattern: a trailing space = 0, a trailing tab = 1.
 */
public final class TextStegoEngine implements StegoEngine {

    public static final String MODE_ZERO_WIDTH = "ZERO_WIDTH";
    public static final String MODE_TRAILING_WS = "TRAILING_WS";

    private static final char ZW0 = '\u200B'; // zero-width space
    private static final char ZW1 = '\u200C'; // zero-width non-joiner

    private final String mode;

    public TextStegoEngine() {
        this(MODE_ZERO_WIDTH);
    }

    public TextStegoEngine(String mode) {
        this.mode = mode == null || mode.isBlank() ? MODE_ZERO_WIDTH : mode.trim().toUpperCase();
    }

    @Override
    public Medium medium() {
        return Medium.TEXT;
    }

    @Override
    public long capacityBits(byte[] cover) {
        String text = new String(cover, StandardCharsets.UTF_8);
        if (MODE_TRAILING_WS.equals(mode)) {
            return text.lines().count(); // one bit per line
        }
        // Zero-width streams append invisibly; bound the payload to 512 KiB.
        return 512L * 1024L * 8L;
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        String text = new String(cover, StandardCharsets.UTF_8);
        long capacity = capacityBits(cover);
        if (container.length * 8L > capacity) {
            throw new StegoException("Payload too large for this text — capacity is "
                    + (capacity / 8) + " bytes, payload needs " + container.length + " bytes");
        }
        return MODE_TRAILING_WS.equals(mode)
                ? hideTrailingWs(text, container)
                : hideZeroWidth(text, container);
    }

    @Override
    public byte[] extract(byte[] cover) {
        String text = new String(cover, StandardCharsets.UTF_8);
        return MODE_TRAILING_WS.equals(mode) ? extractTrailingWs(text) : extractZeroWidth(text);
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        String text = new String(cover, StandardCharsets.UTF_8);
        long removed = 0;
        // Strip every zero-width embedder char and all trailing whitespace.
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ZW0 || c == ZW1 || c == '\u200D' || c == '\uFEFF') {
                removed++;
                continue;
            }
            sb.append(c);
        }
        String cleanedText = sb.toString().replaceAll("(?m)[ \\t]+$", "");
        if (cleanedText.length() < text.length()) {
            removed += text.length() - cleanedText.length();
        }
        return new SanitizeOutcome(cleanedText.getBytes(StandardCharsets.UTF_8), removed, removed);
    }

    /**
     * Structural inspection for the forensic scan: counts the covert-text
     * carriers present in a document and reports whether any decoded bit stream
     * starts with the SB2J marker (i.e. framing exists even if extraction fails).
     */
    public record TextInspection(int zeroWidthChars, int trailingWhitespaceLines,
                                 boolean sb2jMarkerPresent) {
    }

    public static TextInspection inspect(byte[] cover) {
        String text = new String(cover, StandardCharsets.UTF_8);
        int zeroWidth = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ZW0 || c == ZW1 || c == '\u200D' || c == '\uFEFF') {
                zeroWidth++;
            }
        }
        int trailing = 0;
        for (String line : text.split("\n", -1)) {
            if (line.endsWith(" ") || line.endsWith("\t")) {
                trailing++;
            }
        }
        boolean marker = containsMagicAtAnyOffset(zeroWidthBits(text)) || containsMagicAtAnyOffset(trailingBits(text));
        return new TextInspection(zeroWidth, trailing, marker);
    }

    private static String zeroWidthBits(String text) {
        StringBuilder bits = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ZW0) {
                bits.append('0');
            } else if (c == ZW1) {
                bits.append('1');
            }
        }
        return bits.toString();
    }

    private static String trailingBits(String text) {
        StringBuilder bits = new StringBuilder();
        for (String line : text.split("\n", -1)) {
            if (line.endsWith(" ")) {
                bits.append('0');
            } else if (line.endsWith("\t")) {
                bits.append('1');
            }
        }
        return bits.toString();
    }

    private static boolean containsMagicAtAnyOffset(String bits) {
        for (int offset = 0; offset + Packet.MAGIC.length * 8 <= bits.length(); offset++) {
            boolean match = true;
            for (int i = 0; i < Packet.MAGIC.length * 8; i++) {
                int want = (Packet.MAGIC[i / 8] >>> (7 - (i % 8))) & 1;
                if (bits.charAt(offset + i) != (char) ('0' + want)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    /* ------------------------------------------------------------------ */
    /* zero-width Unicode                                                  */
    /* ------------------------------------------------------------------ */

    private static byte[] hideZeroWidth(String text, byte[] container) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length() + container.length * 8);
        byte[] visible = text.getBytes(StandardCharsets.UTF_8);
        out.write(visible, 0, visible.length);

        StringBuilder hidden = new StringBuilder(container.length * 8 + Packet.MAGIC.length * 8);
        BitIO.write(container, 0, (index, bit) -> hidden.append(bit == 0 ? ZW0 : ZW1));
        byte[] zw = hidden.toString().getBytes(StandardCharsets.UTF_8);
        out.write(zw, 0, zw.length);
        return out.toByteArray();
    }

    private static byte[] extractZeroWidth(String text) {
        StringBuilder bits = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ZW0) {
                bits.append('0');
            } else if (c == ZW1) {
                bits.append('1');
            }
        }
        int n = bits.length();
        if (n < Packet.HEADER * 8) {
            return null;
        }
        // Self-synchronizing: hunt the SB2J magic at every bit offset.
        for (int offset = 0; offset <= n - Packet.HEADER * 8; offset++) {
            if (magicAt(bits, offset)) {
                byte[] header = bitsToBytes(bits, offset, Packet.HEADER * 8);
                int ctLen = BitIO.getInt(header, 8);
                long totalBits = (long) (Packet.HEADER + ctLen) * 8L;
                if (ctLen < 0 || offset + totalBits > n) {
                    continue;
                }
                byte[] raw = bitsToBytes(bits, offset, totalBits);
                if (Packet.looksLike(raw)) {
                    return raw;
                }
            }
        }
        return null;
    }

    private static boolean magicAt(StringBuilder bits, int offset) {
        for (int i = 0; i < Packet.MAGIC.length * 8; i++) {
            int want = (Packet.MAGIC[i / 8] >>> (7 - (i % 8))) & 1;
            if (bits.charAt(offset + i) != (char) ('0' + want)) {
                return false;
            }
        }
        return true;
    }

    private static byte[] bitsToBytes(StringBuilder bits, int offset, long bitCount) {
        byte[] out = new byte[(int) ((bitCount + 7) / 8)];
        for (int i = 0; i < bitCount; i++) {
            if (bits.charAt(offset + i) == '1') {
                out[i / 8] |= (byte) (1 << (7 - (i % 8)));
            }
        }
        return out;
    }

    /* ------------------------------------------------------------------ */
    /* trailing whitespace                                                 */
    /* ------------------------------------------------------------------ */

    private static byte[] hideTrailingWs(String text, byte[] container) {
        String[] lines = text.split("\n", -1);
        long capacity = lines.length;
        long needed = container.length * 8L;
        if (needed > capacity) {
            throw new StegoException("Payload too large for trailing-whitespace mode — capacity is "
                    + capacity + " bits (" + lines.length + " lines), payload needs " + needed + " bits");
        }
        String[] out = lines.clone();
        int bitIndex = 0;
        int totalBits = container.length * 8;
        for (int i = 0; i < out.length && bitIndex < totalBits; i++) {
            String line = stripTrailingWs(out[i]);
            int bit = (container[bitIndex / 8] >>> (7 - (bitIndex % 8))) & 1;
            out[i] = line + (bit == 0 ? " " : "\t");
            bitIndex++;
        }
        return String.join("\n", out).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] extractTrailingWs(String text) {
        String[] lines = text.split("\n", -1);
        StringBuilder bits = new StringBuilder(lines.length);
        for (String line : lines) {
            if (line.endsWith(" ")) {
                bits.append('0');
            } else if (line.endsWith("\t")) {
                bits.append('1');
            }
        }
        int n = bits.length();
        if (n < Packet.HEADER * 8) {
            return null;
        }
        for (int offset = 0; offset <= n - Packet.HEADER * 8; offset++) {
            if (magicAt(bits, offset)) {
                byte[] header = bitsToBytes(bits, offset, Packet.HEADER * 8);
                int ctLen = BitIO.getInt(header, 8);
                long totalBits = (long) (Packet.HEADER + ctLen) * 8L;
                if (ctLen < 0 || offset + totalBits > n) {
                    continue;
                }
                byte[] raw = bitsToBytes(bits, offset, totalBits);
                if (Packet.looksLike(raw)) {
                    return raw;
                }
            }
        }
        return null;
    }

    private static String stripTrailingWs(String line) {
        int end = line.length();
        while (end > 0 && (line.charAt(end - 1) == ' ' || line.charAt(end - 1) == '\t')) {
            end--;
        }
        return line.substring(0, end);
    }
}
