package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.BitIO;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Video Steganography (MP4, MKV, AVI) — §4.2.
 *
 * <p><b>AVI (uncompressed DIB frames)</b> — the container is walked at RIFF-chunk
 * level and the payload is scattered over the LSB plane of every {@code 00db}
 * frame payload (uncompressed video frame LSB layer).
 *
 * <p><b>MP4 (ISO-BMFF) / MKV (Matroska)</b> — the payload rides in hidden
 * structural padding: a top-level {@code free} box (MP4) or EBML {@code Void}
 * element (MKV) whose content is ignored by every demuxer, so playback is
 * bit-perfect. Motion-vector coding paths stay untouched.
 */
public final class VideoStegoEngine implements StegoEngine {

    private static final byte[] VOID_ID = {(byte) 0xEC};
    private static final int MAX_CONTAINER = 16 * 1024 * 1024;

    @Override
    public Medium medium() {
        return Medium.VIDEO;
    }

    @Override
    public long capacityBits(byte[] cover) {
        if (isAvi(cover)) {
            long frameBytes = 0;
            for (int[] chunk : aviFrameChunks(cover)) {
                frameBytes += chunk[1] - chunk[0];
            }
            return frameBytes; // one embeddable bit per frame byte
        }
        return MAX_CONTAINER * 8L; // structural padding: bounded by request size
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        if (container.length > MAX_CONTAINER) {
            throw new StegoException("Payload too large for video padding layer (max 16 MiB)");
        }
        return isAvi(cover) ? hideAvi(cover, container) : hideStructural(cover, container);
    }

    @Override
    public byte[] extract(byte[] cover) {
        return isAvi(cover) ? extractAvi(cover) : extractStructural(cover);
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        long changed = 0;
        long randomized = 0;
        byte[] cleaned;
        if (isAvi(cover)) {
            cleaned = cover.clone();
            List<int[]> frames = aviFrameChunks(cleaned);
            boolean hasEmbedded = !randomizeLsb && extractAvi(cover) != null;
            java.security.SecureRandom rng = randomizeLsb ? com.stegobolt.engine.crypto.CryptoEngine.newRng() : null;
            for (int[] chunk : frames) {
                for (int i = chunk[0]; i < chunk[1]; i++) {
                    if (randomizeLsb) {
                        int bit = rng.nextInt(2);
                        int before = cleaned[i] & 1;
                        cleaned[i] = (byte) ((cleaned[i] & 0xFE) | bit);
                        if (before != bit) {
                            changed++;
                        }
                        randomized++;
                    } else if (hasEmbedded) {
                        // neutralize by clearing LSBs of frame bytes
                        changed += cleaned[i] & 1;
                        cleaned[i] = (byte) (cleaned[i] & 0xFE);
                    }
                }
            }
        } else {
            // structural layer: strip our padding box/element entirely
            byte[] before = extractStructural(cover);
            changed = before == null ? 0 : before.length * 8L;
            if (before != null) {
                MemoryHygiene.wipe(before);
            }
            cleaned = stripStructural(cover);
            randomized = changed;
        }
        return new SanitizeOutcome(cleaned, changed, randomized);
    }

    /* ------------------------------------------------------------------ */
    /* AVI — uncompressed frame LSB                                        */
    /* ------------------------------------------------------------------ */

    private static boolean isAvi(byte[] cover) {
        return cover.length > 12
                && cover[0] == 'R' && cover[1] == 'I' && cover[2] == 'F' && cover[3] == 'F'
                && cover[8] == 'A' && cover[9] == 'V' && cover[10] == 'I' && cover[11] == ' ';
    }

    /** Locate [start,end) byte ranges of uncompressed {@code 00db}/{@code 00dc} frame payloads. */
    private static List<int[]> aviFrameChunks(byte[] cover) {
        List<int[]> frames = new ArrayList<>();
        walkRiff(cover, 12, cover.length, frames);
        return frames;
    }

    private static void walkRiff(byte[] data, int start, int end, List<int[]> frames) {
        int pos = start;
        while (pos + 8 <= end) {
            String fourcc = new String(data, pos, 4, StandardCharsets.US_ASCII);
            int size = (data[pos + 4] & 0xFF)
                    | ((data[pos + 5] & 0xFF) << 8)
                    | ((data[pos + 6] & 0xFF) << 16)
                    | ((data[pos + 7] & 0xFF) << 24);
            int payloadStart = pos + 8;
            int payloadEnd = payloadStart + Math.max(0, Math.min(size, end - payloadStart));
            if (fourcc.equals("LIST")) {
                String listType = new String(data, payloadStart, 4, StandardCharsets.US_ASCII);
                if (listType.equals("movi")) {
                    walkRiff(data, payloadStart + 4, payloadEnd, frames);
                }
            } else if (fourcc.equals("00db") || fourcc.equals("00dc")) {
                frames.add(new int[]{payloadStart, payloadEnd});
            }
            pos = payloadEnd + (size & 1); // RIFF chunks are word-aligned
        }
    }

    private static byte[] hideAvi(byte[] cover, byte[] container) {
        List<int[]> frames = aviFrameChunks(cover);
        long capacity = 0;
        for (int[] chunk : frames) {
            capacity += chunk[1] - chunk[0];
        }
        if (container.length * 8L > capacity) {
            throw new StegoException("Payload too large for this video — capacity is "
                    + capacity + " bytes, payload needs " + container.length + " bytes");
        }
        byte[] out = cover.clone();
        BitIO.write(container, 0, (bitIndex, bit) -> {
            // one LSB per frame byte: bit slot i lives in the i-th frame byte
            long byteIndex = bitIndex;
            for (int[] chunk : frames) {
                long len = chunk[1] - chunk[0];
                if (byteIndex < len) {
                    int at = chunk[0] + (int) byteIndex;
                    out[at] = (byte) ((out[at] & 0xFE) | bit);
                    return;
                }
                byteIndex -= len;
            }
        });
        return out;
    }

    private static byte[] extractAvi(byte[] cover) {
        List<int[]> frames = aviFrameChunks(cover);
        long capacity = 0;
        for (int[] chunk : frames) {
            capacity += chunk[1] - chunk[0];
        }
        if (capacity < Packet.HEADER * 8L) {
            return null;
        }
        byte[] header = BitIO.read(Packet.HEADER * 8L, 0, i -> bitAt(frames, cover, i));
        if (!Packet.looksLikeHeader(header)) {
            return null;
        }
        int ctLen = BitIO.getInt(header, 8);
        long total = (long) Packet.HEADER + ctLen;
        if (total * 8L > capacity) {
            return null;
        }
        byte[] raw = BitIO.read(total * 8L, 0, i -> bitAt(frames, cover, i));
        return Packet.looksLike(raw) ? raw : null;
    }

    private static int bitAt(List<int[]> frames, byte[] cover, long bitIndex) {
        long byteIndex = bitIndex; // one LSB per frame byte
        for (int[] chunk : frames) {
            long len = chunk[1] - chunk[0];
            if (byteIndex < len) {
                return cover[chunk[0] + (int) byteIndex] & 1;
            }
            byteIndex -= len;
        }
        return 0;
    }

    /* ------------------------------------------------------------------ */
    /* MP4 free-box / MKV Void-element structural padding                  */
    /* ------------------------------------------------------------------ */

    private static byte[] hideStructural(byte[] cover, byte[] container) {
        byte[] payload = new byte[Packet.MAGIC.length + container.length];
        System.arraycopy(Packet.MAGIC, 0, payload, 0, Packet.MAGIC.length);
        System.arraycopy(container, 0, payload, Packet.MAGIC.length, container.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream(cover.length + payload.length + 16);
        if (isMp4(cover)) {
            out.write(cover, 0, cover.length);
            // top-level 'free' box: 8-byte header + payload
            writeInt(out, payload.length + 8);
            out.write('f');
            out.write('r');
            out.write('e');
            out.write('e');
            out.write(payload, 0, payload.length);
        } else {
            // MKV: EBML Void (0xEC) + VINT size + payload
            out.write(cover, 0, cover.length);
            out.write(VOID_ID, 0, VOID_ID.length);
            writeEbmlVint(out, payload.length);
            out.write(payload, 0, payload.length);
        }
        return out.toByteArray();
    }

    private static byte[] extractStructural(byte[] cover) {
        if (isMp4(cover)) {
            return extractMp4Free(cover);
        }
        return extractMkvVoid(cover);
    }

    private static byte[] stripStructural(byte[] cover) {
        byte[] found = extractStructural(cover);
        if (found == null) {
            return cover.clone();
        }
        // Rebuild without any padding box/element carrying our magic.
        if (isMp4(cover)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(cover.length);
            int pos = 0;
            while (pos + 8 <= cover.length) {
                int size = readInt(cover, pos);
                String type = new String(cover, pos + 4, 4, StandardCharsets.US_ASCII);
                if (size < 8 || pos + size > cover.length) {
                    out.write(cover, pos, cover.length - pos);
                    break;
                }
                if (!type.equals("free") || !hasMagic(cover, pos + 8, size - 8)) {
                    out.write(cover, pos, size);
                }
                pos += size;
            }
            return out.toByteArray();
        }
        // MKV: drop Void elements carrying the magic
        ByteArrayOutputStream out = new ByteArrayOutputStream(cover.length);
        int pos = 0;
        while (pos < cover.length) {
            if ((cover[pos] & 0xFF) == 0xEC && pos + 1 < cover.length) {
                int[] sizeInfo = readEbmlVint(cover, pos + 1);
                if (sizeInfo != null) {
                    int total = 1 + sizeInfo[1] + sizeInfo[0];
                    if (!hasMagic(cover, pos + 1 + sizeInfo[1], sizeInfo[0])) {
                        out.write(cover, pos, total);
                    }
                    pos += total;
                    continue;
                }
            }
            out.write(cover[pos]);
            pos++;
        }
        return out.toByteArray();
    }

    private static byte[] extractMp4Free(byte[] cover) {
        int pos = 0;
        while (pos + 8 <= cover.length) {
            int size = readInt(cover, pos);
            String type = new String(cover, pos + 4, 4, StandardCharsets.US_ASCII);
            if (size < 8 || pos + (long) size > cover.length) {
                break;
            }
            if (type.equals("free") && hasMagic(cover, pos + 8, size - 8)) {
                return Arrays.copyOfRange(cover, pos + 8 + Packet.MAGIC.length, pos + size);
            }
            pos += size;
        }
        return null;
    }

    private static byte[] extractMkvVoid(byte[] cover) {
        int pos = 0;
        while (pos + 1 < cover.length) {
            if ((cover[pos] & 0xFF) == 0xEC) {
                int[] sizeInfo = readEbmlVint(cover, pos + 1);
                if (sizeInfo != null) {
                    int payloadStart = pos + 1 + sizeInfo[1];
                    if (hasMagic(cover, payloadStart, sizeInfo[0])) {
                        return Arrays.copyOfRange(cover, payloadStart + Packet.MAGIC.length,
                                payloadStart + sizeInfo[0]);
                    }
                    pos = payloadStart + sizeInfo[0];
                    continue;
                }
            }
            pos++;
        }
        return null;
    }

    private static boolean isMp4(byte[] cover) {
        return cover.length > 8 && new String(cover, 4, 4, StandardCharsets.US_ASCII).equals("ftyp");
    }

    private static boolean hasMagic(byte[] data, int offset, int len) {
        if (len < Packet.MAGIC.length || offset + Packet.MAGIC.length > data.length) {
            return false;
        }
        for (int i = 0; i < Packet.MAGIC.length; i++) {
            if (data[offset + i] != Packet.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    /** Encode an EBML VINT size (7-bit form for small payloads). */
    private static void writeEbmlVint(ByteArrayOutputStream out, int value) {
        if (value < 0x7F) {
            out.write(0x80 | value);
            return;
        }
        // 2-byte form
        int v = value & 0x3FFF;
        out.write(0x40 | ((v >>> 8) & 0x3F));
        out.write(v & 0xFF);
    }

    /** @return {value, width} or null when malformed. */
    private static int[] readEbmlVint(byte[] data, int offset) {
        if (offset >= data.length) {
            return null;
        }
        int first = data[offset] & 0xFF;
        if ((first & 0x80) != 0) {
            return new int[]{first & 0x7F, 1};
        }
        if ((first & 0x40) != 0 && offset + 1 < data.length) {
            return new int[]{((first & 0x3F) << 8) | (data[offset + 1] & 0xFF), 2};
        }
        return null;
    }
}
