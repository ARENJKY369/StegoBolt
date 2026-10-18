package com.stegobolt.engine.core;

/**
 * Native-Java bitwise pack/unpack used by every medium engine.
 *
 * <p>All packing goes through the raw {@code &}, {@code |}, {@code ^},
 * {@code <<}, {@code >>} and {@code >>>} operators (§4.2 — Bitwise Engine).
 * Bits are packed MSB-first: bit 7 of the first byte first.
 */
public final class BitIO {

    private BitIO() {
    }

    /** Destination for one embedded bit (index = bit index in the cover). */
    @FunctionalInterface
    public interface BitSink {
        void set(long index, int bit);
    }

    /** Source for one embedded bit (index = bit index in the cover). */
    @FunctionalInterface
    public interface BitSource {
        int get(long index);
    }

    /** Write {@code data.length * 8} bits into the cover, starting at {@code startBit}. */
    public static void write(byte[] data, long startBit, BitSink sink) {
        long index = startBit;
        for (byte b : data) {
            int value = b & 0xFF;
            for (int shift = 7; shift >= 0; shift--) {
                sink.set(index++, (value >>> shift) & 1);
            }
        }
    }

    /** Read {@code bitCount} bits from the cover, starting at {@code startBit}. */
    public static byte[] read(long bitCount, long startBit, BitSource source) {
        int byteCount = (int) ((bitCount + 7) / 8);
        byte[] out = new byte[byteCount];
        long index = startBit;
        for (int i = 0; i < byteCount; i++) {
            int value = 0;
            for (int shift = 7; shift >= 0; shift--) {
                if (index - startBit >= bitCount) {
                    break;
                }
                int bit = source.get(index++) & 1;
                value |= (bit << shift);
            }
            out[i] = (byte) value;
        }
        return out;
    }

    /** Big-endian int encode. */
    public static void putInt(byte[] target, int offset, int value) {
        target[offset] = (byte) (value >>> 24);
        target[offset + 1] = (byte) (value >>> 16);
        target[offset + 2] = (byte) (value >>> 8);
        target[offset + 3] = (byte) value;
    }

    /** Big-endian int decode. */
    public static int getInt(byte[] source, int offset) {
        return ((source[offset] & 0xFF) << 24)
                | ((source[offset + 1] & 0xFF) << 16)
                | ((source[offset + 2] & 0xFF) << 8)
                | (source[offset + 3] & 0xFF);
    }

    /** Count differing bits between two equally sized buffers (LSB-plane diff). */
    public static long changedBits(byte[] a, byte[] b) {
        long changed = 0;
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int x = (a[i] ^ b[i]) & 0xFF;
            while (x != 0) {
                changed += x & 1;
                x >>>= 1;
            }
        }
        changed += Math.abs(a.length - b.length) * 8L;
        return changed;
    }
}
