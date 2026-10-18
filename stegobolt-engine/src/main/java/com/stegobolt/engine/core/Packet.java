package com.stegobolt.engine.core;

import java.util.Arrays;

/**
 * SBV2-J — the sealed-payload container every medium engine embeds and extracts.
 *
 * <pre>
 *   offset  size  field
 *   0       4     magic          'S' 'B' '2' 'J'
 *   4       1     version        0x02
 *   5       1     medium id      {@link Medium#id()}
 *   6       1     flags          bit0 = 1 (payload is AES-256-GCM sealed)
 *   7       1     reserved       0x00
 *   8       4     ciphertext len (big-endian, includes the 16-byte GCM tag)
 *   12      16    PBKDF2 salt
 *   28      12    AES-GCM IV
 *   40      n     ciphertext
 * </pre>
 */
public final class Packet {

    public static final byte[] MAGIC = {'S', 'B', '2', 'J'};
    public static final int HEADER = 40;
    public static final byte VERSION = 0x02;
    public static final int FLAG_ENCRYPTED = 0x01;

    public static final int SALT_LEN = 16;
    public static final int IV_LEN = 12;
    public static final int MAX_CIPHERTEXT = 64 * 1024 * 1024;

    private final byte version;
    private final byte mediumId;
    private final byte flags;
    private final byte[] salt;
    private final byte[] iv;
    private final byte[] ciphertext;

    private Packet(byte version, byte mediumId, byte flags, byte[] salt, byte[] iv, byte[] ciphertext) {
        this.version = version;
        this.mediumId = mediumId;
        this.flags = flags;
        this.salt = salt;
        this.iv = iv;
        this.ciphertext = ciphertext;
    }

    public static Packet of(Medium medium, byte[] salt, byte[] iv, byte[] ciphertext) {
        return new Packet(VERSION, medium.id(), (byte) FLAG_ENCRYPTED, salt, iv, ciphertext);
    }

    public byte version() {
        return version;
    }

    public byte mediumId() {
        return mediumId;
    }

    public Medium medium() {
        return Medium.fromId(mediumId);
    }

    public byte[] salt() {
        return salt;
    }

    public byte[] iv() {
        return iv;
    }

    public byte[] ciphertext() {
        return ciphertext;
    }

    public int ciphertextLength() {
        return ciphertext.length;
    }

    /** Serialize the full container. Caller wipes the returned buffer. */
    public byte[] serialize() {
        byte[] raw = new byte[HEADER + ciphertext.length];
        System.arraycopy(MAGIC, 0, raw, 0, MAGIC.length);
        raw[4] = version;
        raw[5] = mediumId;
        raw[6] = flags;
        raw[7] = 0;
        BitIO.putInt(raw, 8, ciphertext.length);
        System.arraycopy(salt, 0, raw, 12, SALT_LEN);
        System.arraycopy(iv, 0, raw, 28, IV_LEN);
        System.arraycopy(ciphertext, 0, raw, HEADER, ciphertext.length);
        return raw;
    }

    /** True when {@code raw} starts with a plausible SBV2-J header. */
    public static boolean looksLike(byte[] raw) {
        return looksLike(raw, 0);
    }

    /**
     * Header-only probe: validates magic, version and a plausible ciphertext
     * length <b>without</b> requiring the body to be present. Used by engines
     * that read the 40-byte header first and the ciphertext second.
     */
    public static boolean looksLikeHeader(byte[] header) {
        if (header == null || header.length < HEADER) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                return false;
            }
        }
        if (header[4] != VERSION) {
            return false;
        }
        int len = BitIO.getInt(header, 8);
        return len >= 0 && len <= MAX_CIPHERTEXT;
    }

    public static boolean looksLike(byte[] raw, int offset) {
        if (raw == null || raw.length - offset < HEADER) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[offset + i] != MAGIC[i]) {
                return false;
            }
        }
        if (raw[offset + 4] != VERSION) {
            return false;
        }
        int len = BitIO.getInt(raw, offset + 8);
        return len >= 0 && len <= MAX_CIPHERTEXT && raw.length - offset >= (long) HEADER + len;
    }

    /** Parse a container at {@code offset}; throws {@link StegoException} when malformed. */
    public static Packet parse(byte[] raw, int offset) {
        if (!looksLike(raw, offset)) {
            throw new StegoException("No SBV2-J container found at the given offset");
        }
        int len = BitIO.getInt(raw, offset + 8);
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        byte[] ct = new byte[len];
        System.arraycopy(raw, offset + 12, salt, 0, SALT_LEN);
        System.arraycopy(raw, offset + 28, iv, 0, IV_LEN);
        System.arraycopy(raw, offset + HEADER, ct, 0, len);
        return new Packet(raw[offset + 4], raw[offset + 5], raw[offset + 6], salt, iv, ct);
    }

    /** Locate the first SBV2-J container inside {@code raw}, or -1. */
    public static int indexOf(byte[] raw) {
        if (raw == null) {
            return -1;
        }
        for (int i = 0; i + HEADER <= raw.length; i++) {
            if (raw[i] == MAGIC[0] && looksLike(raw, i)) {
                boolean match = true;
                for (int k = 1; k < MAGIC.length; k++) {
                    if (raw[i + k] != MAGIC[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return i;
                }
            }
        }
        return -1;
    }

    /** Wipe this packet's mutable fields. */
    public void wipe() {
        MemoryHygiene.wipe(salt, iv, ciphertext);
    }

    @Override
    public String toString() {
        // Deliberately metadata-only: never print salt/iv/ciphertext (zero payload logging).
        return "SBV2-J{version=" + version + ", medium=" + mediumId + ", ctLen=" + ciphertext.length + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Packet other)) {
            return false;
        }
        return version == other.version
                && mediumId == other.mediumId
                && Arrays.equals(salt, other.salt)
                && Arrays.equals(iv, other.iv)
                && Arrays.equals(ciphertext, other.ciphertext);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(salt) ^ Arrays.hashCode(iv) ^ Arrays.hashCode(ciphertext);
    }
}
