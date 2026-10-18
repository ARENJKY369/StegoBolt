package com.stegobolt.engine.core;

/**
 * The six steganographic mediums StegoBolt can hide data inside.
 *
 * <ol>
 *   <li>{@link #IMAGE}    — PNG / BMP / WebP pixel LSB planes.</li>
 *   <li>{@link #AUDIO}    — WAV sample noise floors / FLAC padding layers.</li>
 *   <li>{@link #VIDEO}    — MP4 / MKV / AVI frame planes & container padding.</li>
 *   <li>{@link #DOCUMENT} — PDF / DOCX hidden structural metadata streams.</li>
 *   <li>{@link #TEXT}     — zero-width Unicode spaces & trailing whitespace.</li>
 *   <li>{@link #NETWORK}  — PCAP TCP/IP header padding bits.</li>
 * </ol>
 */
public enum Medium {

    IMAGE((byte) 1, "Image"),
    AUDIO((byte) 2, "Audio"),
    VIDEO((byte) 3, "Video"),
    DOCUMENT((byte) 4, "Document"),
    TEXT((byte) 5, "Text"),
    NETWORK((byte) 6, "Network");

    private final byte id;
    private final String label;

    Medium(byte id, String label) {
        this.id = id;
        this.label = label;
    }

    public byte id() {
        return id;
    }

    public String label() {
        return label;
    }

    public static Medium fromId(byte id) {
        for (Medium m : values()) {
            if (m.id == id) {
                return m;
            }
        }
        throw new StegoException("Unknown medium id in container: " + id);
    }
}
