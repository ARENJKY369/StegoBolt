package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.Sniffer;
import com.stegobolt.engine.core.StegoException;
import com.stegobolt.engine.crypto.CryptoEngine;

import java.util.ArrayList;
import java.util.List;

/**
 * Network / Covert Channel Steganography (PCAP / traffic streams) — §4.2.
 *
 * <p>Secret bits ride in the TCP/IP header padding bits — specifically the LSB
 * of the 16-bit IPv4 Identification field of every captured packet (1 bit per
 * IPv4 packet). Capture files stay valid: Wireshark and tcpdump parse them
 * normally, and IP-ID values are free real estate for exactly this reason.
 * Both classic libpcap (micro/nanosecond, both endiannesses) and pcapng
 * (Enhanced Packet Blocks) are supported. The companion timing channel
 * (packet-arrival intervals) is documented in the engine README.
 */
public final class NetworkStegoEngine implements StegoEngine {

    private static final int LINKTYPE_ETHERNET = 1;
    private static final int LINKTYPE_RAW = 101;
    private static final int LINKTYPE_IPV4 = 228;

    @Override
    public Medium medium() {
        return Medium.NETWORK;
    }

    @Override
    public long capacityBits(byte[] cover) {
        return ipIdSlots(cover).size(); // one bit per IPv4 packet
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        List<int[]> slots = ipIdSlots(cover);
        long needed = container.length * 8L;
        if (needed > slots.size()) {
            throw new StegoException("Payload too large for this capture — capacity is "
                    + slots.size() + " bits (" + slots.size() + " IPv4 packets), payload needs " + needed + " bits");
        }
        byte[] out = cover.clone();
        for (int i = 0; i < needed; i++) {
            int bit = (container[i / 8] >>> (7 - (i % 8))) & 1;
            int at = slots.get(i)[0]; // offset of the IP-ID LSB byte (id low byte)
            out[at] = (byte) ((out[at] & 0xFE) | bit);
        }
        return out;
    }

    @Override
    public byte[] extract(byte[] cover) {
        List<int[]> slots = ipIdSlots(cover);
        if (slots.size() < Packet.HEADER * 8L) {
            return null;
        }
        byte[] header = readBits(cover, slots, 0, Packet.HEADER * 8L);
        if (!Packet.looksLikeHeader(header)) {
            return null;
        }
        int ctLen = beInt(header, 8);
        long totalBits = (long) (Packet.HEADER + ctLen) * 8L;
        if (ctLen < 0 || totalBits > slots.size()) {
            return null;
        }
        byte[] raw = readBits(cover, slots, 0, totalBits);
        return Packet.looksLike(raw) ? raw : null;
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        List<int[]> slots = ipIdSlots(cover);
        byte[] out = cover.clone();
        long changed = 0;
        java.security.SecureRandom rng = randomizeLsb ? CryptoEngine.newRng() : null;
        for (int[] slot : slots) {
            int at = slot[0];
            if (randomizeLsb) {
                int bit = rng.nextInt(2);
                int before = out[at] & 1;
                out[at] = (byte) ((out[at] & 0xFE) | bit);
                if (before != bit) {
                    changed++;
                }
            } else {
                changed += out[at] & 1;
                out[at] = (byte) (out[at] & 0xFE);
            }
        }
        return new SanitizeOutcome(out, changed, slots.size());
    }

    /* ------------------------------------------------------------------ */
    /* capture parsing                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * @return list of {@code {lsbByteOffset}} — one slot per IPv4 packet.
     */
    private static List<int[]> ipIdSlots(byte[] cover) {
        if (!Sniffer.isPcap(cover)) {
            throw new StegoException("Not a PCAP/PCAPNG capture file");
        }
        return isPcapNg(cover) ? pcapNgSlots(cover) : classicSlots(cover);
    }

    private static boolean isPcapNg(byte[] cover) {
        return cover.length >= 4
                && (cover[0] & 0xFF) == 0x0A && (cover[1] & 0xFF) == 0x0D
                && (cover[2] & 0xFF) == 0x0D && (cover[3] & 0xFF) == 0x0A;
    }

    private static List<int[]> classicSlots(byte[] cover) {
        // File is big-endian when the magic reads 0xa1b2c3d4 / 0xa1b23c4d as-is.
        boolean big = (cover[0] & 0xFF) == 0xA1;
        int network = u32(cover, 20, big);
        List<int[]> slots = new ArrayList<>();
        int pos = 24;
        while (pos + 16 <= cover.length) {
            int inclLen = u32(cover, pos + 8, big);
            int dataStart = pos + 16;
            if (inclLen < 0 || dataStart + inclLen > cover.length) {
                break;
            }
            addIpSlot(cover, dataStart, inclLen, network, slots);
            pos = dataStart + inclLen;
        }
        return slots;
    }

    private static List<int[]> pcapNgSlots(byte[] cover) {
        // Section Header Block: byte-order magic at offset 8 (0x1A2B3C4D in file order).
        boolean big = (cover[8] & 0xFF) == 0x1A;
        List<int[]> slots = new ArrayList<>();
        List<Integer> linkTypes = new ArrayList<>();
        int pos = 0;
        while (pos + 12 <= cover.length) {
            int type = u32(cover, pos, big);
            int total = u32(cover, pos + 4, big);
            if (total < 12 || pos + total > cover.length) {
                break;
            }
            if (type == 0x00000001) { // Interface Description Block
                linkTypes.add(u16(cover, pos + 8, big));
            } else if (type == 0x00000006 && pos + 28 <= cover.length) { // Enhanced Packet Block
                int iface = u32(cover, pos + 8, big);
                int capLen = u32(cover, pos + 20, big);
                int dataStart = pos + 28;
                int link = iface >= 0 && iface < linkTypes.size() ? linkTypes.get(iface) : LINKTYPE_ETHERNET;
                if (dataStart + capLen <= cover.length) {
                    addIpSlot(cover, dataStart, capLen, link, slots);
                }
            } else if (type == 0x00000003 && pos + 16 <= cover.length) { // Simple Packet Block
                int origLen = u32(cover, pos + 8, big);
                int dataStart = pos + 12;
                int capLen = Math.min(origLen, total - 16);
                if (dataStart + capLen <= cover.length) {
                    addIpSlot(cover, dataStart, capLen, LINKTYPE_ETHERNET, slots);
                }
            }
            pos += total;
        }
        return slots;
    }

    /** Map one captured packet to its IPv4 ID-LSB byte offset, if it is IPv4. */
    private static void addIpSlot(byte[] pkt, int start, int len, int linkType, List<int[]> slots) {
        int ip;
        switch (linkType) {
            case LINKTYPE_ETHERNET -> {
                if (len < 34) {
                    return;
                }
                int ethertype = ((pkt[start + 12] & 0xFF) << 8) | (pkt[start + 13] & 0xFF);
                if (ethertype == 0x0800) {
                    ip = start + 14;
                } else {
                    return;
                }
            }
            case LINKTYPE_RAW, LINKTYPE_IPV4 -> ip = start;
            default -> {
                return;
            }
        }
        if (ip + 20 > start + len) {
            return;
        }
        if ((pkt[ip] >>> 4) != 4) {
            return; // not IPv4
        }
        // Identification field lives at IP header bytes 4-5; its LSB is byte 5.
        slots.add(new int[]{ip + 5});
    }

    /* ------------------------------------------------------------------ */
    /* bit helpers over the slot list                                      */
    /* ------------------------------------------------------------------ */

    private static byte[] readBits(byte[] cover, List<int[]> slots, int startBit, long bitCount) {
        byte[] out = new byte[(int) ((bitCount + 7) / 8)];
        for (int i = 0; i < bitCount; i++) {
            int[] slot = slots.get(startBit + i);
            if ((cover[slot[0]] & 1) == 1) {
                out[i / 8] |= (byte) (1 << (7 - (i % 8)));
            }
        }
        return out;
    }

    private static int u32(byte[] data, int offset, boolean big) {
        if (big) {
            return ((data[offset] & 0xFF) << 24)
                    | ((data[offset + 1] & 0xFF) << 16)
                    | ((data[offset + 2] & 0xFF) << 8)
                    | (data[offset + 3] & 0xFF);
        }
        return ((data[offset + 3] & 0xFF) << 24)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset] & 0xFF);
    }

    private static int u16(byte[] data, int offset, boolean big) {
        if (big) {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }
        return ((data[offset + 1] & 0xFF) << 8) | (data[offset] & 0xFF);
    }

    /** Big-endian int reader for container headers. */
    private static int beInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }
}
