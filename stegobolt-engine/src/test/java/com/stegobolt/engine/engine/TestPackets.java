package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.BitIO;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;

/**
 * Test fixture: builds minimal but structurally valid SBV2-J containers
 * (magic + version + medium + length) without invoking the crypto layer.
 */
final class TestPackets {

    private TestPackets() {
    }

    /** Valid SBV2-J framing around {@code body}. */
    static byte[] container(byte[] body) {
        byte[] raw = new byte[Packet.HEADER + body.length];
        System.arraycopy(Packet.MAGIC, 0, raw, 0, Packet.MAGIC.length);
        raw[4] = Packet.VERSION;
        raw[5] = Medium.IMAGE.id();
        raw[6] = (byte) Packet.FLAG_ENCRYPTED;
        BitIO.putInt(raw, 8, body.length);
        System.arraycopy(body, 0, raw, Packet.HEADER, body.length);
        return raw;
    }

    /** Random-looking but deterministic body bytes. */
    static byte[] body(int n) {
        byte[] body = new byte[n];
        for (int i = 0; i < n; i++) {
            body[i] = (byte) (i * 31 + 7);
        }
        return body;
    }
}
