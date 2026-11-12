package com.stegobolt.engine.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PacketTest {

    @Test
    void validatesCompleteEncryptedPacketForExpectedMedium() {
        byte[] packet = new byte[Packet.HEADER + Packet.GCM_TAG_LEN];
        System.arraycopy(Packet.MAGIC, 0, packet, 0, Packet.MAGIC.length);
        packet[4] = Packet.VERSION;
        packet[5] = Medium.TEXT.id();
        packet[6] = Packet.FLAG_ENCRYPTED;
        BitIO.putInt(packet, 8, Packet.GCM_TAG_LEN);

        assertTrue(Packet.isValidForMedium(packet, Medium.TEXT));
        assertFalse(Packet.isValidForMedium(packet, Medium.IMAGE));
        assertFalse(Packet.isValidForMedium(java.util.Arrays.copyOf(packet, packet.length - 1), Medium.TEXT));

        packet[6] = 0;
        assertFalse(Packet.isValidForMedium(packet, Medium.TEXT));
    }
}
