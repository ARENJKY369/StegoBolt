package com.stegobolt.engine.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BitIOTest {

    @Test
    void writesAndReadsMsbFirst() {
        byte[] data = {(byte) 0b10110001, (byte) 0b00001111};
        long[] bits = new long[16];
        BitIO.write(data, 0, (i, bit) -> bits[(int) i] = bit);

        // MSB-first: bit 7 of byte 0 first
        assertEquals(1, bits[0]);
        assertEquals(0, bits[1]);
        assertEquals(1, bits[2]);
        assertEquals(1, bits[3]);

        byte[] round = BitIO.read(16, 0, i -> (int) bits[(int) i]);
        assertArrayEquals(data, round);
    }

    @Test
    void offsetsCarryAcrossBytes() {
        byte[] data = {(byte) 0xFF};
        long[] bits = new long[12];
        BitIO.write(data, 3, (i, bit) -> bits[(int) i] = bit);
        assertEquals(0, bits[2]);
        assertEquals(1, bits[3]);
        assertEquals(1, bits[10]);
        assertEquals(0, bits[11]);

        byte[] round = BitIO.read(8, 3, i -> (int) bits[(int) i]);
        assertArrayEquals(data, round);
    }

    @Test
    void bigEndianIntsRoundTrip() {
        byte[] buf = new byte[8];
        BitIO.putInt(buf, 0, 0xDEADBEEF);
        BitIO.putInt(buf, 4, 65536);
        assertEquals(0xDEADBEEF, BitIO.getInt(buf, 0));
        assertEquals(65536, BitIO.getInt(buf, 4));
    }

    @Test
    void countsChangedBits() {
        assertEquals(0, BitIO.changedBits(new byte[]{0x0F}, new byte[]{0x0F}));
        assertEquals(4, BitIO.changedBits(new byte[]{0x00}, new byte[]{0x0F}));
        assertEquals(8, BitIO.changedBits(new byte[]{0x00}, new byte[]{(byte) 0xFF}));
    }

    @Test
    void wipeOverwritesBuffers() {
        byte[] secret = {1, 2, 3};
        char[] pass = {'s', 'e', 'c'};
        MemoryHygiene.wipe(secret);
        MemoryHygiene.wipe(pass);
        assertArrayEquals(new byte[]{0, 0, 0}, secret);
        assertEquals('\0', pass[0]);
    }
}
