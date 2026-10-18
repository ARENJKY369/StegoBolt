package com.stegobolt.engine.crypto;

import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoEngineTest {

    @Test
    void sealThenOpenRoundTrips() {
        byte[] plaintext = "the secret payload".getBytes(StandardCharsets.UTF_8);
        char[] pass = "correct horse battery staple".toCharArray();
        Packet packet = CryptoEngine.seal(plaintext, pass, Medium.IMAGE);
        byte[] raw = packet.serialize();
        assertTrue(Packet.looksLike(raw));

        Packet parsed = Packet.parse(raw, 0);
        byte[] opened = CryptoEngine.open(parsed, pass);
        assertArrayEquals(plaintext, opened);
    }

    @Test
    void wrongPassphraseFailsClosed() {
        byte[] plaintext = new byte[]{1, 2, 3, 4};
        Packet packet = CryptoEngine.seal(plaintext, "right".toCharArray(), Medium.TEXT);
        byte[] raw = packet.serialize();
        assertThrows(StegoException.class,
                () -> CryptoEngine.open(Packet.parse(raw, 0), "wrong".toCharArray()));
    }

    @Test
    void tamperedCiphertextFailsTheGcmTag() {
        byte[] plaintext = new byte[]{9, 9, 9, 9, 9};
        Packet packet = CryptoEngine.seal(plaintext, "pw".toCharArray(), Medium.AUDIO);
        byte[] raw = packet.serialize();
        raw[raw.length - 1] ^= 0x55; // flip one ciphertext bit
        assertThrows(StegoException.class,
                () -> CryptoEngine.open(Packet.parse(raw, 0), "pw".toCharArray()));
    }

    @Test
    void deriveKeyIsSaltAndPassphraseSensitive() {
        byte[] salt = CryptoEngine.randomBytes(Packet.SALT_LEN);
        byte[] k1 = CryptoEngine.deriveKey("a".toCharArray(), salt);
        byte[] k2 = CryptoEngine.deriveKey("b".toCharArray(), salt);
        byte[] k3 = CryptoEngine.deriveKey("a".toCharArray(), CryptoEngine.randomBytes(Packet.SALT_LEN));
        assertFalse(java.util.Arrays.equals(k1, k2));
        assertFalse(java.util.Arrays.equals(k1, k3));
    }

    @Test
    void containerIndexFindsSignature() {
        byte[] plaintext = new byte[]{7, 7, 7};
        Packet packet = CryptoEngine.seal(plaintext, "x".toCharArray(), Medium.NETWORK);
        byte[] raw = packet.serialize();
        byte[] padded = new byte[raw.length + 32];
        System.arraycopy(raw, 0, padded, 32, raw.length);
        assertEqualsAt(32, Packet.indexOf(padded));
    }

    private static void assertEqualsAt(int expected, int actual) {
        if (expected != actual) {
            throw new AssertionError("expected " + expected + " but was " + actual);
        }
    }
}
