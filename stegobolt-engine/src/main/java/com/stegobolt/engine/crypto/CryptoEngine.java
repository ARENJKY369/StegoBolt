package com.stegobolt.engine.crypto;

import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Cryptography Engine — pure JCA (Java Cryptography Architecture), §4.3.
 *
 * <ul>
 *   <li>Key derivation: {@code PBKDF2WithHmacSHA256} @ 100,000 iterations, 256-bit key.</li>
 *   <li>Sealed cipher: {@code AES/GCM/NoPadding} (128-bit tag, 96-bit IV).</li>
 *   <li>Randomness: {@link SecureRandom} only.</li>
 * </ul>
 *
 * <p>Derived keys and plaintext copies are wiped with
 * {@link MemoryHygiene#wipe(byte[]...)} in {@code finally} blocks. Passphrases are
 * accepted as {@code char[]} so callers can wipe them; nothing here ever logs
 * key material, passphrases or plaintext (zero payload logging).
 */
public final class CryptoEngine {

    public static final int PBKDF2_ITERATIONS = 100_000;
    public static final int KEY_BITS = 256;
    public static final int GCM_TAG_BITS = 128;

    private static final SecureRandom RNG = new SecureRandom();

    private CryptoEngine() {
    }

    /** Fresh CSPRNG handle for engines that need noise-floor randomization. */
    public static SecureRandom newRng() {
        return new SecureRandom();
    }

    /** Fresh CSPRNG bytes. */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    /** PBKDF2WithHmacSHA256 → AES-256 key bytes. Caller wipes the result. */
    public static byte[] deriveKey(char[] passphrase, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new StegoException("Key derivation unavailable on this JVM", e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Seal {@code plaintext} with AES-256-GCM under a passphrase-derived key and
     * wrap it in an SBV2-J {@link Packet}. The plaintext buffer is NOT wiped here —
     * the caller owns it.
     */
    public static Packet seal(byte[] plaintext, char[] passphrase, Medium medium) {
        byte[] salt = randomBytes(Packet.SALT_LEN);
        byte[] iv = randomBytes(Packet.IV_LEN);
        byte[] key = null;
        try {
            key = deriveKey(passphrase, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            // salt + iv live on inside the Packet; only the derived key is wiped.
            return Packet.of(medium, salt, iv, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new StegoException("Payload sealing failed", e);
        } finally {
            MemoryHygiene.wipe(key);
        }
    }

    /**
     * Open a sealed {@link Packet}. A wrong passphrase or a tampered carrier fails
     * the GCM authentication tag and surfaces a clean error — never garbage.
     */
    public static byte[] open(Packet packet, char[] passphrase) {
        byte[] key = null;
        try {
            key = deriveKey(passphrase, packet.salt());
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, packet.iv()));
            return cipher.doFinal(packet.ciphertext());
        } catch (BadPaddingException e) {
            throw new StegoException("Decryption failed — wrong passphrase or tampered carrier", e);
        } catch (GeneralSecurityException e) {
            throw new StegoException("Decryption failed", e);
        } finally {
            MemoryHygiene.wipe(key);
        }
    }
}
