package com.stegobolt.engine.core;

/**
 * Explicit volatile-RAM purging (§5 of the StegoBolt Engine charter).
 *
 * <p>Every {@code byte[]} holding media bytes or secret payloads MUST be passed to
 * {@link #wipe(byte[]...)} inside a {@code finally} block immediately after the
 * response stream has been written. {@code char[]} passphrases are wiped the same
 * way so key material never lingers in the heap longer than necessary.
 */
public final class MemoryHygiene {

    private MemoryHygiene() {
    }

    /** Overwrite every buffer with zero bytes. Null-safe, order-safe. */
    public static void wipe(byte[]... buffers) {
        if (buffers == null) {
            return;
        }
        for (byte[] buffer : buffers) {
            if (buffer != null) {
                java.util.Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    /** Overwrite passphrase material with NUL chars. */
    public static void wipe(char[]... buffers) {
        if (buffers == null) {
            return;
        }
        for (char[] buffer : buffers) {
            if (buffer != null) {
                java.util.Arrays.fill(buffer, '\0');
            }
        }
    }
}
