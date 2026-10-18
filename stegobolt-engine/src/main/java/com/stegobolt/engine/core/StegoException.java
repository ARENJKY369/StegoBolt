package com.stegobolt.engine.core;

/**
 * Checked failure raised by any engine layer. The message is safe to surface to
 * the client and safe to log — it never contains payload bytes, passphrases or
 * raw bit matrices (zero payload logging rule).
 */
public class StegoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public StegoException(String message) {
        super(message);
    }

    public StegoException(String message, Throwable cause) {
        super(message, cause);
    }
}
