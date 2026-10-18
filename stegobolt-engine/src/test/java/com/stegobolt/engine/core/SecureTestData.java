package com.stegobolt.engine.core;

import java.util.Random;

/**
 * Deterministic pseudo-random fixtures for the steganalysis tests.
 * (Named SecureTestData for clarity — these are test vectors, not secrets.)
 */
public final class SecureTestData {

    private SecureTestData() {
    }

    /** Deterministic byte noise with a fixed seed — reproducible across runs. */
    public static byte[] deterministicNoise(int n) {
        byte[] data = new byte[n];
        new Random(1234).nextBytes(data);
        return data;
    }
}
