package com.stegobolt.engine.analysis;

import com.stegobolt.engine.core.SecureTestData;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SteganalysisEngineTest {

    @Test
    void regularizedGammaMatchesKnownValues() {
        // P(1, x) = 1 - e^-x
        assertEquals(1 - Math.exp(-2), SteganalysisEngine.regularizedGammaP(1.0, 2.0), 1e-9);
        // P(a, 0) = 0
        assertEquals(0.0, SteganalysisEngine.regularizedGammaP(3.0, 0.0), 1e-12);
    }

    @Test
    void lsbOnesRatioAndEntropyOnNoise() {
        byte[] noise = SecureTestData.deterministicNoise(256);
        double ratio = SteganalysisEngine.lsbOnesRatio(noise);
        assertTrue(ratio > 0.3 && ratio < 0.7, "noise LSBs should hover near 0.5, was " + ratio);
        double entropy = SteganalysisEngine.lsbBinaryEntropy(noise);
        assertTrue(entropy > 0.9, "binary entropy of noise should be near 1.0, was " + entropy);
    }

    @Test
    void chiSquareFlagsEqualizedValuePairs() {
        // Unequalized cover: only even values → n(2i) ≫ n(2i+1) for every pair.
        Random rng = new Random(42);
        byte[] cover = new byte[4096];
        for (int i = 0; i < cover.length; i++) {
            cover[i] = (byte) (rng.nextInt(128) << 1);
        }
        double before = SteganalysisEngine.chiSquareProbability(cover);

        // Perfectly equalized embedding: every value 0..255 appears equally often,
        // so n(2i) == n(2i+1) for all 128 pairs — the classic sequential-LSB fingerprint.
        byte[] embedded = new byte[4096];
        for (int i = 0; i < embedded.length; i++) {
            embedded[i] = (byte) (i & 0xFF);
        }
        double after = SteganalysisEngine.chiSquareProbability(embedded);
        assertTrue(after > before, "equalized pairs must raise the embedding probability (" + before + " -> " + after + ")");
        assertTrue(after > 0.9, "perfectly equalized pairs should look embedded, was " + after);
    }

    @Test
    void spaRespondsToSequentialLsbReplacement() {
        // Poised-pair-dominated stream: alternating type A (even, even+1) and
        // type B (odd, odd+1) pairs — the regime the first-order SPA model covers.
        byte[] samples = new byte[8000];
        for (int i = 0; i < samples.length; i += 4) {
            int base = 2 * ((i / 4) % 60);
            samples[i] = (byte) base;            // type A pair: (even, even+1)
            samples[i + 1] = (byte) (base + 1);
            samples[i + 2] = (byte) (base + 1);  // type B pair: (odd, odd+1)
            samples[i + 3] = (byte) (base + 2);
        }
        double cleanPi = SteganalysisEngine.spaEmbeddingRatio(samples);
        assertTrue(cleanPi < 0.15, "clean poised stream should estimate ~0, was " + cleanPi);

        // One-shot LSB replacement at change-probability p = 0.25 (π ≈ 0.5).
        Random rng = new Random(7);
        byte[] embedded = samples.clone();
        for (int i = 0; i < embedded.length; i++) {
            if (rng.nextDouble() < 0.25) {
                embedded[i] = (byte) (embedded[i] ^ 1);
            }
        }
        double embeddedPi = SteganalysisEngine.spaEmbeddingRatio(embedded);
        assertTrue(embeddedPi > cleanPi,
                "SPA must rise after LSB replacement (" + cleanPi + " -> " + embeddedPi + ")");
    }

    @Test
    void threatScoreStaysWithinBounds() {
        SteganalysisEngine.Stats stats = SteganalysisEngine.analyze(SecureTestData.deterministicNoise(512));
        int clean = SteganalysisEngine.threatScore(stats, false);
        int flagged = SteganalysisEngine.threatScore(stats, true);
        assertTrue(clean >= 0 && clean <= 100);
        assertTrue(flagged > clean, "signature detection must push the threat score up");
    }
}
