package com.stegobolt.engine.analysis;

/**
 * Forensic Steganalysis &amp; Math — pure Java, hand-rolled loops (§4.4).
 *
 * <ul>
 *   <li><b>Chi-Square (Westfeld value-pair attack)</b> — sequential LSB embedding
 *       equalizes the populations of value pairs (2i, 2i+1); the resulting
 *       statistic is mapped through the chi-square survival function.</li>
 *   <li><b>Sample Pair Analysis (SPA)</b> — Dumitrescu-style pair-category
 *       estimator: adjacent sample pairs with |x−y| = 1 are split into
 *       type&nbsp;A (smaller value even) and type&nbsp;B (smaller value odd).
 *       LSB replacement erodes type&nbsp;A into identical pairs and scatters
 *       type&nbsp;B into unrelated pairs, so the ratio r = A/B yields the
 *       embedding rate π = 2s/(1+s), s = √max(0, r−1).</li>
 *   <li><b>LSB noise/entropy</b> — ones-ratio of the LSB plane, its binary
 *       entropy, and windowed Shannon entropy of the sample stream.</li>
 * </ul>
 *
 * <p>All routines operate on the embeddable sample stream of a carrier
 * (pixel channel bytes, PCM sample bytes, …) and never log or retain data.
 */
public final class SteganalysisEngine {

    private SteganalysisEngine() {
    }

    /** Snapshot of every detector over one sample stream. */
    public record Stats(
            double chiSquareStatistic,
            double chiSquareProbability,
            double spaEmbeddingRatio,
            double lsbOnesRatio,
            double lsbEntropy,
            double windowedEntropy) {
    }

    /** Run all detectors over {@code samples} (one embeddable unit per byte). */
    public static Stats analyze(byte[] samples) {
        if (samples == null || samples.length < 16) {
            return new Stats(0, 0, 0, 0.5, 1, 1);
        }
        return new Stats(
                chiSquareStatistic(samples),
                chiSquareProbability(samples),
                spaEmbeddingRatio(samples),
                lsbOnesRatio(samples),
                lsbBinaryEntropy(samples),
                windowedShannonEntropy(samples));
    }

    /* ------------------------------------------------------------------ */
    /* Chi-square value-pair attack (Westfeld)                             */
    /* ------------------------------------------------------------------ */

    /** Σ (n_2i − n'_i)² / n'_i over the 128 value pairs, n'_i = (n_2i + n_2i+1)/2. */
    public static double chiSquareStatistic(byte[] samples) {
        long[] freq = histogram(samples);
        double chi = 0;
        for (int i = 0; i < 128; i++) {
            double n0 = freq[2 * i];
            double n1 = freq[2 * i + 1];
            double expected = (n0 + n1) / 2.0;
            if (expected > 0) {
                double d = n0 - expected;
                chi += d * d / expected;
            }
        }
        return chi;
    }

    /**
     * Survival function of the chi-square distribution with 127 degrees of
     * freedom — the probability that a clean cover produces a statistic this
     * large. Values near 1.0 mean the value pairs are suspiciously equalized
     * (sequential LSB embedding), values near 0.5 look natural.
     */
    public static double chiSquareProbability(byte[] samples) {
        double chi = chiSquareStatistic(samples);
        return 1.0 - regularizedGammaP(127.0 / 2.0, chi / 2.0);
    }

    /** Regularized lower incomplete gamma P(a, x) — series + continued fraction. */
    static double regularizedGammaP(double a, double x) {
        if (x < 0 || a <= 0) {
            return 0;
        }
        if (x == 0) {
            return 0;
        }
        if (x < a + 1.0) {
            // series representation
            double sum = 1.0 / a;
            double term = sum;
            for (int n = 1; n < 500; n++) {
                term *= x / (a + n);
                sum += term;
                if (Math.abs(term) < Math.abs(sum) * 1e-12) {
                    break;
                }
            }
            return sum * Math.exp(-x + a * Math.log(x) - logGamma(a));
        }
        // continued fraction for Q, then P = 1 - Q
        double tiny = 1e-300;
        double b = x + 1.0 - a;
        double c = 1.0 / tiny;
        double d = 1.0 / b;
        double h = d;
        for (int i = 1; i < 500; i++) {
            double an = -i * (i - a);
            b += 2.0;
            d = an * d + b;
            if (Math.abs(d) < tiny) {
                d = tiny;
            }
            c = b + an / c;
            if (Math.abs(c) < tiny) {
                c = tiny;
            }
            d = 1.0 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1.0) < 1e-12) {
                break;
            }
        }
        double q = Math.exp(-x + a * Math.log(x) - logGamma(a)) * h;
        return 1.0 - q;
    }

    /** Lanczos approximation of ln Γ(z). */
    static double logGamma(double z) {
        double[] g = {
                676.5203681218851, -1259.1392167224028, 771.32342877765313,
                -176.61502916214059, 12.507343278686905, -0.13857109526572012,
                9.9843695780195716e-6, 1.5056327351493116e-7
        };
        if (z < 0.5) {
            return Math.log(Math.PI / Math.sin(Math.PI * z)) - logGamma(1.0 - z);
        }
        z -= 1.0;
        double x = 0.99999999999980993;
        for (int i = 0; i < g.length; i++) {
            x += g[i] / (z + i + 1);
        }
        double t = z + g.length - 0.5;
        return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
    }

    /* ------------------------------------------------------------------ */
    /* Sample Pair Analysis (SPA)                                          */
    /* ------------------------------------------------------------------ */

    /**
     * Dumitrescu-style embedding-rate estimate over disjoint adjacent pairs.
     * Returns π ∈ [0, 1]; ~0 for natural covers, near 1 for fully embedded ones.
     */
    public static double spaEmbeddingRatio(byte[] samples) {
        long typeA = 0; // poised pair (x, x+1), smaller value even
        long typeB = 0; // poised pair (x, x+1), smaller value odd
        for (int i = 0; i + 1 < samples.length; i += 2) {
            int a = samples[i] & 0xFF;
            int b = samples[i + 1] & 0xFF;
            int lo = Math.min(a, b);
            int hi = Math.max(a, b);
            if (hi - lo == 1) {
                if ((lo & 1) == 0) {
                    typeA++;
                } else {
                    typeB++;
                }
            }
        }
        if (typeB == 0 || typeA + typeB < 8) {
            return 0;
        }
        double r = (double) typeA / (double) typeB;
        double s = Math.sqrt(Math.max(0, r - 1.0));
        double pi = 2.0 * s / (1.0 + s);
        return Math.min(1.0, Math.max(0.0, pi));
    }

    /* ------------------------------------------------------------------ */
    /* LSB noise & entropy                                                 */
    /* ------------------------------------------------------------------ */

    /** Fraction of LSBs that are 1 — natural covers hover near 0.5 with drift. */
    public static double lsbOnesRatio(byte[] samples) {
        long ones = 0;
        for (byte b : samples) {
            ones += b & 1;
        }
        return samples.length == 0 ? 0.5 : (double) ones / samples.length;
    }

    /** Binary Shannon entropy (bits) of the LSB plane — 1.0 = pure noise. */
    public static double lsbBinaryEntropy(byte[] samples) {
        double p = lsbOnesRatio(samples);
        if (p <= 0 || p >= 1) {
            return 0;
        }
        return -p * Math.log(p) / Math.log(2) - (1 - p) * Math.log(1 - p) / Math.log(2);
    }

    /** Mean Shannon entropy over 256-byte windows of the sample stream. */
    public static double windowedShannonEntropy(byte[] samples) {
        int window = 256;
        if (samples.length < window) {
            return shannon(samples, 0, samples.length);
        }
        double total = 0;
        int windows = 0;
        for (int start = 0; start + window <= samples.length; start += window) {
            total += shannon(samples, start, window);
            windows++;
        }
        return windows == 0 ? 0 : total / windows;
    }

    private static double shannon(byte[] samples, int from, int len) {
        long[] freq = new long[256];
        for (int i = from; i < from + len; i++) {
            freq[samples[i] & 0xFF]++;
        }
        double entropy = 0;
        for (long f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }
        return entropy;
    }

    private static long[] histogram(byte[] samples) {
        long[] freq = new long[256];
        for (byte b : samples) {
            freq[b & 0xFF]++;
        }
        return freq;
    }

    /**
     * Threat Assessment Score (0-100): blended evidence from the value-pair
     * attack, SPA ratio, LSB balance drift and container-signature detection.
     */
    public static int threatScore(Stats stats, boolean signatureFound) {
        double score = 0;
        score += stats.chiSquareProbability() * 35;      // equalized pairs
        score += stats.spaEmbeddingRatio() * 30;          // pair-category drift
        score += Math.min(1.0, Math.abs(0.5 - stats.lsbOnesRatio()) * 4) * 10;
        score += (1.0 - Math.min(1.0, stats.windowedEntropy() / 4.0)) * 5;
        if (signatureFound) {
            score += 40;                                  // SBV2-J signature hunt hit
        }
        return (int) Math.round(Math.min(100, Math.max(0, score)));
    }
}
