package com.stegobolt.engine.analysis;

import com.stegobolt.engine.core.Packet;

/**
 * Forensic Steganalysis &amp; Math — pure Java, hand-rolled loops (§4.4).
 *
 * <p><b>Statistical semantics.</b> The chi-square value-pair test is a
 * <i>goodness-of-fit</i> test of the natural-cover hypothesis: sequential LSB
 * replacement pushes neighbouring value pairs (2i, 2i+1) towards equal
 * populations, while natural texture, gradients and JPEG quantisation keep them
 * uneven. Consequently
 * <ul>
 *   <li>the survival probability {@code p} rises with equalisation (embedding)
 *       and falls for ordinary photographs — a small {@code p} is <b>not</b>
 *       evidence of embedding,</li>
 *   <li>the test has one degree of freedom per adequately populated pair, so the
 *       statistic must be judged against its own {@code df} (a large sample can
 *       otherwise look "significant" for a negligible deviation),</li>
 *   <li>a single detector is never enough: {@link #assess} requires two
 *       independent detector families (value-pair equalisation and sample-pair
 *       analysis) before a verdict may rise above {@code LOW}, and</li>
 *   <li>only a validated SBV2-J container is reported as confirmed.</li>
 * </ul>
 *
 * <p>Runs of identical LSBs and the byte-stream entropy are context signals
 * only — payload ciphertext is pseudorandom, so "high entropy" is neither
 * necessary nor sufficient for embedding.
 *
 * <p>All routines operate on the embeddable sample stream of a carrier
 * (pixel channel bytes, PCM sample bytes, …) and never log or retain data.
 */
public final class SteganalysisEngine {

    /** Minimum population for a value pair to participate in the test. */
    private static final int PAIR_MIN_COUNT = 20;
    /** Minimum degrees of freedom for the equalisation statistic to be meaningful. */
    private static final int MIN_DF = 8;

    private SteganalysisEngine() {
    }

    /** Container-signature state, as established by the medium engine. */
    public enum SignatureState {
        /** No SBV2-J framing anywhere in the medium layer. */
        ABSENT,
        /** A complete, validated SBV2-J container was extracted. */
        CONFIRMED,
        /** SBV2-J magic is present but the header/body is inconsistent or truncated. */
        MALFORMED
    }

    public enum Level {
        LOW, ELEVATED, HIGH, CRITICAL
    }

    public enum Confidence {
        CONFIRMED, SUSPICIOUS, INCONCLUSIVE, CLEAN
    }

    /**
     * Calibrated verdict for one carrier.
     *
     * @param code machine-readable classification: {@code CONFIRMED_CONTAINER},
     *             {@code DAMAGED_CONTAINER}, {@code STRONG_STATISTICAL_SUSPICION},
     *             {@code INCONCLUSIVE} or {@code CLEAN}
     */
    public record Verdict(int score, Level level, Confidence confidence, String summary,
                          String basis, String code) {
    }

    /**
     * Snapshot of every detector over one sample stream.
     *
     * @param samples            number of analysed unit samples (bits for bit planes)
     * @param sampleBased        true when LSB-plane statistics are meaningful for
     *                           this medium (image pixels, PCM samples, AVI frames);
     *                           false for structural media (documents, text, FLAC,
     *                           MP4/MKV padding, PCAP header bits)
     * @param chiSquareProbability pair-equalisation survival probability (high =
     *                           equalised = embedding-like)
     * @param pairImbalanceEffect   mean |n_even − n_odd| / n over tested pairs
     * @param runAnomaly         share of LSB runs of length ≥ 5 (context only)
     */
    public record Stats(
            long samples,
            boolean sampleBased,
            double chiSquareStatistic,
            int degreesOfFreedom,
            double chiSquareProbability,
            double pairImbalanceEffect,
            double spaEmbeddingRatio,
            double lsbOnesRatio,
            double lsbEntropy,
            double windowedEntropy,
            double runAnomaly) {

        /** Statistics for media where LSB-plane tests do not apply. */
        public static Stats structural(long samples) {
            return new Stats(Math.max(0, samples), false, 0, 0, 1.0, 0, 0, 0.5, 1.0, 1.0, 0);
        }

        /** Structural stats that still carry a real bit-plane ones ratio (e.g. IPv4 ID LSBs). */
        public static Stats structural(long samples, double lsbOnesRatio) {
            return new Stats(Math.max(0, samples), false, 0, 0, 1.0, 0, 0,
                    clamp01(lsbOnesRatio), 1.0, 1.0, 0);
        }

        /**
         * Calibrated value-pair equalisation evidence (0..1). Uses the z-score of
         * the collapsed statistic above the χ²(df) equalisation floor, gated by
         * the sample size and the number of tested pairs.
         */
        public double chiEqualization() {
            if (!sampleBased || samples < 4096 || degreesOfFreedom < MIN_DF) {
                return 0;
            }
            double sigma = Math.sqrt(2.0 * degreesOfFreedom);
            double z = (chiSquareStatistic - degreesOfFreedom) / sigma;
            double raw = clamp01(1.0 - (z - 1.0) / 4.0);
            double sizeGate = clamp01(Math.sqrt(samples / 65536.0));
            double dfGate = clamp01((degreesOfFreedom - MIN_DF) / 24.0);
            return raw * sizeGate * dfGate;
        }

        /** Calibrated SPA evidence (0..1). */
        public double spaEvidence() {
            if (!sampleBased || samples < 4096) {
                return 0;
            }
            double sizeGate = clamp01(Math.sqrt(samples / 65536.0));
            return clamp01((spaEmbeddingRatio - 0.15) / 0.35) * sizeGate;
        }

        /** Closeness of the LSB ones ratio to 0.500 — supporting signal only. */
        public double balanceSupport() {
            return clamp01((0.06 - Math.abs(lsbOnesRatio - 0.5)) / 0.06);
        }

        /** LSB-plane randomness — supporting signal only. */
        public double randomnessSupport() {
            return clamp01((lsbEntropy - 0.9) / 0.1);
        }

        /** How much the sample size can support a confident statistical verdict. */
        public double sampleConfidence() {
            return sampleBased ? clamp01(Math.sqrt(samples / 32768.0)) : 0;
        }
    }

    /** Run all detectors over {@code samples} (one embeddable unit per byte). */
    public static Stats analyze(byte[] samples) {
        if (samples == null || samples.length < 16) {
            return new Stats(samples == null ? 0 : samples.length, true, 0, 0, 1.0, 0, 0, 0.5, 1.0, 1.0, 0);
        }
        double[] pairTest = pairTest(samples);
        double chi = pairTest[0];
        int df = (int) pairTest[1];
        double effect = pairTest[2];
        return new Stats(
                samples.length,
                true,
                chi,
                df,
                df == 0 ? 1.0 : survivalChiSquare(chi, df),
                effect,
                spaEmbeddingRatio(samples),
                lsbOnesRatio(samples),
                lsbBinaryEntropy(samples),
                windowedShannonEntropy(samples),
                runAnomaly(samples));
    }

    /* ------------------------------------------------------------------ */
    /* Chi-square value-pair attack (Westfeld)                             */
    /* ------------------------------------------------------------------ */

    /** Σ (n_2i − n_2i+1)² / (n_2i + n_2i+1) over the adequately populated pairs. */
    public static double chiSquareStatistic(byte[] samples) {
        return pairTest(samples)[0];
    }

    /** Degrees of freedom of the collapsed value-pair statistic. */
    public static int degreesOfFreedom(byte[] samples) {
        return (int) pairTest(samples)[1];
    }

    /** Mean relative pair imbalance — effect size of the value-pair test. */
    public static double pairImbalanceEffect(byte[] samples) {
        return pairTest(samples)[2];
    }

    /**
     * Survival function (upper tail) of the chi-square distribution with the
     * actual number of tested pairs as degrees of freedom. Rises towards 1 when
     * the value pairs are equalised (sequential LSB embedding); stays near 0 for
     * ordinary photographs whose pairs are unevenly populated.
     */
    public static double chiSquareProbability(byte[] samples) {
        double[] pairTest = pairTest(samples);
        int df = (int) pairTest[1];
        if (df == 0) {
            return 1.0;
        }
        return survivalChiSquare(pairTest[0], df);
    }

    /** Q(df/2, statistic/2) — regularized upper incomplete gamma. */
    private static double survivalChiSquare(double statistic, int df) {
        if (statistic <= 0) {
            return 1.0;
        }
        return clamp01(1.0 - regularizedGammaP(df / 2.0, statistic / 2.0));
    }

    /** @return {statistic, degreesOfFreedom, meanRelativeImbalance, testedSamples} */
    private static double[] pairTest(byte[] samples) {
        if (samples == null || samples.length < 16) {
            return new double[]{0, 0, 0, 0};
        }
        long[] freq = histogram(samples);
        double chi = 0;
        double absImbalance = 0;
        double tested = 0;
        int df = 0;
        for (int i = 0; i < 128; i++) {
            double n0 = freq[2 * i];
            double n1 = freq[2 * i + 1];
            double n = n0 + n1;
            if (n < PAIR_MIN_COUNT) {
                continue;
            }
            double d = n0 - n1;
            chi += (d * d) / n;
            absImbalance += Math.abs(d);
            tested += n;
            df++;
        }
        return new double[]{chi, df, tested > 0 ? absImbalance / tested : 0, tested};
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
     *
     * <p>The estimate is a detector, not proof: quantised or saturated media can
     * bias the pair categories, which is why {@link #assess} never lets SPA lift
     * a carrier above LOW without value-pair agreement.
     */
    public static double spaEmbeddingRatio(byte[] samples) {
        if (samples == null || samples.length < 512) {
            return 0;
        }
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
        if (typeB == 0 || typeA + typeB < 64) {
            return 0;
        }
        double r = (double) typeA / (double) typeB;
        double s = Math.sqrt(Math.max(0, r - 1.0));
        double pi = 2.0 * s / (1.0 + s);
        return Math.min(1.0, Math.max(0.0, pi));
    }

    /* ------------------------------------------------------------------ */
    /* LSB noise, runs & entropy (context signals)                         */
    /* ------------------------------------------------------------------ */

    /** Fraction of LSBs that are 1 — natural covers hover near 0.5 with drift. */
    public static double lsbOnesRatio(byte[] samples) {
        if (samples == null || samples.length == 0) {
            return 0.5;
        }
        long ones = 0;
        for (byte b : samples) {
            ones += b & 1;
        }
        return (double) ones / samples.length;
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
        if (samples == null || samples.length < window) {
            return samples == null || samples.length == 0 ? 0 : shannon(samples, 0, samples.length);
        }
        double total = 0;
        int windows = 0;
        for (int start = 0; start + window <= samples.length; start += window) {
            total += shannon(samples, start, window);
            windows++;
        }
        return windows == 0 ? 0 : total / windows;
    }

    /** Share of LSB runs that reach five identical bits (context only). */
    public static double runAnomaly(byte[] samples) {
        if (samples == null || samples.length == 0) {
            return 0;
        }
        long longRuns = 0;
        long runs = 0;
        int current = 0;
        int previous = -1;
        for (byte b : samples) {
            int bit = b & 1;
            if (bit == previous) {
                current++;
            } else {
                if (current >= 5) {
                    longRuns++;
                }
                if (current > 0) {
                    runs++;
                }
                current = 1;
                previous = bit;
            }
        }
        if (current >= 5) {
            longRuns++;
        }
        if (current > 0) {
            runs++;
        }
        return runs == 0 ? 0 : (double) longRuns / runs;
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

    /* ------------------------------------------------------------------ */
    /* Signature probes                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * Probe the LSB bit plane of {@code samples} for SBV2-J framing. Call only
     * after a full {@code extract()} returned {@code null}: a magic match then
     * means the framing exists but cannot be validated (damaged container).
     */
    public static SignatureState probeBitPlane(byte[] samples) {
        // In a bit-plane sample stream each sample contributes exactly one bit.
        if (samples == null || samples.length < Packet.HEADER * 8) {
            return SignatureState.ABSENT;
        }
        byte[] header = new byte[Packet.HEADER];
        for (int i = 0; i < Packet.HEADER * 8; i++) {
            int bit = samples[i] & 1;
            header[i / 8] |= (byte) (bit << (7 - (i % 8)));
        }
        return startsWithMagic(header) ? SignatureState.MALFORMED : SignatureState.ABSENT;
    }

    /**
     * Probe a structural medium (FLAC padding, MP4 free box, MKV Void element,
     * PDF stream, DOCX part) for the raw SB2J marker. Call only after
     * {@code extract()} returned {@code null}.
     */
    public static SignatureState probeStructuralBytes(byte[] raw) {
        if (raw == null || raw.length < Packet.MAGIC.length) {
            return SignatureState.ABSENT;
        }
        for (int i = 0; i + Packet.MAGIC.length <= raw.length; i++) {
            if (raw[i] != Packet.MAGIC[0]) {
                continue;
            }
            boolean match = true;
            for (int k = 1; k < Packet.MAGIC.length; k++) {
                if (raw[i + k] != Packet.MAGIC[k]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return SignatureState.MALFORMED;
            }
        }
        return SignatureState.ABSENT;
    }

    private static boolean startsWithMagic(byte[] raw) {
        if (raw.length < Packet.MAGIC.length) {
            return false;
        }
        for (int i = 0; i < Packet.MAGIC.length; i++) {
            if (raw[i] != Packet.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /* ------------------------------------------------------------------ */
    /* Verdict calibration                                                 */
    /* ------------------------------------------------------------------ */

    /** Threat Assessment Score (0-100) — kept for API compatibility. */
    public static int threatScore(Stats stats, boolean signatureFound) {
        return assess(stats, signatureFound ? SignatureState.CONFIRMED : SignatureState.ABSENT)
                .score();
    }

    /** Calibrated verdict with generic wording. */
    public static Verdict assess(Stats stats, SignatureState signature) {
        return assess(stats, signature, "carrier", "sample-stream statistics");
    }

    /**
     * Calibrated verdict for one carrier.
     *
     * <p>Rules (mirrored 1:1 by {@code lib/analysis.ts} so local and Java engine
     * scans agree):
     * <ul>
     *   <li>validated SBV2-J container → {@code CRITICAL} / {@code CONFIRMED};</li>
     *   <li>damaged SBV2-J framing → {@code HIGH} / {@code SUSPICIOUS};</li>
     *   <li>two independent detectors agreeing → {@code HIGH} / {@code SUSPICIOUS};</li>
     *   <li>partial or single-detector evidence → {@code ELEVATED} /
     *       {@code INCONCLUSIVE};</li>
     *   <li>everything else (including a single high detector) → {@code LOW}.</li>
     * </ul>
     *
     * @param basis      human-readable description of what was inspected
     * @param mediumNoun lower-case medium noun used in the summary ("image", "document", …)
     */
    public static Verdict assess(Stats stats, SignatureState signature, String mediumNoun, String basis) {
        if (signature == SignatureState.CONFIRMED) {
            return new Verdict(96, Level.CRITICAL, Confidence.CONFIRMED,
                    "Confirmed StegoBolt container detected: a valid SBV2-J container header is present in this carrier.",
                    basis, "CONFIRMED_CONTAINER");
        }
        if (signature == SignatureState.MALFORMED) {
            return new Verdict(68, Level.HIGH, Confidence.SUSPICIOUS,
                    "Damaged StegoBolt container framing detected: the SBV2-J signature is present but its header is inconsistent, "
                            + "so the payload cannot be read. Treat this carrier as modified and sanitize it before sharing.",
                    basis, "DAMAGED_CONTAINER");
        }
        if (!stats.sampleBased()) {
            return new Verdict(8, Level.LOW, Confidence.INCONCLUSIVE,
                    "No StegoBolt container detected in this " + mediumNoun
                            + " carrier; no medium-specific embedding layer or structural anomaly was found.",
                    basis, "CLEAN");
        }
        if (stats.samples() < 4096 || stats.sampleConfidence() < 0.25) {
            return new Verdict(12, Level.LOW, Confidence.INCONCLUSIVE,
                    "No StegoBolt container detected. The sample is too small for reliable statistics, "
                            + "so no direct evidence of an embedded message was found and none can be excluded.",
                    basis, "INCONCLUSIVE");
        }

        double eq = stats.chiEqualization();
        double spa = stats.spaEvidence();
        double weighted = 0.55 * eq + 0.45 * spa;
        // Two independent detector families: SPA and value-pair equalisation from
        // chi-square. Neither may raise the level alone — SPA must be strong and
        // chi-square must corroborate it, so a high chi-square probability can
        // never by itself produce ELEVATED or HIGH.
        double support = 0.5 * stats.balanceSupport() + 0.5 * stats.randomnessSupport();
        double adjusted = clamp01(weighted * stats.sampleConfidence());

        if (spa >= 0.6 && eq >= 0.45) {
            int score = (int) Math.round(Math.min(88, 50 + 40 * adjusted));
            return new Verdict(score, Level.HIGH, Confidence.SUSPICIOUS,
                    "No StegoBolt container signature was found, but two independent statistical detectors agree on "
                            + "an embedding-like layer. Treat this as strong statistical suspicion, not a confirmed message, "
                            + "and sanitize before sharing.",
                    basis, "STRONG_STATISTICAL_SUSPICION");
        }
        if (spa >= 0.6 && eq >= 0.3) {
            int score = (int) Math.round(Math.min(49, 25 + 22 * adjusted));
            return new Verdict(score, Level.ELEVATED, Confidence.INCONCLUSIVE,
                    "No StegoBolt container detected; statistical irregularities are inconclusive. "
                            + "No direct evidence of an embedded message.",
                    basis, "INCONCLUSIVE");
        }
        int score = (int) Math.round(Math.min(24, 6 + 16 * Math.max(weighted, 0.5 * support) * stats.sampleConfidence()));
        return new Verdict(score, Level.LOW, Confidence.CLEAN,
                "No StegoBolt container detected and no direct evidence of an embedded message. "
                        + "The statistics are consistent with an ordinary cover medium.",
                basis, "CLEAN");
    }

    private static double clamp01(double value) {
        return Math.max(0, Math.min(1, value));
    }
}
