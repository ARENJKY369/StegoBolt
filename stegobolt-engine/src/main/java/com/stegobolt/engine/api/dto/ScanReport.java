package com.stegobolt.engine.api.dto;

import java.util.List;

/**
 * POST /scan — forensic steganalysis report.
 *
 * <p>The numeric detectors are reported verbatim so an operator can audit them,
 * but the user-facing classification lives in {@code level}, {@code confidence},
 * {@code summary} and {@code verdict}:
 * <ul>
 *   <li>{@code CONFIRMED_CONTAINER} — a validated SBV2-J container was extracted;</li>
 *   <li>{@code DAMAGED_CONTAINER} — SBV2-J framing present but unreadable;</li>
 *   <li>{@code STRONG_STATISTICAL_SUSPICION} — two independent detectors agree,
 *       no container signature;</li>
 *   <li>{@code INCONCLUSIVE} — weak/single-detector or structural-only evidence;</li>
 *   <li>{@code CLEAN} — no container, no meaningful statistical anomaly.</li>
 * </ul>
 *
 * <p>{@code sampleBased} is {@code false} for media where LSB-plane statistics
 * are not applicable (documents, text/code, FLAC padding, MP4/MKV padding,
 * PCAP header bits); {@code chiSquareProbability}, {@code spaEmbeddingRatio},
 * {@code lsbOnesRatio} and {@code lsbEntropy} must then be ignored.
 */
public record ScanReport(
        String medium,
        long carrierBytes,
        double chiSquareStatistic,
        double chiSquareProbability,
        double spaEmbeddingRatio,
        double lsbOnesRatio,
        double lsbEntropy,
        double windowedEntropy,
        boolean containerSignatureFound,
        int threatScore,
        List<String> indicators,
        List<String> exifTags,
        String level,
        String confidence,
        String summary,
        String analysisBasis,
        boolean sampleBased,
        long sampleSize,
        String verdict) {
}
