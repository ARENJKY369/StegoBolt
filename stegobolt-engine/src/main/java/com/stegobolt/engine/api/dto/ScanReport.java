package com.stegobolt.engine.api.dto;

import java.util.List;

/** POST /scan — forensic steganalysis report. */
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
        List<String> exifTags) {
}
