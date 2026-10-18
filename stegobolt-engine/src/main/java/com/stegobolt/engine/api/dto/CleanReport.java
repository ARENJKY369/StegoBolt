package com.stegobolt.engine.api.dto;

/** Header report accompanying the binary /clean response. */
public record CleanReport(
        String medium,
        long originalBytes,
        long cleanedBytes,
        int exifTagsRemoved,
        long lsbBitsReRandomized,
        long changedBits,
        Double psnrDb) {
}
