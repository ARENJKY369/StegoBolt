package com.stegobolt.engine.api.dto;

/**
 * Header-only report accompanying the binary /hide and /clean responses
 * (serialized to the {@code X-StegoBolt-Report} response header so the stego
 * media itself can stream as application/octet-stream).
 */
public record HideReport(
        String medium,
        String stegoFileName,
        long stegoBytes,
        long payloadBytes,
        long capacityUsedBits,
        Double psnrDb,
        String sha256) {
}
