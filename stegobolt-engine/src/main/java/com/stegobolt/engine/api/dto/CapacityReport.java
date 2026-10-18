package com.stegobolt.engine.api.dto;

/** POST /capacity — how much secret data a carrier can hold. */
public record CapacityReport(
        String medium,
        long carrierBytes,
        long capacityBits,
        long capacityBytes,
        long maxPayloadTextChars,
        String details) {
}
