package com.stegobolt.engine.api.dto;

/** POST /extract — recovered payload (text form when UTF-8 decodable, plus base64). */
public record ExtractReport(
        String medium,
        boolean found,
        String payloadText,
        String payloadBase64,
        long payloadBytes,
        String sha256) {
}
