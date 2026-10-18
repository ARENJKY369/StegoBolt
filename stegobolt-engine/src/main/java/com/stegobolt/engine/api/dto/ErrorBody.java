package com.stegobolt.engine.api.dto;

/** Uniform error body — safe to log, never carries payload data. */
public record ErrorBody(String error, String message) {
}
