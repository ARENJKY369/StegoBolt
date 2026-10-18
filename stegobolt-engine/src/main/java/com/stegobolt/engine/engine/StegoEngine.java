package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.Medium;

/**
 * Contract every medium engine implements: capacity probing, LSB/structural
 * embedding of an SBV2-J container, extraction, and sanitization. All methods
 * are pure in-memory transformations over {@code byte[]} payloads — no disk I/O.
 *
 * <p>Ownership rule: engines never wipe their input buffers (the caller owns
 * those) — they only wipe local copies they allocate internally.
 */
public interface StegoEngine {

    /** Result of {@link #sanitize}: the cleaned carrier plus diff statistics. */
    record SanitizeOutcome(byte[] cleaned, long changedBits, long reRandomizedBits) {
    }

    Medium medium();

    /** Maximum embeddable bits in this cover. */
    long capacityBits(byte[] cover);

    /** Embed {@code container} into {@code cover}; returns the stego carrier. */
    byte[] hide(byte[] cover, byte[] container);

    /**
     * Extract the embedded SBV2-J container bytes, or {@code null} when the
     * carrier holds no recognizable container.
     */
    byte[] extract(byte[] cover);

    /**
     * Sanitize the carrier: neutralize hidden containers and (optionally)
     * re-randomize the LSB noise floor with CSPRNG bits.
     */
    SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb);
}
