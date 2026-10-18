package com.stegobolt.engine.engine;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TextStegoEngineTest {

    @Test
    void zeroWidthRoundTripsThroughVisibleText() {
        TextStegoEngine engine = new TextStegoEngine(TextStegoEngine.MODE_ZERO_WIDTH);
        String cover = "Hello, world!\nThis is a plain letter.\n";
        byte[] container = TestPackets.container(TestPackets.body(24));

        byte[] stego = engine.hide(cover.getBytes(StandardCharsets.UTF_8), container);
        byte[] extracted = engine.extract(stego);
        assertNotNull(extracted);
        assertArrayEquals(container, extracted);

        // The visible text is unchanged once the zero-width stream is dropped.
        String stegoText = new String(stego, StandardCharsets.UTF_8);
        assertTrue(stegoText.startsWith(cover));
    }

    @Test
    void trailingWhitespaceRoundTrips() {
        TextStegoEngine engine = new TextStegoEngine(TextStegoEngine.MODE_TRAILING_WS);
        StringBuilder cover = new StringBuilder();
        for (int i = 0; i < 600; i++) {
            cover.append("line ").append(i).append('\n');
        }
        byte[] container = TestPackets.container(TestPackets.body(20));

        byte[] stego = engine.hide(cover.toString().getBytes(StandardCharsets.UTF_8), container);
        byte[] extracted = engine.extract(stego);
        assertNotNull(extracted);
        assertArrayEquals(container, extracted);
    }

    @Test
    void cleanRemovesEveryZeroWidthCharacter() {
        TextStegoEngine engine = new TextStegoEngine();
        String cover = "visible";
        byte[] container = TestPackets.container(TestPackets.body(4));
        byte[] stego = engine.hide(cover.getBytes(StandardCharsets.UTF_8), container);
        assertTrue(new String(stego, StandardCharsets.UTF_8).length() > cover.length());

        StegoEngine.SanitizeOutcome outcome = engine.sanitize(stego, false);
        String cleaned = new String(outcome.cleaned(), StandardCharsets.UTF_8);
        assertTrue(cleaned.contains("visible"));
        assertNull(engine.extract(outcome.cleaned()));
    }

    @Test
    void extractReturnsNullOnCleanText() {
        TextStegoEngine engine = new TextStegoEngine();
        assertNull(engine.extract("nothing hidden here".getBytes(StandardCharsets.UTF_8)));
    }
}
