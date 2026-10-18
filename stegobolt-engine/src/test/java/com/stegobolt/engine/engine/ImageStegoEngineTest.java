package com.stegobolt.engine.engine;

import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImageStegoEngineTest {

    private static byte[] coverPng(int w, int h) throws Exception {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int r = (x * 7) & 0xFF;
                int g = (y * 11) & 0xFF;
                int b = (x + y) & 0xFF;
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }

    @Test
    void hideExtractRoundTrip() throws Exception {
        ImageStegoEngine engine = new ImageStegoEngine();
        byte[] cover = coverPng(64, 64);
        byte[] container = TestPackets.container(TestPackets.body(100));

        byte[] stego = engine.hide(cover, container);
        byte[] extracted = engine.extract(stego);
        assertNotNull(extracted);
        assertArrayEquals(container, extracted);
    }

    @Test
    void stegoImageIsDecodableAndVisuallyNearIdentical() throws Exception {
        ImageStegoEngine engine = new ImageStegoEngine();
        byte[] cover = coverPng(48, 48);
        byte[] container = TestPackets.container(TestPackets.body(50));

        byte[] stego = engine.hide(cover, container);
        BufferedImage decoded = ImageIO.read(new ByteArrayInputStream(stego));
        assertNotNull(decoded);
        assertTrue(ImageStegoEngine.psnr(cover, stego) > 40.0, "LSB embedding must stay imperceptible");
    }

    @Test
    void extractReturnsNullOnCleanImage() throws Exception {
        ImageStegoEngine engine = new ImageStegoEngine();
        assertNull(engine.extract(coverPng(32, 32)));
    }

    @Test
    void oversizePayloadIsRejected() throws Exception {
        ImageStegoEngine engine = new ImageStegoEngine();
        byte[] cover = coverPng(8, 8); // 8*8*3 = 192 bits = 24 bytes max
        byte[] container = TestPackets.container(TestPackets.body(64));
        assertThrows(RuntimeException.class, () -> engine.hide(cover, container));
    }

    @Test
    void sanitizeNeutralizesTheLsbLayer() throws Exception {
        ImageStegoEngine engine = new ImageStegoEngine();
        byte[] cover = coverPng(32, 32);
        byte[] container = TestPackets.container(TestPackets.body(30));
        byte[] stego = engine.hide(cover, container);

        StegoEngine.SanitizeOutcome outcome = engine.sanitize(stego, true);
        assertNull(engine.extract(outcome.cleaned()));
        assertTrue(outcome.reRandomizedBits() > 0);
    }
}
