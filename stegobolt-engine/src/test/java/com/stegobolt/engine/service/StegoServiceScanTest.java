package com.stegobolt.engine.service;

import com.stegobolt.engine.api.dto.ScanReport;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StegoServiceScanTest {

    private static byte[] coverPng() throws Exception {
        BufferedImage image = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                image.setRGB(x, y, ((x * 13) & 0xFF) << 16 | ((y * 7) & 0xFF) << 8 | ((x + y) & 0xFF));
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    @Test
    void scanKeepsCleanImageLowAndConfirmsEmbeddedImage() throws Exception {
        StegoService service = new StegoService();
        byte[] clean = coverPng();

        StegoService.WorkResult cleanWork = service.scan(clean, "clean.png", null);
        ScanReport cleanReport = cleanWork.report();
        assertFalse(cleanReport.containerSignatureFound());
        assertTrue(cleanReport.threatScore() < 25);
        cleanWork.close();

        StegoService.WorkResult hideWork = service.hide(
                coverPng(), "hidden message".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "unit-test-pass".toCharArray(), "cover.png", null);
        byte[] stego = hideWork.out().clone();
        hideWork.close();

        StegoService.WorkResult scanWork = service.scan(stego, "stego.png", null);
        ScanReport stegoReport = scanWork.report();
        assertTrue(stegoReport.containerSignatureFound());
        assertTrue(stegoReport.threatScore() >= 42);
        scanWork.close();
    }
}
