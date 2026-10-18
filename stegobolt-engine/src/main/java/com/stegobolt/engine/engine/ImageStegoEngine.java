package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.BitIO;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;
import com.stegobolt.engine.crypto.CryptoEngine;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Image Steganography (PNG, BMP, WebP) — §4.2.
 *
 * <p>Secrets are embedded in the least significant bits of the R/G/B pixel color
 * channels via {@link BufferedImage} + {@link javax.imageio.ImageIO}, so the
 * visual appearance is unchanged. Every pixel is normalized to truecolor
 * (TYPE_INT_RGB) before embedding so palette-based covers (GIF, indexed PNG)
 * cannot quantize the payload away. Output is always re-encoded as lossless PNG.
 */
public final class ImageStegoEngine implements StegoEngine {

    private static final int CHANNELS = 3; // R, G, B

    @Override
    public Medium medium() {
        return Medium.IMAGE;
    }

    @Override
    public long capacityBits(byte[] cover) {
        BufferedImage img = decode(cover);
        return (long) img.getWidth() * img.getHeight() * CHANNELS;
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        BufferedImage img = decode(cover);
        long capacity = (long) img.getWidth() * img.getHeight() * CHANNELS;
        long neededBits = container.length * 8L;
        if (neededBits > capacity) {
            throw new StegoException("Payload too large for this image — capacity is "
                    + (capacity / 8) + " bytes, payload needs " + container.length + " bytes");
        }
        BitIO.write(container, 0, (index, bit) -> {
            long pixel = index / CHANNELS;
            int channel = (int) (index % CHANNELS);
            int x = (int) (pixel % img.getWidth());
            int y = (int) (pixel / img.getWidth());
            int rgb = img.getRGB(x, y);
            int shift = 16 - (channel * 8); // R=16, G=8, B=0
            rgb = (rgb & ~(1 << shift)) | (bit << shift); // clear LSB then set bit
            img.setRGB(x, y, rgb);
        });
        return encodePng(img);
    }

    @Override
    public byte[] extract(byte[] cover) {
        BufferedImage img = decode(cover);
        long bitsAvailable = (long) img.getWidth() * img.getHeight() * CHANNELS;
        if (bitsAvailable < Packet.HEADER * 8L) {
            return null;
        }
        byte[] header = BitIO.read(Packet.HEADER * 8L, 0, bitIndex -> lsbAt(img, bitIndex));
        if (!Packet.looksLikeHeader(header)) {
            return null;
        }
        int ctLen = BitIO.getInt(header, 8);
        long totalBits = (long) (Packet.HEADER + ctLen) * 8L;
        if (totalBits > bitsAvailable) {
            return null;
        }
        byte[] raw = BitIO.read(totalBits, 0, bitIndex -> lsbAt(img, bitIndex));
        return Packet.looksLike(raw) ? raw : null;
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        BufferedImage img = decode(cover);
        long changed = 0;
        long randomized = 0;
        java.security.SecureRandom rng = randomizeLsb ? CryptoEngine.newRng() : null;
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int before = rgb;
                for (int shift = 0; shift <= 16; shift += 8) {
                    int bit = rng != null ? rng.nextInt(2) : 0;
                    rgb = (rgb & ~(1 << shift)) | (bit << shift);
                }
                img.setRGB(x, y, rgb);
                changed += Integer.bitCount(before ^ rgb);
                randomized += CHANNELS;
            }
        }
        return new SanitizeOutcome(encodePng(img), changed, randomized);
    }

    /**
     * The embeddable sample stream for steganalysis: every R/G/B channel byte
     * of every pixel, in raster order. Caller wipes the result.
     */
    public static byte[] embeddableSamples(byte[] cover) {
        BufferedImage img = decode(cover);
        byte[] samples = new byte[img.getWidth() * img.getHeight() * CHANNELS];
        int i = 0;
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                samples[i++] = (byte) (rgb >>> 16);
                samples[i++] = (byte) (rgb >>> 8);
                samples[i++] = (byte) rgb;
            }
        }
        return samples;
    }

    /** PSNR (dB) between two decodes of the same geometry; higher = more imperceptible. */
    public static double psnr(byte[] original, byte[] stego) {
        BufferedImage a = decode(original);
        BufferedImage b = decode(stego);
        if (a.getWidth() != b.getWidth() || a.getHeight() != b.getHeight()) {
            return 0;
        }
        double mse = 0;
        long n = 0;
        for (int y = 0; y < a.getHeight(); y++) {
            for (int x = 0; x < a.getWidth(); x++) {
                int pa = a.getRGB(x, y);
                int pb = b.getRGB(x, y);
                for (int shift = 0; shift <= 16; shift += 8) {
                    int da = (pa >>> shift) & 0xFF;
                    int db = (pb >>> shift) & 0xFF;
                    double d = da - db;
                    mse += d * d;
                    n++;
                }
            }
        }
        if (n == 0 || mse == 0) {
            return 99.0; // identical
        }
        mse /= n;
        return 10.0 * Math.log10(255.0 * 255.0 / mse);
    }

    /* ------------------------------------------------------------------ */
    /* internals                                                          */
    /* ------------------------------------------------------------------ */

    private static int lsbAt(BufferedImage img, long bitIndex) {
        long pixel = bitIndex / CHANNELS;
        int channel = (int) (bitIndex % CHANNELS);
        int x = (int) (pixel % img.getWidth());
        int y = (int) (pixel / img.getWidth());
        int rgb = img.getRGB(x, y);
        return (rgb >>> (16 - channel * 8)) & 1;
    }

    private static BufferedImage decode(byte[] bytes) {
        BufferedImage raw;
        try {
            raw = ImageIO.read(new ByteArrayInputStream(bytes));
        } catch (IOException | RuntimeException e) {
            throw new StegoException("Image could not be decoded", e);
        }
        if (raw == null) {
            throw new StegoException("Image format not readable by ImageIO (use PNG, BMP, WebP, GIF or TIFF)");
        }
        // Decompression-bomb guard: crafted headers can declare absurd dimensions.
        if ((long) raw.getWidth() * raw.getHeight() > 64_000_000L) {
            throw new StegoException("Image exceeds the 64 megapixel processing ceiling");
        }
        // Normalize to truecolor so palette quantization can never destroy LSBs.
        if (raw.getType() == BufferedImage.TYPE_INT_RGB) {
            return raw;
        }
        BufferedImage rgb = new BufferedImage(raw.getWidth(), raw.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = rgb.createGraphics();
        try {
            g.drawImage(raw, 0, 0, null);
        } finally {
            g.dispose();
        }
        return rgb;
    }

    private static byte[] encodePng(BufferedImage img) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (!ImageIO.write(img, "png", out)) {
                throw new StegoException("PNG encoder unavailable");
            }
        } catch (IOException e) {
            throw new StegoException("Stego image encoding failed", e);
        }
        return out.toByteArray();
    }
}
