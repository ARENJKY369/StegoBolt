package com.stegobolt.engine.exif;

import com.stegobolt.engine.core.StegoException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * EXIF metadata parsing for /scan and /clean (§4.4) via
 * {@code org.apache.commons.imaging}. Only tag *names* and printable values are
 * surfaced — never raw byte matrices (zero payload logging).
 */
public final class ExifSanitizer {

    private ExifSanitizer() {
    }

    /**
     * Enumerate EXIF/XMP/ICC tag lines found in {@code imageBytes}.
     * Returns an empty list when the format carries no parseable metadata.
     */
    public static List<String> listTags(byte[] imageBytes) {
        try {
            var metadata = org.apache.commons.imaging.Imaging.getMetadata(imageBytes);
            if (metadata == null) {
                return Collections.emptyList();
            }
            List<String> tags = new ArrayList<>();
            for (String line : metadata.toString().split("\\R")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    tags.add(trimmed);
                }
            }
            return tags;
        } catch (Exception e) {
            // Metadata parsing is best-effort — never fail the whole request for it.
            return Collections.emptyList();
        }
    }

    /**
     * Strip metadata by re-encoding the decoded image through ImageIO
     * (the Java equivalent of the browser's canvas re-encode). Non-image or
     * undecodable input is returned untouched with zero tags counted.
     */
    public static byte[] strip(byte[] imageBytes) {
        try {
            var img = javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(imageBytes));
            if (img == null) {
                throw new StegoException("Image could not be decoded for metadata stripping");
            }
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            if (!javax.imageio.ImageIO.write(img, "png", out)) {
                throw new StegoException("PNG encoder unavailable");
            }
            return out.toByteArray();
        } catch (java.io.IOException e) {
            throw new StegoException("Metadata stripping failed", e);
        }
    }
}
