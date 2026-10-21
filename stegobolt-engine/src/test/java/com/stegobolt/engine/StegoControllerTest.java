package com.stegobolt.engine;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** End-to-end REST exercise: multipart in → binary/JSON out, zero-disk contract. */
@SpringBootTest
@AutoConfigureMockMvc
class StegoControllerTest {

    @Autowired
    private MockMvc mvc;

    private static byte[] png(int w, int h) throws Exception {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                img.setRGB(x, y, ((x * 13) & 0xFF) << 16 | ((y * 7) & 0xFF) << 8 | ((x + y) & 0xFF));
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }

    private static MockMultipartFile cover() throws Exception {
        return new MockMultipartFile("cover", "cover.png", "image/png", png(64, 64));
    }

    @Test
    void capacityReportsImageHeadroom() throws Exception {
        mvc.perform(multipart("/api/v1/stego/capacity").file(cover()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.medium").value("Image"))
                .andExpect(jsonPath("$.capacityBytes").isNumber());
    }

    @Test
    void hideThenExtractRoundTripsThroughTheRestApi() throws Exception {
        MvcResult hidden = mvc.perform(multipart("/api/v1/stego/hide")
                        .file(cover())
                        .param("payloadText", "attack at dawn")
                        .param("passphrase", "unit-test-pass"))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-StegoBolt-Report"))
                .andReturn();

        byte[] stego = hidden.getResponse().getContentAsByteArray();
        assertTrue(stego.length > 0);

        MockMultipartFile stegoPart = new MockMultipartFile("cover", "stego.png", "image/png", stego);
        mvc.perform(multipart("/api/v1/stego/extract")
                        .file(stegoPart)
                        .param("passphrase", "unit-test-pass"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.found").value(true))
                .andExpect(jsonPath("$.payloadText").value("attack at dawn"));
    }

    @Test
    void scanReturnsThreatAssessment() throws Exception {
        mvc.perform(multipart("/api/v1/stego/scan").file(cover()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.medium").value("Image"))
                .andExpect(jsonPath("$.threatScore").isNumber())
                .andExpect(jsonPath("$.indicators").isArray())
                .andExpect(jsonPath("$.sampleBased").value(true))
                .andExpect(jsonPath("$.containerSignatureFound").value(false))
                // A clean cover must never be reported as elevated or embedded.
                .andExpect(jsonPath("$.level").value("LOW"))
                .andExpect(jsonPath("$.verdict").value("CLEAN"))
                .andExpect(jsonPath("$.summary").value(Matchers.containsString("No StegoBolt container detected")))
                .andExpect(jsonPath("$.analysisBasis").isNotEmpty());
    }

    @Test
    void scanOfHiddenCarrierConfirmsTheContainer() throws Exception {
        MvcResult hidden = mvc.perform(multipart("/api/v1/stego/hide")
                        .file(cover())
                        .param("payloadText", "forensic payload")
                        .param("passphrase", "unit-test-pass"))
                .andExpect(status().isOk())
                .andReturn();

        MockMultipartFile stegoPart = new MockMultipartFile("cover", "stego.png", "image/png",
                hidden.getResponse().getContentAsByteArray());
        mvc.perform(multipart("/api/v1/stego/scan").file(stegoPart))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.containerSignatureFound").value(true))
                .andExpect(jsonPath("$.level").value("CRITICAL"))
                .andExpect(jsonPath("$.confidence").value("CONFIRMED"))
                .andExpect(jsonPath("$.verdict").value("CONFIRMED_CONTAINER"));
    }

    @Test
    void cleanStripsAndReturnsBinary() throws Exception {
        MvcResult cleaned = mvc.perform(multipart("/api/v1/stego/clean")
                        .file(cover())
                        .param("randomizeLsb", "true"))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-StegoBolt-Report"))
                .andReturn();
        assertTrue(cleaned.getResponse().getContentType().contains(MediaType.APPLICATION_OCTET_STREAM_VALUE));
        assertTrue(cleaned.getResponse().getContentAsByteArray().length > 0);
    }

    @Test
    void wrongPassphraseIsRejectedWithCleanError() throws Exception {
        MvcResult hidden = mvc.perform(multipart("/api/v1/stego/hide")
                        .file(cover())
                        .param("payloadText", "top secret")
                        .param("passphrase", "right"))
                .andExpect(status().isOk())
                .andReturn();

        MockMultipartFile stegoPart = new MockMultipartFile(
                "cover", "stego.png", "image/png", hidden.getResponse().getContentAsByteArray());
        mvc.perform(multipart("/api/v1/stego/extract")
                        .file(stegoPart)
                        .param("passphrase", "wrong"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("stego_error"));
    }

    @Test
    void payloadTooLargeIsRejectedBeforeProcessing() throws Exception {
        // 8x8 image = 192 bits of capacity — a 1 KiB payload cannot fit.
        MockMultipartFile tiny = new MockMultipartFile(
                "cover", "tiny.png", "image/png", png(8, 8));
        byte[] big = new byte[1024];
        mvc.perform(multipart("/api/v1/stego/hide")
                        .file(tiny)
                        .file(new MockMultipartFile("payload", "big.bin", MediaType.APPLICATION_OCTET_STREAM_VALUE, big))
                        .param("passphrase", "pw"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mediumIsDetectedFromContent() throws Exception {
        mvc.perform(multipart("/api/v1/stego/capacity").file(cover()))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals("Image",
                        result.getResponse().getContentAsString().contains("\"medium\":\"Image\"")
                                ? "Image" : "other"));
    }
}
