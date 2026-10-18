package com.stegobolt.engine.api;

import com.stegobolt.engine.api.dto.CleanReport;
import com.stegobolt.engine.api.dto.ExtractReport;
import com.stegobolt.engine.api.dto.HideReport;
import com.stegobolt.engine.api.dto.ScanReport;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.service.StegoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * REST Controller Layer (§4.1) — pure Spring Boot {@code @RestController}
 * handling {@code multipart/form-data} across {@code /hide}, {@code /extract},
 * {@code /scan}, {@code /clean} and {@code /capacity} under
 * {@code /api/v1/stego}.
 *
 * <p><b>Zero-disk:</b> uploads arrive in RAM (multipart threshold = 2 GiB, see
 * application.properties) and responses stream straight out of byte arrays.
 *
 * <p><b>Volatile RAM purging:</b> for binary responses ({@code /hide},
 * {@code /clean}) the {@link StreamingResponseBody} lambda writes the stego
 * bytes and then closes the {@link StegoService.WorkResult} in {@code finally},
 * which zero-wipes every media/payload buffer. For JSON endpoints the wipe runs
 * in the handler's own {@code finally}.
 *
 * <p><b>Zero payload logging:</b> the logger below only ever reports operation,
 * medium and byte counts — never payload contents, passphrases or matrices.
 */
@RestController
@RequestMapping("/api/v1/stego")
public class StegoController {

    private static final Logger log = LoggerFactory.getLogger(StegoController.class);

    private final StegoService service;
    private final ObjectMapper mapper;

    public StegoController(StegoService service, ObjectMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    /* ---------------------------------------------------------------- */
    /* /hide — encrypt + embed, return stego media                       */
    /* ---------------------------------------------------------------- */

    @PostMapping(value = "/hide", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<StreamingResponseBody> hide(
            @RequestPart("cover") org.springframework.web.multipart.MultipartFile cover,
            @RequestPart(value = "payload", required = false) org.springframework.web.multipart.MultipartFile payload,
            @RequestParam(value = "payloadText", required = false) String payloadText,
            @RequestParam("passphrase") String passphrase,
            @RequestParam(value = "textMode", required = false) String textMode) throws IOException {

        byte[] coverBytes = cover.getBytes();
        byte[] payloadBytes = payload != null
                ? payload.getBytes()
                : (payloadText != null ? payloadText.getBytes(StandardCharsets.UTF_8) : null);
        char[] pass = passphrase == null ? new char[0] : passphrase.toCharArray();

        StegoService.WorkResult work;
        try {
            work = service.hide(coverBytes, payloadBytes, pass, cover.getOriginalFilename(), textMode);
        } catch (RuntimeException e) {
            MemoryHygiene.wipe(coverBytes, payloadBytes);
            MemoryHygiene.wipe(pass);
            throw e;
        }
        MemoryHygiene.wipe(pass);
        HideReport hideReport = work.report();
        log.info("hide ok — medium={}, stegoBytes={}, payloadBytes={}",
                hideReport.medium(), work.out().length,
                payloadBytes == null ? 0 : payloadBytes.length);

        try {
            String reportJson = mapper.writeValueAsString(work.report());
            StegoService.WorkResult owned = work;
            StreamingResponseBody body = out -> {
                try {
                    out.write(owned.out());
                    out.flush();
                } finally {
                    // volatile RAM purge immediately after the response stream
                    owned.close();
                }
            };
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            ContentDisposition.attachment().filename(work.fileName(), StandardCharsets.UTF_8).build().toString())
                    .header("X-StegoBolt-Report", asciiSafe(reportJson))
                    .body(body);
        } catch (IOException e) {
            work.close();
            throw e;
        }
    }

    /* ---------------------------------------------------------------- */
    /* /extract — recover + decrypt payload                              */
    /* ---------------------------------------------------------------- */

    @PostMapping("/extract")
    public ResponseEntity<ExtractReport> extract(
            @RequestPart("cover") org.springframework.web.multipart.MultipartFile cover,
            @RequestParam("passphrase") String passphrase,
            @RequestParam(value = "textMode", required = false) String textMode) throws IOException {

        byte[] coverBytes = cover.getBytes();
        char[] pass = passphrase == null ? new char[0] : passphrase.toCharArray();
        StegoService.WorkResult work;
        try {
            work = service.extract(coverBytes, pass, cover.getOriginalFilename(), textMode);
        } catch (RuntimeException e) {
            MemoryHygiene.wipe(coverBytes);
            MemoryHygiene.wipe(pass);
            throw e;
        } finally {
            MemoryHygiene.wipe(pass);
        }
        try {
            ExtractReport report = work.report();
            log.info("extract ok — medium={}, found={}", report.medium(), report.found());
            return ResponseEntity.ok(report);
        } finally {
            work.close();
        }
    }

    /* ---------------------------------------------------------------- */
    /* /scan — forensic steganalysis                                     */
    /* ---------------------------------------------------------------- */

    @PostMapping("/scan")
    public ResponseEntity<ScanReport> scan(
            @RequestPart("cover") org.springframework.web.multipart.MultipartFile cover,
            @RequestParam(value = "textMode", required = false) String textMode) throws IOException {

        byte[] coverBytes = cover.getBytes();
        StegoService.WorkResult work;
        try {
            work = service.scan(coverBytes, cover.getOriginalFilename(), textMode);
        } catch (RuntimeException e) {
            MemoryHygiene.wipe(coverBytes);
            throw e;
        }
        try {
            ScanReport report = work.report();
            log.info("scan ok — medium={}, threatScore={}", report.medium(), report.threatScore());
            return ResponseEntity.ok(report);
        } finally {
            work.close();
        }
    }

    /* ---------------------------------------------------------------- */
    /* /clean — strip metadata + re-noise LSB floor                      */
    /* ---------------------------------------------------------------- */

    @PostMapping(value = "/clean", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<StreamingResponseBody> clean(
            @RequestPart("cover") org.springframework.web.multipart.MultipartFile cover,
            @RequestParam(value = "randomizeLsb", defaultValue = "true") boolean randomizeLsb,
            @RequestParam(value = "textMode", required = false) String textMode) throws IOException {

        byte[] coverBytes = cover.getBytes();
        StegoService.WorkResult work;
        try {
            work = service.clean(coverBytes, randomizeLsb, cover.getOriginalFilename(), textMode);
        } catch (RuntimeException e) {
            MemoryHygiene.wipe(coverBytes);
            throw e;
        }
        CleanReport cleanReport = work.report();
        log.info("clean ok — medium={}, changedBits={}", cleanReport.medium(), cleanReport.changedBits());

        try {
            String reportJson = mapper.writeValueAsString(work.report());
            StegoService.WorkResult owned = work;
            StreamingResponseBody body = out -> {
                try {
                    out.write(owned.out());
                    out.flush();
                } finally {
                    owned.close();
                }
            };
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            ContentDisposition.attachment().filename(work.fileName(), StandardCharsets.UTF_8).build().toString())
                    .header("X-StegoBolt-Report", asciiSafe(reportJson))
                    .body(body);
        } catch (IOException e) {
            work.close();
            throw e;
        }
    }

    /* ---------------------------------------------------------------- */
    /* /capacity — carrier headroom report                               */
    /* ---------------------------------------------------------------- */

    @PostMapping("/capacity")
    public ResponseEntity<com.stegobolt.engine.api.dto.CapacityReport> capacity(
            @RequestPart("cover") org.springframework.web.multipart.MultipartFile cover,
            @RequestParam(value = "textMode", required = false) String textMode) throws IOException {

        byte[] coverBytes = cover.getBytes();
        StegoService.WorkResult work;
        try {
            work = service.capacity(coverBytes, cover.getOriginalFilename(), textMode);
        } catch (RuntimeException e) {
            MemoryHygiene.wipe(coverBytes);
            throw e;
        }
        try {
            com.stegobolt.engine.api.dto.CapacityReport report = work.report();
            log.info("capacity ok — medium={}, capacityBytes={}", report.medium(), report.capacityBytes());
            return ResponseEntity.ok(report);
        } finally {
            work.close();
        }
    }

    /* ---------------------------------------------------------------- */

    /** Header values must be ASCII — escape anything exotic in the JSON report. */
    private static String asciiSafe(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            sb.append(c < 0x80 ? c : '?');
        }
        return sb.toString();
    }
}
