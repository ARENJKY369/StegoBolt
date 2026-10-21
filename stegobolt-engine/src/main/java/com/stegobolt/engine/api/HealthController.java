package com.stegobolt.engine.api;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Small non-sensitive health page for local hosting checks and operators. */
@RestController
public final class HealthController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("<html><head><title>StegoBolt Engine</title></head>"
                + "<body><h1>StegoBolt Engine is running</h1>"
                + "<p>Java 17 in-memory engine · API v1 ready</p></body></html>");
    }
}
