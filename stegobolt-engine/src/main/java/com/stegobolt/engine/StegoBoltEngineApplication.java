package com.stegobolt.engine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * StegoBolt Engine v2.0 — production-grade, zero-knowledge steganography backend.
 *
 * <p>Architecture contract (enforced throughout the code base):
 * <ul>
 *   <li><b>100% Java</b> — Spring Boot 3.x on Java 17. No Node.js, no Python, no
 *       serverless TypeScript routes. The Next.js UI is a pure client that may
 *       delegate to {@code http://localhost:8080/api/v1/stego}.</li>
 *   <li><b>Zero-disk / zero-knowledge</b> — uploaded covers, generated stego media
 *       and decrypted payloads are never written to disk, {@code /tmp} or a
 *       database. All processing executes in volatile RAM via
 *       {@link java.io.ByteArrayInputStream}/{@link java.io.ByteArrayOutputStream}.</li>
 *   <li><b>Volatile RAM purging</b> — every {@code byte[]} that touches media or
 *       payload data is overwritten with {@code Arrays.fill(buf, (byte) 0)} inside
 *       {@code finally} blocks (see {@link com.stegobolt.engine.core.MemoryHygiene}).</li>
 *   <li><b>Zero payload logging</b> — loggers report status, medium and byte counts
 *       only. Payload contents, passphrases and raw bit matrices are never logged.</li>
 * </ul>
 */
@SpringBootApplication
public class StegoBoltEngineApplication {

    public static void main(String[] args) {
        SpringApplication.run(StegoBoltEngineApplication.class, args);
    }
}
