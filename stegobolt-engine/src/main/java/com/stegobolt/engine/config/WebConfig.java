package com.stegobolt.engine.config;

import com.stegobolt.engine.service.StegoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web-layer configuration: CORS for the Next.js client layer, and the
 * StegoService bean wiring. No view resolvers, no persistence, no temp dirs.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /** The Next.js UI delegates to http://localhost:8080/api/v1/stego. */
    private static final String[] ALLOWED_ORIGINS = {
            "http://localhost:3000",
            "http://127.0.0.1:3000"
    };

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(ALLOWED_ORIGINS)
                .allowedMethods("POST", "OPTIONS")
                .allowedHeaders("*")
                .exposedHeaders("X-StegoBolt-Report", "Content-Disposition")
                .maxAge(3600);
    }

    @Bean
    public StegoService stegoService() {
        return new StegoService();
    }
}
