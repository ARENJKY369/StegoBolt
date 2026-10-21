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

    /**
     * Local development plus the hosted preview/deployment origins supported by
     * the UI. CORS is not authentication; the engine still has no credentials
     * or persistent state to disclose.
     */
    private static final String[] ALLOWED_ORIGIN_PATTERNS = {
            "http://localhost:[*]",
            "http://127.0.0.1:[*]",
            "https://*.vercel.app",
            "https://*.e2b.app"
    };

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOriginPatterns(ALLOWED_ORIGIN_PATTERNS)
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
