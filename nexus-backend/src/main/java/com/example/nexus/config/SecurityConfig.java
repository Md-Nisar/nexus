package com.example.nexus.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Security baseline: stateless, default-deny. Every endpoint requires authentication unless
 * explicitly permitted below.
 *
 * <p>HTTP Basic is a placeholder until the auth bounded context introduces JWT bearer tokens
 * (see SECURITY.md → Authentication Roadmap). Swagger paths are permitted here but springdoc is
 * disabled entirely under the prod profile, so nothing is exposed in production.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final String frontendBaseUrl;

  public SecurityConfig(@Value("${nexus.frontend.base-url}") String frontendBaseUrl) {
    this.frontendBaseUrl = frontendBaseUrl;
  }

  @Bean
  SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        // Stateless token-based API with no session cookie — CSRF does not apply
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // SEC-1: explicit HSTS (Spring Security only sends this header over HTTPS by default)
        .headers(headers -> headers
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31_536_000)))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
            .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
            .requestMatchers(
                "/api/v1/auth/register",
                "/api/v1/auth/verify-email",
                "/api/v1/auth/resend-verification").permitAll()
            .anyRequest().authenticated())
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(List.of(frontendBaseUrl));
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    // Allow Content-Type, Authorization, and the correlation-id header the frontend attaches.
    cfg.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Correlation-Id"));
    // Expose Retry-After so the Angular HTTP client can read it on 429 responses.
    cfg.setExposedHeaders(List.of("Retry-After", "X-Correlation-Id"));
    cfg.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", cfg);
    return source;
  }
}
