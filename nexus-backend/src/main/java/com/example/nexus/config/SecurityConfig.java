package com.example.nexus.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

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

  @Bean
  SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    http
        // Stateless token-based API with no session cookie — CSRF does not apply
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
            .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
            .permitAll()
            .anyRequest().authenticated())
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }
}
