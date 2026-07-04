package com.example.nexus.config;

import com.example.nexus.common.web.CorrelationIdFilter;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.infrastructure.web.JwtAuthenticationFilter;
import com.example.nexus.identity.infrastructure.web.LoginRateLimitFilter;
import java.util.List;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Security baseline: stateless JWT bearer tokens, default-deny, no sessions, no HTTP Basic.
 *
 * <p>Filter chain order (innermost first):
 * <ol>
 *   <li>{@link LoginRateLimitFilter} — IP / email-HMAC rate limiting for login and refresh.
 *   <li>{@link JwtAuthenticationFilter} — validates the {@code Authorization: Bearer} header.
 *   <li>Spring Security built-ins (csrf=disabled, session=STATELESS, default-deny).
 * </ol>
 *
 * <p>Both custom filters are registered as {@code @Bean}s with
 * {@link FilterRegistrationBean#setEnabled(boolean) setEnabled(false)} to prevent Spring Boot
 * from also registering them as standalone servlet filters outside the security chain.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final String frontendBaseUrl;

  public SecurityConfig(@Value("${nexus.frontend.base-url}") String frontendBaseUrl) {
    this.frontendBaseUrl = frontendBaseUrl;
  }

  /**
   * Builds the security filter chain: stateless JWT bearer tokens, default-deny authorization,
   * HSTS, and custom filters for JWT validation and rate limiting.
   *
   * @param http              Spring Security's {@link HttpSecurity} for configuration
   * @param jwtFilter         validates the {@code Authorization: Bearer} header
   * @param rateLimitFilter   enforces rate limits on login and refresh endpoints
   * @return the configured {@link SecurityFilterChain}
   */
  @Bean
  SecurityFilterChain apiSecurity(
      HttpSecurity http,
      JwtAuthenticationFilter jwtFilter,
      LoginRateLimitFilter rateLimitFilter) {
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
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(rateLimitFilter, JwtAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(
                "/actuator/health/**", "/actuator/info",
                "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
                "/api/v1/auth/register", "/api/v1/auth/verify-email",
                "/api/v1/auth/resend-verification",
                "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
                "/api/v1/auth/password/forgot", "/api/v1/auth/password/reset",
                "/.well-known/jwks.json").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(e -> e
            .authenticationEntryPoint(jwtAuthenticationEntryPoint())
            .accessDeniedHandler(accessDeniedHandler()));
    return http.build();
  }

  /**
   * Builds an authentication entry point that returns 401 RFC 7807 problem documents.
   * No redirect, no {@code WWW-Authenticate: Basic} challenge.
   *
   * @return an {@link AuthenticationEntryPoint} that writes JSON problem responses on 401
   */
  @Bean
  AuthenticationEntryPoint jwtAuthenticationEntryPoint() {
    return (request, response, authException) -> {
      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType("application/problem+json");
      String traceId = MDC.get(CorrelationIdFilter.MDC_KEY);
      String json = "{\"status\":401,\"title\":\"Unauthorized\",\"code\":\"AUTH_003\""
          + ",\"traceId\":\"" + (traceId != null ? traceId : "") + "\"}";
      response.getWriter().write(json);
    };
  }

  /**
   * Builds an access-denied handler that returns 403 RFC 7807 problem documents.
   *
   * @return an {@link AccessDeniedHandler} that writes JSON problem responses on 403
   */
  @Bean
  AccessDeniedHandler accessDeniedHandler() {
    return (request, response, accessDeniedException) -> {
      response.setStatus(HttpStatus.FORBIDDEN.value());
      response.setContentType("application/problem+json");
      String traceId = MDC.get(CorrelationIdFilter.MDC_KEY);
      String json = "{\"status\":403,\"title\":\"Forbidden\",\"code\":\"ACCESS_DENIED\""
          + ",\"traceId\":\"" + (traceId != null ? traceId : "") + "\"}";
      response.getWriter().write(json);
    };
  }

  /**
   * Instantiates the JWT authentication filter with the authentication entry point.
   *
   * @param jwtPort the JWT validation port
   * @return a configured {@link JwtAuthenticationFilter}
   */
  @Bean
  JwtAuthenticationFilter jwtAuthenticationFilter(JwtPort jwtPort) {
    return new JwtAuthenticationFilter(jwtPort, jwtAuthenticationEntryPoint());
  }

  /**
   * Registers the JWT filter with Spring Boot disabled to prevent duplicate servlet filter registration.
   * The filter is registered manually in the {@link SecurityFilterChain}.
   *
   * @param filter the JWT authentication filter
   * @return a disabled filter registration bean
   */
  @Bean
  FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(
      JwtAuthenticationFilter filter) {
    FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>(filter);
    reg.setEnabled(false);
    return reg;
  }

  /**
   * Registers the login rate-limit filter with Spring Boot disabled to prevent duplicate servlet filter registration.
   * The filter is registered manually in the {@link SecurityFilterChain}.
   *
   * @param filter the login rate-limit filter
   * @return a disabled filter registration bean
   */
  @Bean
  FilterRegistrationBean<LoginRateLimitFilter> loginRateLimitFilterRegistration(
      LoginRateLimitFilter filter) {
    FilterRegistrationBean<LoginRateLimitFilter> reg = new FilterRegistrationBean<>(filter);
    reg.setEnabled(false);
    return reg;
  }

  /**
   * Builds the CORS configuration restricting origins to the configured frontend base URL.
   * {@code Set-Cookie} is intentionally not exposed: the refresh token is HttpOnly and applied automatically.
   *
   * @return a {@link CorsConfigurationSource} configured for the frontend and well-known endpoints
   */
  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(List.of(frontendBaseUrl));
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    cfg.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Correlation-Id"));
    // Expose only headers the browser JS legitimately reads. Set-Cookie is intentionally NOT
    // exposed: the refresh cookie is HttpOnly (never script-readable) and the browser applies it
    // automatically, so exposing it grants nothing while widening the CORS surface.
    cfg.setExposedHeaders(List.of("Retry-After", "X-Correlation-Id"));
    cfg.setAllowCredentials(true);
    cfg.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", cfg);
    source.registerCorsConfiguration("/.well-known/**", cfg);
    return source;
  }
}
