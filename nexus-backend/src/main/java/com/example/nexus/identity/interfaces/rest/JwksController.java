package com.example.nexus.identity.interfaces.rest;

import com.example.nexus.identity.application.port.out.JwkSetPort;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the RSA public key set at {@code /.well-known/jwks.json} (US-003).
 *
 * <p>Only public key material is included — no {@code d}, {@code p}, {@code q} or
 * other private components. Response is cached for 1 hour.
 */
@RestController
@ConditionalOnProperty(name = "feature.nexus-us003-auth-login.enabled", havingValue = "true")
public class JwksController {

  private final JwkSetPort jwkSetPort;

  public JwksController(JwkSetPort jwkSetPort) {
    this.jwkSetPort = jwkSetPort;
  }

  @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
  ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(3600, TimeUnit.SECONDS))
        .body(jwkSetPort.getPublicKeySet());
  }
}
