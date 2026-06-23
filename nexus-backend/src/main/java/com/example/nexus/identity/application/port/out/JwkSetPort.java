package com.example.nexus.identity.application.port.out;

import java.util.Map;

/**
 * Publishes the active RSA public key set in RFC 7517 (JWK Set) format.
 * Implementations live in {@code identity.infrastructure.security}.
 */
public interface JwkSetPort {

  /**
   * Returns the JWKS as a JSON-serialisable map suitable for direct Jackson serialisation.
   * Contains only public key material — never {@code d}, {@code p}, {@code q}, or any other
   * private key component.
   *
   * @return RFC 7517-compliant JWK Set map
   */
  Map<String, Object> getPublicKeySet();
}
