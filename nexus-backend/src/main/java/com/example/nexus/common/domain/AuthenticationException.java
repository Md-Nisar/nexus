package com.example.nexus.common.domain;

/**
 * Signals an authentication failure: bad credentials, unknown identity, invalid or expired token,
 * or a non-ACTIVE account status that prevents login. Maps to HTTP 401 Unauthorized.
 *
 * <p>Stable error codes: {@code AUTH_001} (bad credentials / non-ACTIVE status),
 * {@code AUTH_003} (invalid or expired JWT), {@code AUTH_004} (invalid refresh token).
 */
public class AuthenticationException extends DomainException {

  public AuthenticationException(String code, String message) {
    super(code, message);
  }
}
