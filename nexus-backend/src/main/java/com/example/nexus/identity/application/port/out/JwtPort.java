package com.example.nexus.identity.application.port.out;

import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;

/**
 * Issues and verifies RS256 JWT access tokens.
 * Implementations live in {@code identity.infrastructure.security}.
 */
public interface JwtPort {

  /**
   * Issues a signed RS256 JWT access token for the given user.
   *
   * @param user the authenticated, ACTIVE user
   * @return the compact JWT, its TTL in seconds, and the JTI
   */
  AccessTokenResult issue(User user);

  /**
   * Verifies the signature, expiry, and algorithm of a raw JWT and returns its claims.
   *
   * @param rawJwt the compact serialised JWT from the {@code Authorization: Bearer} header
   * @return parsed and validated claims
   * @throws com.example.nexus.common.domain.AuthenticationException with code {@code AUTH_003} on
   *     any failure (expired, tampered, wrong algorithm, alg=none, foreign key, etc.)
   */
  JwtClaims verify(String rawJwt);
}
