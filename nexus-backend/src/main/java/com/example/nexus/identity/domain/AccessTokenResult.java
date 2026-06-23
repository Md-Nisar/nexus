package com.example.nexus.identity.domain;

/**
 * Value object returned by
 * {@link com.example.nexus.identity.application.port.out.JwtPort#issue(User)}.
 * The {@code token} field contains a signed JWT and must not appear in logs.
 */
public record AccessTokenResult(String token, long expiresInSeconds, String jti) {

  @Override
  public String toString() {
    return "AccessTokenResult{jti='" + jti + "', expiresInSeconds=" + expiresInSeconds + "}";
  }
}
