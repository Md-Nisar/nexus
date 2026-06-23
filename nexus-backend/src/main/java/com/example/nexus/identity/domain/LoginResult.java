package com.example.nexus.identity.domain;

/**
 * Value object returned by the login and refresh use-cases.
 * {@code rawRefreshToken} is the plaintext token value used once by the controller to set the
 * {@code refresh_token} cookie; it must not appear in logs or be stored anywhere.
 */
public record LoginResult(
    String accessToken, long expiresInSeconds, String userId, String rawRefreshToken) {

  @Override
  public String toString() {
    return "LoginResult{userId='" + userId + "', expiresInSeconds=" + expiresInSeconds + "}";
  }
}
