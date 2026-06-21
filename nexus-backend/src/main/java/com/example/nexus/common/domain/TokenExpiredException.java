package com.example.nexus.common.domain;

/**
 * Thrown when a verification token is not found, has expired, or has already been consumed.
 * All three states produce the same code (anti-enumeration: callers must not distinguish them).
 * Maps to HTTP 410 Gone.
 */
public class TokenExpiredException extends DomainException {

  public TokenExpiredException(String code, String message) {
    super(code, message);
  }
}
