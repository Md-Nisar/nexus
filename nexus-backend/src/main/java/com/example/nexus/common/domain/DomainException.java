package com.example.nexus.common.domain;

/**
 * Base class for all business-rule violations.
 *
 * <p>Subclasses map to HTTP status codes in {@code GlobalExceptionHandler}. The {@code code} is a
 * stable, machine-readable identifier (SCREAMING_SNAKE_CASE) that API clients may branch on — it is
 * part of the public contract, so never rename an existing code.
 */
public abstract class DomainException extends RuntimeException {

  private final String code;

  protected DomainException(String code, String message) {
    super(message);
    this.code = code;
  }

  public String code() {
    return code;
  }
}
