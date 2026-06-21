package com.example.nexus.common.domain;

/**
 * Thrown when a single field fails a domain-enforced business rule (e.g., password policy).
 * Maps to HTTP 400 Bad Request with a {@code details} array containing the offending field.
 *
 * <p>Distinct from {@link org.springframework.web.bind.MethodArgumentNotValidException}, which
 * covers Bean Validation failures at the controller boundary. This exception is thrown from
 * application-layer services where the rule cannot be expressed as a Bean Validation constraint.
 */
public class FieldValidationException extends DomainException {

  private final String field;

  public FieldValidationException(String code, String field, String message) {
    super(code, message);
    this.field = field;
  }

  public String field() {
    return field;
  }
}
