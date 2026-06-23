package com.example.nexus.common.domain;

/**
 * Signals that a login was attempted on an account whose email address has not yet been verified.
 * Maps to HTTP 403 Forbidden with error code {@code AUTH_002}.
 *
 * <p>This is raised only <em>after</em> credentials are verified so it is indistinguishable from a
 * credential failure from the perspective of timing; it carries an actionable {@code action} field
 * in the response to let the client offer a resend-verification flow.
 */
public class AccountNotVerifiedException extends DomainException {

  public AccountNotVerifiedException(String code, String message) {
    super(code, message);
  }
}
