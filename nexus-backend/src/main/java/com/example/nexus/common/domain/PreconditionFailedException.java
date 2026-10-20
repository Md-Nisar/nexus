package com.example.nexus.common.domain;

/**
 * Thrown when a conditional write's {@code If-Match} no longer matches the resource's current
 * state. Maps to HTTP 412 {@code PRECONDITION_FAILED}. The message is fixed and the exception
 * carries no state, so the response body never reveals the current version or contents (US-019
 * RC-58.2).
 */
public class PreconditionFailedException extends DomainException {

  /** The one, fixed-message instance shape: no state is ever attached. */
  public PreconditionFailedException() {
    super(
        "PRECONDITION_FAILED",
        "The resource changed since you read it. Reload it and try again.");
  }
}
