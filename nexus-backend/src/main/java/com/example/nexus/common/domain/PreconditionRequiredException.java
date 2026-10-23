package com.example.nexus.common.domain;

/**
 * Thrown when a conditional write arrives without a usable {@code If-Match}: absent, {@code *}, a
 * list, weak-only, empty or unparseable. Maps to HTTP 428 {@code PRECONDITION_REQUIRED}. The
 * message is fixed and never echoes the header (US-019 RC-55.2).
 */
public class PreconditionRequiredException extends DomainException {

  /** The one, fixed-message instance shape: the header is never attached. */
  public PreconditionRequiredException() {
    super(
        "PRECONDITION_REQUIRED",
        "This request requires an If-Match header with exactly one strong entity tag.");
  }
}
