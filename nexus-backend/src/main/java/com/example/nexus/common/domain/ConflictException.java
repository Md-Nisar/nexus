package com.example.nexus.common.domain;

/**
 * Thrown when a request conflicts with current state — duplicates, stale versions, illegal state
 * transitions. Maps to HTTP 409.
 */
public class ConflictException extends DomainException {

  public ConflictException(String code, String message) {
    super(code, message);
  }
}
