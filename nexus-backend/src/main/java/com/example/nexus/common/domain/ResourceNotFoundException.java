package com.example.nexus.common.domain;

/**
 * Thrown when a requested resource does not exist or the caller is not allowed to know it exists.
 * Maps to HTTP 404.
 */
public class ResourceNotFoundException extends DomainException {

  public ResourceNotFoundException(String code, String message) {
    super(code, message);
  }
}
