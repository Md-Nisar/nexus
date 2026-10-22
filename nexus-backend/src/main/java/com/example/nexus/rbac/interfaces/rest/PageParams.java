package com.example.nexus.rbac.interfaces.rest;

import com.example.nexus.common.domain.FieldValidationException;

/**
 * The validated {@code page} and {@code size} query parameters of a paged list (US-018 C2, api-design
 * skill: default page size 20, max 100). Out-of-range or non-numeric values are a 400 {@code
 * VALIDATION_FAILED}, never silently clamped.
 *
 * <p>The raw parameters are {@code String}s parsed here, as path UUIDs are in {@link
 * RbacControllerSupport#parsePathUuid}: an {@code int}-typed {@code @RequestParam} would raise a
 * type-mismatch exception for {@code page=abc} that {@code GlobalExceptionHandler} does not map,
 * producing a 500.
 */
record PageParams(int page, int size) {

  static final int DEFAULT_SIZE = 20;
  static final int MAX_SIZE = 100;

  static PageParams parse(String rawPage, String rawSize) {
    int page = parseInt(rawPage, "page", 0);
    int size = parseInt(rawSize, "size", DEFAULT_SIZE);
    if (page < 0) {
      throw new FieldValidationException("VALIDATION_FAILED", "page", "must be 0 or greater");
    }
    if (size < 1 || size > MAX_SIZE) {
      throw new FieldValidationException(
          "VALIDATION_FAILED", "size", "must be between 1 and " + MAX_SIZE);
    }
    return new PageParams(page, size);
  }

  private static int parseInt(String raw, String field, int defaultValue) {
    if (raw == null || raw.isEmpty()) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new FieldValidationException("VALIDATION_FAILED", field, "must be an integer");
    }
  }
}
