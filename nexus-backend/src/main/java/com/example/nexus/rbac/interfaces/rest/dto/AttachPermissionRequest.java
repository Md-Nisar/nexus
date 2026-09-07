package com.example.nexus.rbac.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request body for {@code POST /api/v1/roles/{roleId}/permissions} (03-design.md §8.4).
 *
 * <p>{@code permissionId} is deliberately a {@code String}, not a {@code UUID}: a malformed
 * {@code UUID}-typed field would fail Jackson deserialization with {@code
 * HttpMessageNotReadableException}, which {@code GlobalExceptionHandler} (a plain {@code
 * @RestControllerAdvice}, not {@code ResponseEntityExceptionHandler}) has no handler for and would
 * fall through to a 500. Validating as a canonical-UUID-shaped string routes malformed input
 * through Bean Validation instead, yielding a 400 with a {@code details[]} entry.
 */
public record AttachPermissionRequest(
    @NotBlank
        @Pattern(
            regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            message = "must be a canonical UUID")
        String permissionId) {}
