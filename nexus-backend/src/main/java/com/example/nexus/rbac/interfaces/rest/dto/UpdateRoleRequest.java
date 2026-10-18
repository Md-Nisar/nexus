package com.example.nexus.rbac.interfaces.rest.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code PATCH /api/v1/roles/{roleId}} (US-018 C1, 03-design.md 11.1).
 *
 * <p>A field that is absent or {@code null} is left unchanged. An empty {@code description} clears
 * it. At least one field must be present. There is no {@code tenantId} and no {@code isSystemRole}
 * field, by the same "do not model it" rule as {@link CreateRoleRequest}. {@code name} is not
 * trimmed and keeps create's allow-list (no CR/LF), so it stays loggable and auditable.
 *
 * <p><b>{@code description} is untrusted free text and must never be written to a log, a metric tag
 * or an audit payload</b> (T-T9/RC-3).
 */
public record UpdateRoleRequest(
    @Size(min = 1, max = 64)
        @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9 ._-]*$", message = "must be a valid role name")
        String name,
    @Size(max = 255)
        @Pattern(
            regexp = "^[^\\p{Cntrl}\\u2028\\u2029]*$",
            message = "must not contain control characters")
        String description) {

  /** Rejects an empty body: nothing to update. */
  @AssertTrue(message = "at least one of name or description is required")
  public boolean isAtLeastOneFieldPresent() {
    return name != null || description != null;
  }
}
