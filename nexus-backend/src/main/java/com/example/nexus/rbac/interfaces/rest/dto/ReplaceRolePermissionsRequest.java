package com.example.nexus.rbac.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Request body for {@code PUT /api/v1/roles/{roleId}/permissions} (US-019 B8, design §10.5): the
 * complete permission set the role should carry. At most 100 ids, each a canonical UUID string
 * (validated as a string for the reason {@link AttachPermissionRequest} gives); an empty list is
 * legal. Duplicates are rejected by the controller after parsing, so differently-cased spellings of
 * one id count as a duplicate.
 */
public record ReplaceRolePermissionsRequest(
    @NotNull
        @Size(max = 100)
        @ArraySchema(
            schema =
                @Schema(
                    description = "Permission id",
                    example = "019f6839-1804-7000-8000-000000000005"),
            maxItems = 100,
            uniqueItems = true)
        List<
                @NotNull
                @Pattern(
                    regexp =
                        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                            + "-[0-9a-fA-F]{12}$",
                    message = "must be a canonical UUID")
                String>
            permissionIds) {

  /** An unmodifiable copy, not {@code List.copyOf}: null elements must reach bean validation. */
  public ReplaceRolePermissionsRequest {
    permissionIds =
        permissionIds == null ? null : Collections.unmodifiableList(new ArrayList<>(permissionIds));
  }
}
