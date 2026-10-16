package com.example.nexus.rbac.application.port.out;

import com.example.nexus.common.domain.RequestContext;
import java.util.List;
import java.util.UUID;

/**
 * Typed carrier for the {@code ROLE_UPDATED} audit payload (US-018 C1, PATCH). Beside {@link
 * RoleAuditEvent} rather than a widening of it: an update has no permission and carries the changed
 * field names and the old and new NAME instead.
 *
 * <p><b>The description text is never carried</b>, in this record or in the audit row (T-T9/RC-3: it
 * is untrusted tenant free text). Only {@code changedFields}, which may contain the literal field
 * name {@code "description"}, says that it changed. {@code oldName} and {@code newName} are the role
 * names (allow-listed, CR/LF-excluded), non-null only when the name changed.
 */
public record RoleUpdateAuditEvent(
    UUID tenantId,
    UUID roleId,
    String roleName,
    String oldName,
    String newName,
    List<String> changedFields,
    UUID actorUserId,
    RequestContext requestContext) {

  public RoleUpdateAuditEvent {
    changedFields = List.copyOf(changedFields);
  }
}
