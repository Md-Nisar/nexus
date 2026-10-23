package com.example.nexus.identity.application.port.out;

import java.util.Map;
import java.util.UUID;

/**
 * Port for the audit row of one directory read (US-019 design §4.5).
 *
 * <p>Best-effort: an implementation never throws and never fails the read it records. The metadata
 * holds {@code operation}, {@code resultCount}, {@code statusFilter} and, for lookups, {@code
 * outcome} and {@code resolvedUserId}. It never holds an email, a blind index or an id list.
 */
public interface DirectoryReadAuditPort {

  /**
   * Records that {@code actorUserId} read the directory of {@code tenantId}.
   *
   * @param metadata the PII-free audit metadata; values may be {@code null}
   */
  void recordDirectoryRead(UUID tenantId, UUID actorUserId, Map<String, Object> metadata);
}
