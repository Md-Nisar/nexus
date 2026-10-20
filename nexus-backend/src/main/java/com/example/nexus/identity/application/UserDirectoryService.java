package com.example.nexus.identity.application;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The user directory reads (US-019 B1, design §4.2): list, batch and by-id, always inside the
 * caller's tenant, which the controller takes from the JWT.
 *
 * <p><b>Cross-tenant parity (NF-S2).</b> A by-id miss always runs {@code existsById}, so a missing
 * id and another tenant's id run the same two statements and give the same 404 {@code
 * USER_NOT_FOUND}; the foreign case adds the WARN {@code IDENTITY_DIRECTORY_CROSS_TENANT_TARGET}
 * (no target id) and the {@code cross_tenant_miss} counter. Every batch runs the unscoped {@code
 * countByIdIn} (RC-61.2); its result only decides that WARN and never changes the response.
 */
@Service
@Transactional(readOnly = true)
public class UserDirectoryService {

  private static final Logger log = LoggerFactory.getLogger(UserDirectoryService.class);

  private static final String COUNTER_CROSS_TENANT_MISS =
      "nexus.identity.directory.cross_tenant_miss";
  private static final String EVENT_CROSS_TENANT_TARGET = "IDENTITY_DIRECTORY_CROSS_TENANT_TARGET";
  private static final String CODE_USER_NOT_FOUND = "USER_NOT_FOUND";
  private static final String MESSAGE_NO_SUCH_USER = "No such user";

  private final UserDirectoryQueryPort queryPort;
  private final MeterRegistry meterRegistry;

  public UserDirectoryService(UserDirectoryQueryPort queryPort, MeterRegistry meterRegistry) {
    this.queryPort = queryPort;
    this.meterRegistry = meterRegistry;
  }

  /**
   * One page of the tenant's users, ordered by id.
   *
   * @param status the status to filter by, or {@code null} for every status
   */
  public DirectoryPage<DirectoryUserView> list(
      UUID tenantId, UserStatus status, int page, int size) {
    return queryPort.findPageByTenant(tenantId, status, page, size);
  }

  /**
   * The tenant's users among {@code ids} (already de-duplicated, at most 100), ordered by id. Ids
   * of other tenants are silently omitted.
   */
  public List<DirectoryUserView> batch(UUID tenantId, UUID actorUserId, List<UUID> ids) {
    List<DirectoryUserView> found = queryPort.findByTenantAndIds(tenantId, ids);
    long omittedForeign = queryPort.countByIdIn(ids) - found.size();
    if (omittedForeign > 0) {
      log.atWarn()
          .addKeyValue("event", EVENT_CROSS_TENANT_TARGET)
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("actorUserId", actorUserId)
          .addKeyValue("operation", "BATCH")
          .addKeyValue("omittedCount", omittedForeign)
          .log("Omitted users of another tenant from a directory batch read");
      meterRegistry.counter(COUNTER_CROSS_TENANT_MISS).increment();
    }
    return found;
  }

  /** The user {@code userId} of the tenant; 404 {@code USER_NOT_FOUND} if missing or foreign. */
  public DirectoryUserView get(UUID tenantId, UUID actorUserId, UUID userId) {
    return queryPort
        .findByTenantAndId(tenantId, userId)
        .orElseThrow(() -> notFound(tenantId, actorUserId, userId));
  }

  private ResourceNotFoundException notFound(UUID tenantId, UUID actorUserId, UUID userId) {
    if (queryPort.existsById(userId)) {
      log.atWarn()
          .addKeyValue("event", EVENT_CROSS_TENANT_TARGET)
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("actorUserId", actorUserId)
          .addKeyValue("operation", "GET")
          .log("Refused a directory read: the target belongs to another tenant");
      meterRegistry.counter(COUNTER_CROSS_TENANT_MISS).increment();
    }
    return new ResourceNotFoundException(CODE_USER_NOT_FOUND, MESSAGE_NO_SUCH_USER);
  }
}
