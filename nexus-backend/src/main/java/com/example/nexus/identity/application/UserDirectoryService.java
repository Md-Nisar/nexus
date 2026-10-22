package com.example.nexus.identity.application;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.application.port.out.DirectoryReadAuditPort;
import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.domain.DirectoryBatch;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserStatus;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The user directory reads (US-019 B1, design §4.2): list, batch, by-id and exact-email lookup,
 * always inside the caller's tenant, which the controller takes from the JWT.
 *
 * <p><b>Cross-tenant parity (NF-S2).</b> A by-id miss always runs {@code existsById}, so a missing
 * id and another tenant's id run the same two statements and give the same 404 {@code
 * USER_NOT_FOUND}; the foreign case adds the WARN {@code IDENTITY_DIRECTORY_CROSS_TENANT_TARGET}
 * (no target id) and the {@code cross_tenant_miss} counter. Every batch also reads the unscoped
 * count in the same transaction as the rows (RC-61.2); its result only decides that WARN and never
 * changes the response.
 *
 * <p><b>Lookup (design §4.4).</b> The email is hashed only by {@link
 * EmailBlindIndexService#blindIndex} (ADR-0006) and never logged. The per-actor throttle and
 * ceiling live in {@link DirectoryAccessGuard}, consulted by the controller first.
 *
 * <p><b>No transaction here (review R2-1).</b> Each query-port call is its own read-only
 * transaction, opened by the port's JPA adapter and over before the audit row is written. The audit write is a {@code REQUIRES_NEW} transaction;
 * called inside an open read transaction it would need a second pooled connection while holding
 * the first, so enough concurrent reads would exhaust the pool and lose their audit rows.
 *
 * <p><b>Audit and logs (design §4.5, §17).</b> Every successful read writes one {@code
 * USER_DIRECTORY_READ} row through {@link DirectoryReadAuditPort} and logs one INFO {@code
 * IDENTITY_DIRECTORY_READ}, both carrying counts and ids only: never an email, a blind index or the
 * id list.
 */
@Service
public class UserDirectoryService {

  private static final Logger log = LoggerFactory.getLogger(UserDirectoryService.class);

  private static final String COUNTER_CROSS_TENANT_MISS =
      "nexus.identity.directory.cross_tenant_miss";
  private static final String EVENT_CROSS_TENANT_TARGET = "IDENTITY_DIRECTORY_CROSS_TENANT_TARGET";
  private static final String CODE_USER_NOT_FOUND = "USER_NOT_FOUND";
  private static final String MESSAGE_NO_SUCH_USER = "No such user";

  private static final String EVENT_READ = "IDENTITY_DIRECTORY_READ";

  private final UserDirectoryQueryPort queryPort;
  private final EmailBlindIndexService blindIndexService;
  private final DirectoryReadAuditPort auditPort;
  private final MeterRegistry meterRegistry;

  public UserDirectoryService(
      UserDirectoryQueryPort queryPort,
      EmailBlindIndexService blindIndexService,
      DirectoryReadAuditPort auditPort,
      MeterRegistry meterRegistry) {
    this.queryPort = queryPort;
    this.blindIndexService = blindIndexService;
    this.auditPort = auditPort;
    this.meterRegistry = meterRegistry;
  }

  /**
   * One page of the tenant's users, ordered by id.
   *
   * @param status the status to filter by, or {@code null} for every status
   */
  public DirectoryPage<DirectoryUserView> list(
      UUID tenantId, UUID actorUserId, UserStatus status, int page, int size) {
    DirectoryPage<DirectoryUserView> result =
        queryPort.findPageByTenant(tenantId, status, page, size);
    String statusFilter = status == null ? null : status.name();
    audit(tenantId, actorUserId, new Read("LIST", result.items().size(), statusFilter, null, null, null));
    return result;
  }

  /**
   * The tenant's users among {@code ids} (already de-duplicated, at most 100), ordered by id. Ids
   * of other tenants are silently omitted.
   */
  public List<DirectoryUserView> batch(UUID tenantId, UUID actorUserId, List<UUID> ids) {
    DirectoryBatch batch = queryPort.findBatchByTenant(tenantId, ids);
    List<DirectoryUserView> found = batch.found();
    long omittedForeign = batch.omittedForeign();
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
    audit(tenantId, actorUserId, new Read("BATCH", found.size(), null, ids.size(), null, null));
    return found;
  }

  /** The user {@code userId} of the tenant; 404 {@code USER_NOT_FOUND} if missing or foreign. */
  public DirectoryUserView get(UUID tenantId, UUID actorUserId, UUID userId) {
    DirectoryUserView view =
        queryPort
            .findByTenantAndId(tenantId, userId)
            .orElseThrow(() -> notFound(tenantId, actorUserId, userId));
    audit(tenantId, actorUserId, new Read("GET", 1, null, null, null, null));
    return view;
  }

  /**
   * The tenant's user with exactly this email, after {@link EmailBlindIndexService}'s
   * normalisation; empty when no user of the tenant has it, including when another tenant's user
   * does (design §4.4). The caller consults {@link DirectoryAccessGuard} first, so a throttled
   * lookup never reaches here.
   */
  public Optional<DirectoryUserView> lookup(UUID tenantId, UUID actorUserId, String email) {
    Optional<DirectoryUserView> found =
        queryPort.findByTenantAndEmailHmac(tenantId, blindIndexService.blindIndex(email));
    audit(
        tenantId,
        actorUserId,
        new Read(
            "LOOKUP",
            found.isPresent() ? 1 : 0,
            null,
            null,
            found.isPresent() ? "HIT" : "MISS",
            found.map(DirectoryUserView::id).orElse(null)));
    return found;
  }

  /**
   * Writes the audit row (best-effort, the port never throws) and the INFO log of one read. Only
   * counts, the status filter and ids go in: never the email, the blind index or the id list.
   */
  private void audit(UUID tenantId, UUID actorUserId, Read read) {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("operation", read.operation());
    metadata.put("resultCount", read.resultCount());
    metadata.put("statusFilter", read.statusFilter());
    if (read.outcome() != null) {
      metadata.put("outcome", read.outcome());
    }
    if (read.resolvedUserId() != null) {
      metadata.put("resolvedUserId", read.resolvedUserId().toString());
    }
    auditPort.recordDirectoryRead(tenantId, actorUserId, metadata);

    var entry =
        log.atInfo()
            .addKeyValue("event", EVENT_READ)
            .addKeyValue("tenantId", tenantId)
            .addKeyValue("actorUserId", actorUserId)
            .addKeyValue("operation", read.operation())
            .addKeyValue("resultCount", read.resultCount())
            .addKeyValue("statusFilter", read.statusFilter());
    if (read.requestedCount() != null) {
      entry =
          entry
              .addKeyValue("requestedCount", read.requestedCount())
              .addKeyValue("returnedCount", read.resultCount());
    }
    entry.log("Directory read");
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

  private record Read(
      String operation,
      int resultCount,
      String statusFilter,
      Integer requestedCount,
      String outcome,
      UUID resolvedUserId) {}
}
