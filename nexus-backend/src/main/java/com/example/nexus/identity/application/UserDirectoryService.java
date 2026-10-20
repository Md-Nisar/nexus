package com.example.nexus.identity.application;

import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.UserDirectoryThrottledException;
import com.example.nexus.identity.domain.UserStatus;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The user directory reads (US-019 B1, design §4.2): list, batch, by-id and exact-email lookup,
 * always inside the caller's tenant, which the controller takes from the JWT.
 *
 * <p><b>Cross-tenant parity (NF-S2).</b> A by-id miss always runs {@code existsById}, so a missing
 * id and another tenant's id run the same two statements and give the same 404 {@code
 * USER_NOT_FOUND}; the foreign case adds the WARN {@code IDENTITY_DIRECTORY_CROSS_TENANT_TARGET}
 * (no target id) and the {@code cross_tenant_miss} counter. Every batch runs the unscoped {@code
 * countByIdIn} (RC-61.2); its result only decides that WARN and never changes the response.
 *
 * <p><b>Lookup (design §4.4, §4.5).</b> The email is hashed only by {@link
 * EmailBlindIndexService#blindIndex} (ADR-0006) and never logged; a hit and a miss run the same
 * throttle, hash and indexed query, and a hit adds one decryption. Lookups are throttled per
 * (tenant, actor), failing open with the store, because the permission is the authorization gate.
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

  private static final String EVENT_THROTTLED = "IDENTITY_DIRECTORY_THROTTLED";
  private static final String LOOKUP_BUCKET = "DIR_LOOKUP";
  private static final String LOOKUP_WARN_BUCKET = "DIR_LOOKUP_WARN";

  private final UserDirectoryQueryPort queryPort;
  private final EmailBlindIndexService blindIndexService;
  private final RateLimitStore rateLimitStore;
  private final MeterRegistry meterRegistry;
  private final int lookupMaxAttempts;
  private final int lookupWindowSeconds;

  public UserDirectoryService(
      UserDirectoryQueryPort queryPort,
      EmailBlindIndexService blindIndexService,
      RateLimitStore rateLimitStore,
      MeterRegistry meterRegistry,
      @Value("${nexus.identity.directory.lookup.max-attempts}") int lookupMaxAttempts,
      @Value("${nexus.identity.directory.lookup.window-seconds}") int lookupWindowSeconds) {
    this.queryPort = queryPort;
    this.blindIndexService = blindIndexService;
    this.rateLimitStore = rateLimitStore;
    this.meterRegistry = meterRegistry;
    this.lookupMaxAttempts = lookupMaxAttempts;
    this.lookupWindowSeconds = lookupWindowSeconds;
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

  /**
   * The tenant's user with exactly this email, after {@link EmailBlindIndexService}'s
   * normalisation; empty when no user of the tenant has it, including when another tenant's user
   * does (design §4.4). The per-actor throttle is consumed first, so a throttled lookup never
   * hashes or queries.
   *
   * @throws UserDirectoryThrottledException 429 {@code USER_DIR_001} once the actor exceeds the
   *     lookup bucket; the store fails open (ADR-0016)
   */
  public Optional<DirectoryUserView> lookup(UUID tenantId, UUID actorUserId, String email) {
    String actorKey = tenantId + ":" + actorUserId;
    RateLimitResult throttle =
        rateLimitStore.tryConsume(
            LOOKUP_BUCKET + ":" + actorKey, lookupWindowSeconds, lookupMaxAttempts);
    if (!throttle.allowed()) {
      warnOncePerWindow(actorKey, tenantId, actorUserId);
      throw new UserDirectoryThrottledException(throttle.retryAfterSeconds());
    }
    return queryPort.findByTenantAndEmailHmac(tenantId, blindIndexService.blindIndex(email));
  }

  /**
   * Emits {@code IDENTITY_DIRECTORY_THROTTLED} for the first rejection of a window only. A
   * one-slot bucket on the same store decides it, so the WARN stays once per window per actor
   * across replicas when the store is Redis.
   */
  private void warnOncePerWindow(String actorKey, UUID tenantId, UUID actorUserId) {
    if (rateLimitStore
        .tryConsume(LOOKUP_WARN_BUCKET + ":" + actorKey, lookupWindowSeconds, 1)
        .allowed()) {
      log.atWarn()
          .addKeyValue("event", EVENT_THROTTLED)
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("actorUserId", actorUserId)
          .addKeyValue("bucket", LOOKUP_BUCKET)
          .log("Throttled directory lookups for an actor");
    }
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
