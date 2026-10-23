package com.example.nexus.identity.application;

import com.example.nexus.identity.application.port.out.RateLimitResult;
import com.example.nexus.identity.application.port.out.RateLimitStore;
import com.example.nexus.identity.domain.UserDirectoryCeilingExceededException;
import com.example.nexus.identity.domain.UserDirectoryThrottledException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The two abuse buckets of the user directory (US-019 design §4.5), consulted by the controller
 * before the service runs, so a throttled request never hashes, queries or writes an audit row.
 *
 * <ul>
 *   <li>{@code DIR_LOOKUP:{tenantId}:{actorUserId}}: email lookups only (NF-S5), 429 {@code
 *       USER_DIR_001}.
 *   <li>{@code DIR_ALL:{tenantId}:{actorUserId}}: all four operations (RC-61.3), 429 {@code
 *       USER_DIR_002}.
 * </ul>
 *
 * Both fail open with the store (ADR-0016), because the permission is the authorization gate. Each
 * logs at most one WARN {@code IDENTITY_DIRECTORY_THROTTLED} per window per actor, decided by a
 * one-slot bucket on the same store, so it stays once per window across replicas when the store is
 * Redis (RC-63(c)).
 */
@Component
public class DirectoryAccessGuard {

  private static final Logger log = LoggerFactory.getLogger(DirectoryAccessGuard.class);

  private static final String EVENT_THROTTLED = "IDENTITY_DIRECTORY_THROTTLED";
  private static final String LOOKUP_BUCKET = "DIR_LOOKUP";
  private static final String CEILING_BUCKET = "DIR_ALL";
  private static final String WARN_SUFFIX = "_WARN";

  private final RateLimitStore rateLimitStore;
  private final int lookupMaxAttempts;
  private final int lookupWindowSeconds;
  private final int ceilingMaxAttempts;
  private final int ceilingWindowSeconds;

  public DirectoryAccessGuard(
      RateLimitStore rateLimitStore,
      @Value("${nexus.identity.directory.lookup.max-attempts}") int lookupMaxAttempts,
      @Value("${nexus.identity.directory.lookup.window-seconds}") int lookupWindowSeconds,
      @Value("${nexus.identity.directory.ceiling.max-attempts}") int ceilingMaxAttempts,
      @Value("${nexus.identity.directory.ceiling.window-seconds}") int ceilingWindowSeconds) {
    this.rateLimitStore = rateLimitStore;
    this.lookupMaxAttempts = lookupMaxAttempts;
    this.lookupWindowSeconds = lookupWindowSeconds;
    this.ceilingMaxAttempts = ceilingMaxAttempts;
    this.ceilingWindowSeconds = ceilingWindowSeconds;
  }

  /**
   * Consumes one slot of the actor's directory ceiling.
   *
   * @throws UserDirectoryCeilingExceededException 429 {@code USER_DIR_002} once exceeded
   */
  public void checkCeiling(UUID tenantId, UUID actorUserId) {
    RateLimitResult result =
        consume(CEILING_BUCKET, tenantId, actorUserId, ceilingWindowSeconds, ceilingMaxAttempts);
    if (!result.allowed()) {
      warnOncePerWindow(CEILING_BUCKET, tenantId, actorUserId, ceilingWindowSeconds);
      throw new UserDirectoryCeilingExceededException(result.retryAfterSeconds());
    }
  }

  /**
   * Consumes one slot of the actor's email-lookup throttle.
   *
   * @throws UserDirectoryThrottledException 429 {@code USER_DIR_001} once exceeded
   */
  public void checkLookup(UUID tenantId, UUID actorUserId) {
    RateLimitResult result =
        consume(LOOKUP_BUCKET, tenantId, actorUserId, lookupWindowSeconds, lookupMaxAttempts);
    if (!result.allowed()) {
      warnOncePerWindow(LOOKUP_BUCKET, tenantId, actorUserId, lookupWindowSeconds);
      throw new UserDirectoryThrottledException(result.retryAfterSeconds());
    }
  }

  private RateLimitResult consume(
      String bucket, UUID tenantId, UUID actorUserId, int windowSeconds, int maxAttempts) {
    return rateLimitStore.tryConsume(key(bucket, tenantId, actorUserId), windowSeconds, maxAttempts);
  }

  private void warnOncePerWindow(
      String bucket, UUID tenantId, UUID actorUserId, int windowSeconds) {
    if (rateLimitStore
        .tryConsume(key(bucket + WARN_SUFFIX, tenantId, actorUserId), windowSeconds, 1)
        .allowed()) {
      log.atWarn()
          .addKeyValue("event", EVENT_THROTTLED)
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("actorUserId", actorUserId)
          .addKeyValue("bucket", bucket)
          .log("Throttled directory requests for an actor");
    }
  }

  private static String key(String bucket, UUID tenantId, UUID actorUserId) {
    return bucket + ":" + tenantId + ":" + actorUserId;
  }
}
