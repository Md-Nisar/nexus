package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Token-freshness policy for the per-user permission epoch (US-018 A9, design §9.1 to §9.3).
 *
 * <ul>
 *   <li>{@link #epochForMint} is read by the token minter <b>before</b> it resolves permissions
 *       (MC-7a), so a bump racing the mint yields "old epoch, new permissions" (rejected once,
 *       safe) and never "new epoch, old permissions".
 *   <li>{@link #check} runs once per non-public authenticated request. A single failed or slow
 *       read fails open for that request only and is counted as {@code skipped_error}.
 *   <li>{@link #invalidateUser} and {@link #invalidateHolders} must only be called after the
 *       permission-reducing transaction commits (MC-7b); bumping earlier lets a mint in the gap
 *       read the new epoch with pre-commit permissions.
 * </ul>
 *
 * <p>Signals: {@code nexus.rbac.epoch.check{outcome}} and {@code nexus.rbac.epoch.check.latency}
 * (p50/p95/p99), the hot-path budget being p95 at most 2 ms (design §9.5); {@code
 * nexus.rbac.epoch.fanout{holders}} per holder fan-out, bucketed, with no tenant tag (§9.4). Bump
 * failures are logged only and never touch the check outcomes (RC-53).
 */
@Service
public class PermissionFreshnessService {

  private static final Logger log = LoggerFactory.getLogger(PermissionFreshnessService.class);

  static final String METRIC_CHECK = "nexus.rbac.epoch.check";
  static final String METRIC_CHECK_LATENCY = "nexus.rbac.epoch.check.latency";
  static final String METRIC_FANOUT = "nexus.rbac.epoch.fanout";

  /** Users per bump script call (design §9.4); sized for the 500 ms bump timeout. */
  static final int FANOUT_BATCH_SIZE = 500;

  /** Above this many holders a fan-out logs {@code RBAC_EPOCH_FANOUT_LARGE}. */
  static final int FANOUT_LARGE_THRESHOLD = 1000;

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_OPERATION = "operation";
  private static final String LOG_KEY_TENANT_ID = "tenantId";

  private final PermissionEpochPort epochPort;
  private final Map<FreshnessVerdict, Counter> outcomeCounters;
  private final Timer checkLatency;
  private final Map<String, Counter> fanoutCounters;

  public PermissionFreshnessService(PermissionEpochPort epochPort, MeterRegistry meterRegistry) {
    this.epochPort = epochPort;
    this.outcomeCounters = new EnumMap<>(FreshnessVerdict.class);
    for (FreshnessVerdict verdict : FreshnessVerdict.values()) {
      outcomeCounters.put(verdict, Counter.builder(METRIC_CHECK)
          .description("Request-time permission-epoch checks, by outcome")
          .tag("outcome", verdict.tag())
          .register(meterRegistry));
    }
    this.checkLatency = Timer.builder(METRIC_CHECK_LATENCY)
        .description("Latency of the request-time permission-epoch check")
        .publishPercentiles(0.5, 0.95, 0.99)
        .register(meterRegistry);
    this.fanoutCounters = new HashMap<>();
    for (String bucket : List.of("0", "1-10", "11-100", "101-1000", ">1000")) {
      fanoutCounters.put(bucket, Counter.builder(METRIC_FANOUT)
          .description("Post-commit permission-epoch fan-outs, by holder-count bucket")
          .tag("holders", bucket)
          .register(meterRegistry));
    }
  }

  /**
   * Returns the epoch to embed in a token about to be minted.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the current epoch; {@code 0} when none is stored or the store still cannot answer
   *     after one retry (a token minted with 0 against a later-recovered epoch is rejected once,
   *     which is safe)
   */
  public long epochForMint(UUID tenantId, UUID userId) {
    // One retry: a single 50 ms read failure would otherwise mint perm_epoch=0 for a recently
    // revoked user, who is then rejected, refreshes and is rejected again.
    OptionalLong current = epochPort.current(tenantId, userId);
    if (current.isEmpty()) {
      current = epochPort.current(tenantId, userId);
    }
    return current.orElse(0L);
  }

  /**
   * Checks whether a token epoch is still current.
   *
   * @param tenantId the token's tenant
   * @param userId the token's subject
   * @param tokenEpoch the token's {@code perm_epoch} ({@code 0} for a v2 token)
   * @return {@link FreshnessVerdict#STALE} iff {@code tokenEpoch} is lower than the stored epoch;
   *     {@link FreshnessVerdict#SKIPPED_ERROR} when the store could not answer
   */
  public FreshnessVerdict check(UUID tenantId, UUID userId, long tokenEpoch) {
    Timer.Sample sample = Timer.start();
    OptionalLong current = epochPort.current(tenantId, userId);
    FreshnessVerdict verdict;
    if (current.isEmpty()) {
      verdict = FreshnessVerdict.SKIPPED_ERROR;
    } else if (tokenEpoch < current.getAsLong()) {
      verdict = FreshnessVerdict.STALE;
    } else {
      verdict = FreshnessVerdict.FRESH;
    }
    sample.stop(checkLatency);
    outcomeCounters.get(verdict).increment();
    return verdict;
  }

  /**
   * Makes every token of a user minted so far stale. Post-commit only (MC-7b).
   *
   * <p>A store failure is logged as {@code RBAC_EPOCH_BUMP_FAILED} and not rethrown: the change
   * has already committed, so an exception here would only turn the administrator's success into
   * an error.
   *
   * @param tenantId the user's tenant
   * @param userId the user whose permissions were reduced
   * @param operation what reduced them (for example {@code revoke}); logged on failure
   */
  public void invalidateUser(UUID tenantId, UUID userId, String operation) {
    // Runs in afterCommit, so the JDBC connection is still held for up to the bump timeout
    // (500 ms) while Redis is slow.
    try {
      epochPort.bump(tenantId, List.of(userId));
    } catch (RuntimeException e) {
      // Not only DataAccessException: a stopped factory or a bad script result must not turn a
      // committed change into a 500 either.
      logBumpFailed(tenantId, operation, 1, e);
    }
  }

  /**
   * Makes every token minted so far stale for each given user, and deletes each user's cached
   * permission set under the replaced epoch (A10, design §9.4). Post-commit only (MC-7b); the
   * caller reads the holders after commit, so no assignment committed before that read is missed.
   *
   * <p>Duplicates are dropped. The users are bumped in sequential batches of {@value
   * #FANOUT_BATCH_SIZE}, with no cap: a cap would silently leave holders unrevoked (T-D23). The
   * first failed batch ends the fan-out, so a down Redis costs the request one bump timeout, not
   * one per batch; one {@code RBAC_EPOCH_BUMP_FAILED} counts that batch and every batch not sent.
   * Nothing is rethrown, for the reason given on {@link #invalidateUser}.
   *
   * @param tenantId the holders' tenant
   * @param userIds the active holders of the role whose permission set shrank
   * @param operation what shrank it (for example {@code detach}); logged
   */
  public void invalidateHolders(UUID tenantId, Collection<UUID> userIds, String operation) {
    List<UUID> holders = List.copyOf(new LinkedHashSet<>(userIds));
    fanoutCounters.get(fanoutBucket(holders.size())).increment();
    if (holders.size() > FANOUT_LARGE_THRESHOLD) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_FANOUT_LARGE")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .addKeyValue("holderCount", holders.size())
          .log("Large permission epoch fan-out");
    }
    // Runs in afterCommit on the request thread: the 204 waits for every batch (design §9.4).
    for (int from = 0; from < holders.size(); from += FANOUT_BATCH_SIZE) {
      List<UUID> batch = holders.subList(from, Math.min(from + FANOUT_BATCH_SIZE, holders.size()));
      try {
        epochPort.bump(tenantId, batch);
      } catch (RuntimeException e) {
        logBumpFailed(tenantId, operation, holders.size() - from, e);
        return;
      }
    }
  }

  private static void logBumpFailed(
      UUID tenantId, String operation, int userCount, RuntimeException e) {
    log.atError()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_FAILED")
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
        .addKeyValue("userCount", userCount)
        .addKeyValue("exception", e.getClass().getSimpleName())
        .log("Permission epoch bump failed");
  }

  /** {@code 0 | 1-10 | 11-100 | 101-1000 | >1000} (design §9.4, US-016 D13 precedent). */
  private static String fanoutBucket(int holders) {
    if (holders == 0) {
      return "0";
    }
    if (holders <= 10) {
      return "1-10";
    }
    if (holders <= 100) {
      return "11-100";
    }
    if (holders <= FANOUT_LARGE_THRESHOLD) {
      return "101-1000";
    }
    return ">1000";
  }
}
