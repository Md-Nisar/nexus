package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
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
 *   <li>{@link #invalidateUser} must only be called after the revoking transaction commits
 *       (MC-7b); bumping earlier lets a mint in the gap read the new epoch with pre-commit
 *       permissions.
 * </ul>
 *
 * <p>Signals: {@code nexus.rbac.epoch.check{outcome}} and {@code nexus.rbac.epoch.check.latency}
 * (p50/p95/p99), the hot-path budget being p95 at most 2 ms (design §9.5).
 */
@Service
public class PermissionFreshnessService {

  private static final Logger log = LoggerFactory.getLogger(PermissionFreshnessService.class);

  static final String METRIC_CHECK = "nexus.rbac.epoch.check";
  static final String METRIC_CHECK_LATENCY = "nexus.rbac.epoch.check.latency";

  private final PermissionEpochPort epochPort;
  private final Map<FreshnessVerdict, Counter> outcomeCounters;
  private final Timer checkLatency;

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
  }

  /**
   * Returns the epoch to embed in a token about to be minted.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the current epoch; {@code 0} when none is stored or the store cannot answer (a token
   *     minted with 0 against a later-recovered epoch is rejected once, which is safe)
   */
  public long epochForMint(UUID tenantId, UUID userId) {
    return epochPort.current(tenantId, userId).orElse(0L);
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
   */
  public void invalidateUser(UUID tenantId, UUID userId) {
    try {
      epochPort.bump(tenantId, List.of(userId));
    } catch (DataAccessException e) {
      log.atError()
          .addKeyValue("event", "RBAC_EPOCH_BUMP_FAILED")
          .addKeyValue("operation", "revoke")
          .addKeyValue("tenantId", tenantId)
          .addKeyValue("userCount", 1)
          .addKeyValue("exception", e.getClass().getSimpleName())
          .log("Permission epoch bump failed");
    }
  }
}
