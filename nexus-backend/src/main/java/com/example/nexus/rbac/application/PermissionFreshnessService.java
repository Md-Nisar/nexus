package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Token-freshness policy for the per-user permission epoch (US-018 A9, design §9.1 to §9.3).
 *
 * <ul>
 *   <li>{@link #epochForMint} is read by the token minter <b>before</b> it resolves permissions
 *       (MC-7a), so a bump racing the mint yields "old epoch, new permissions" (rejected once,
 *       safe) and never "new epoch, old permissions".
 *   <li>{@link #check} runs once per non-public authenticated request. A single failed or slow
 *       read fails open for that request only and is counted as {@code skipped_error}; three
 *       failures within 10 s move the instance into the outage state machine (design §9.5, below).
 *   <li>{@link #invalidateUser} and {@link #invalidateHolders} must only be called after the
 *       permission-reducing transaction commits (MC-7b); bumping earlier lets a mint in the gap
 *       read the new epoch with pre-commit permissions.
 * </ul>
 *
 * <p>Signals: {@code nexus.rbac.epoch.check{outcome}} and {@code nexus.rbac.epoch.check.latency}
 * (p50/p95/p99), the hot-path budget being p95 at most 2 ms (design §9.5); {@code
 * nexus.rbac.epoch.fanout{holders}} per holder fan-out, bucketed, with no tenant tag (§9.4). Bump
 * failures never touch the check outcomes (RC-53); see the replay queue below.
 *
 * <p><b>Outage state machine (T-011, design §9.5).</b> Per instance, driven by the injected
 * {@link Clock}: {@link DegradedState#HEALTHY} to {@link DegradedState#DEGRADED_OPEN} on 3 or more
 * epoch-read or probe failures within a 10 s sliding window ({@code t0} is the first of them); to
 * {@link DegradedState#DEGRADED_CLOSED} once {@code fail-open-window} has elapsed since {@code t0};
 * to {@link DegradedState#RECOVERING} on a probe success with the replay queue drained; back to
 * {@link DegradedState#HEALTHY}, clearing {@code t0}, after {@code
 * recovery-sustain} without a counted failure. A relapse in Recovering uses the same 3-in-10 s
 * rule and keeps {@code t0}. Only epoch-read and probe failures count (RC-53): bump and drain
 * failures never do, and a drain failure in Recovering does not restart the sustain (L-4). A read
 * that returns empty because the adapter is not ready yet is a read failure. All transitions run
 * under one lock, so request threads and the scheduler cannot lose a relapse.
 *
 * <p><b>Lost-bump replay (T-012, design §9.3).</b> A bump that Redis refuses is queued in a
 * bounded, coalescing {@link EpochReplayQueue} ({@code replay-capacity-users}) and replayed by the
 * scheduled task on every tick in every state: in {@link DegradedState#HEALTHY} straight away, in
 * a degraded state only after that tick's probe succeeded. Replay runs in batches of {@value
 * #FANOUT_BATCH_SIZE}; a failed batch goes back with its original {@code failedAt}; entries older
 * than {@code key-ttl-seconds} are dropped. Signals: {@code nexus.rbac.epoch.bump_failed{operation,
 * reason=redis|overflow}}, {@code nexus.rbac.epoch.bump_replayed} (users replayed) and the gauge
 * {@code nexus.rbac.epoch.replay_queue_users}; ERROR {@code RBAC_EPOCH_BUMP_FAILED} and INFO
 * {@code RBAC_EPOCH_BUMP_REPLAYED}, never with user ids.
 *
 * <p><b>Locally known bumps (security review M-1).</b> While reads fail, an attacker who drives
 * the instance into fail-open could replay a revoked token. The service therefore keeps a bounded
 * per-instance map of the highest epoch it has seen per user (from successful reads and from its
 * own successful bumps), expiring at {@code key-ttl-seconds}. When the store cannot answer, or the
 * instance is degraded-open, a token below that epoch is {@link FreshnessVerdict#STALE}. The map
 * holds only users with an epoch above 0, that is, users bumped within the key TTL. It holds at
 * most {@value #LAST_SEEN_CAPACITY} entries; a new user beyond that is not recorded and counted in
 * {@code nexus.rbac.epoch.last_seen_dropped}. A local bump records {@code max(seen + 1, local ms)}:
 * with a local clock ahead of the store, a fresh token can be refused once; the refresh then mints
 * with the recorded value and is accepted.
 */
@Service
public final class PermissionFreshnessService {

  private static final Logger log = LoggerFactory.getLogger(PermissionFreshnessService.class);

  static final String METRIC_CHECK = "nexus.rbac.epoch.check";
  static final String METRIC_CHECK_LATENCY = "nexus.rbac.epoch.check.latency";
  static final String METRIC_FANOUT = "nexus.rbac.epoch.fanout";
  static final String METRIC_DEGRADED = "nexus.rbac.epoch.degraded";
  static final String METRIC_DEGRADED_ENTRIES = "nexus.rbac.epoch.degraded_entries";
  static final String METRIC_DEGRADED_FLAP = "nexus.rbac.epoch.degraded_flap";
  static final String METRIC_LAST_SEEN_DROPPED = "nexus.rbac.epoch.last_seen_dropped";
  static final String METRIC_BUMP_FAILED = "nexus.rbac.epoch.bump_failed";
  static final String METRIC_BUMP_REPLAYED = "nexus.rbac.epoch.bump_replayed";
  static final String METRIC_REPLAY_QUEUE = "nexus.rbac.epoch.replay_queue_users";

  private static final String REASON_REDIS = "redis";
  private static final String REASON_OVERFLOW = "overflow";
  private static final String OPERATION_REPLAY = "replay";

  /** Entries into a degraded state within {@link #FLAP_WINDOW} that raise the flap signal. */
  static final int FLAP_ENTRIES = 3;

  static final Duration FLAP_WINDOW = Duration.ofMinutes(15);

  /** Upper bound of the locally-seen epoch map (security review M-1). */
  static final int LAST_SEEN_CAPACITY = 100_000;

  private static final String INSTANCE = System.getenv().getOrDefault("HOSTNAME", "unknown");

  /** Users per bump script call (design §9.4); sized for the 500 ms bump timeout. */
  static final int FANOUT_BATCH_SIZE = 500;

  /** Above this many holders a fan-out logs {@code RBAC_EPOCH_FANOUT_LARGE}. */
  static final int FANOUT_LARGE_THRESHOLD = 1000;

  private static final String LOG_KEY_EVENT = "event";
  private static final String LOG_KEY_OPERATION = "operation";
  private static final String LOG_KEY_TENANT_ID = "tenantId";
  private static final String LOG_KEY_INSTANCE = "instance";
  private static final String LOG_KEY_CAUSE = "cause";
  private static final String LOG_KEY_STATE = "state";
  private static final String LOG_KEY_USER_COUNT = "userCount";

  private final PermissionEpochPort epochPort;
  private final BiFunction<String, String, Counter> bumpFailedCounters;
  private final Clock clock;
  private final Duration failOpenWindow;
  private final int entryFailureThreshold;
  private final Duration entryFailureWindow;
  private final Duration recoverySustain;
  private final Duration lastSeenTtl;
  private final Map<FreshnessVerdict, Counter> outcomeCounters;
  private final Timer checkLatency;
  private final Map<String, Counter> fanoutCounters;
  private final Counter degradedEntries;
  private final Counter degradedFlaps;
  private final Counter lastSeenDropped;
  private final Counter bumpReplayed;
  private final EpochReplayQueue replayQueue;
  private final Map<UserKey, SeenEpoch> lastSeen = new ConcurrentHashMap<>();

  // State machine. Every field below is written only while holding `lock`; `state` is volatile so
  // the Healthy fast path reads it without the lock.
  private final Object lock = new Object();
  private volatile DegradedState state = DegradedState.HEALTHY;
  private Instant t0;
  private Instant recoverySince;
  private final Deque<Instant> recentFailures = new ArrayDeque<>();
  private final Deque<Instant> recentEntries = new ArrayDeque<>();

  /**
   * Creates the service.
   *
   * @param epochPort the epoch store
   * @param meterRegistry registry for the signals listed on the class
   * @param clock the time source of the state machine and the locally-seen map
   * @param failOpenWindow {@code nexus.rbac.epoch.fail-open-window}: time from {@code t0} until
   *     degraded-open becomes degraded-closed
   * @param entryFailureThreshold {@code nexus.rbac.epoch.entry-failure-threshold}: failures in
   *     the window that enter (or relapse into) a degraded state
   * @param entryFailureWindow {@code nexus.rbac.epoch.entry-failure-window}: the sliding window
   * @param recoverySustain {@code nexus.rbac.epoch.recovery-sustain}: failure-free time in
   *     Recovering before Healthy
   * @param keyTtlSeconds {@code nexus.rbac.epoch.key-ttl-seconds}: lifetime of a locally-seen
   *     epoch, equal to the store key's; also the age after which a queued bump is dropped
   * @param replayCapacityUsers {@code nexus.rbac.epoch.replay-capacity-users}: the most distinct
   *     users whose failed bump is queued for replay
   * @throws IllegalArgumentException if the threshold is below 1 or a duration is not positive
   */
  public PermissionFreshnessService(
      PermissionEpochPort epochPort,
      MeterRegistry meterRegistry,
      Clock clock,
      @Value("${nexus.rbac.epoch.fail-open-window}") Duration failOpenWindow,
      @Value("${nexus.rbac.epoch.entry-failure-threshold}") int entryFailureThreshold,
      @Value("${nexus.rbac.epoch.entry-failure-window}") Duration entryFailureWindow,
      @Value("${nexus.rbac.epoch.recovery-sustain}") Duration recoverySustain,
      @Value("${nexus.rbac.epoch.key-ttl-seconds}") long keyTtlSeconds,
      @Value("${nexus.rbac.epoch.replay-capacity-users}") int replayCapacityUsers) {
    if (entryFailureThreshold < 1
        || !failOpenWindow.isPositive()
        || !entryFailureWindow.isPositive()
        || !recoverySustain.isPositive()
        || keyTtlSeconds < 1
        || replayCapacityUsers < 1) {
      throw new IllegalArgumentException("permission epoch outage policy settings must be positive");
    }
    this.epochPort = epochPort;
    // Operation is a caller-supplied label, so the counter is looked up per call (get or create).
    this.bumpFailedCounters = (operation, reason) -> Counter.builder(METRIC_BUMP_FAILED)
        .description("Failed permission-epoch bumps and replays; overflow counts dropped users")
        .tag(LOG_KEY_OPERATION, operation)
        .tag("reason", reason)
        .register(meterRegistry);
    this.clock = clock;
    this.failOpenWindow = failOpenWindow;
    this.entryFailureThreshold = entryFailureThreshold;
    this.entryFailureWindow = entryFailureWindow;
    this.recoverySustain = recoverySustain;
    this.lastSeenTtl = Duration.ofSeconds(keyTtlSeconds);
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
    for (DegradedState degraded : List.of(
        DegradedState.DEGRADED_OPEN, DegradedState.DEGRADED_CLOSED, DegradedState.RECOVERING)) {
      Gauge.builder(METRIC_DEGRADED, () -> state == degraded ? 1.0 : 0.0)
          .description("1 while this instance is in the given outage state (design §9.5)")
          .tag(LOG_KEY_STATE, degraded.tag())
          .strongReference(true)
          .register(meterRegistry);
    }
    this.degradedEntries = Counter.builder(METRIC_DEGRADED_ENTRIES)
        .description("Entries of this instance into a degraded state, relapses included")
        .register(meterRegistry);
    this.degradedFlaps = Counter.builder(METRIC_DEGRADED_FLAP)
        .description("Degraded entries that made 3 or more within 15 minutes")
        .register(meterRegistry);
    this.lastSeenDropped = Counter.builder(METRIC_LAST_SEEN_DROPPED)
        .description("Locally-seen epochs not recorded because the bounded map was full")
        .register(meterRegistry);
    this.replayQueue = new EpochReplayQueue(replayCapacityUsers);
    this.bumpReplayed = Counter.builder(METRIC_BUMP_REPLAYED)
        .description("Users whose lost permission-epoch bump was replayed")
        .register(meterRegistry);
    Gauge.builder(METRIC_REPLAY_QUEUE, replayQueue::size)
        .description("Users whose permission-epoch bump failed and awaits replay on this instance")
        .strongReference(true)
        .register(meterRegistry);
  }

  /** Returns the outage state of this instance. */
  public DegradedState state() {
    return state;
  }

  /**
   * Returns the epoch to embed in a token about to be minted.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the current epoch; when the store cannot answer (after one retry, or at once while
   *     degraded) the epoch this instance last saw for the user, else {@code 0} (a token minted
   *     with a lower epoch than a later-recovered one is rejected once, which is safe)
   */
  public long epochForMint(UUID tenantId, UUID userId) {
    UserKey key = new UserKey(tenantId, userId);
    Instant now = clock.instant();
    // A degraded instance does not spend 50 ms per read on a store it knows is down; the probe
    // finds out when it is back. Minting with the epoch seen last is safe: a later bump makes the
    // token stale once. Mint reads never count towards the state machine (design §9.5).
    DegradedState current = refreshState(now);
    if (current == DegradedState.DEGRADED_OPEN || current == DegradedState.DEGRADED_CLOSED) {
      return lastSeenEpoch(key, now).orElse(0L);
    }
    // One retry: a single 50 ms read failure would otherwise mint perm_epoch=0 for a recently
    // revoked user, who is then rejected, refreshes and is rejected again.
    OptionalLong read = epochPort.current(tenantId, userId);
    if (read.isEmpty()) {
      read = epochPort.current(tenantId, userId);
    }
    if (read.isPresent()) {
      remember(key, read.getAsLong(), now);
      return read.getAsLong();
    }
    return lastSeenEpoch(key, now).orElse(0L);
  }

  /**
   * Checks whether a token epoch is still current.
   *
   * @param tenantId the token's tenant
   * @param userId the token's subject
   * @param tokenEpoch the token's {@code perm_epoch} ({@code 0} for a v2 token)
   * @return {@link FreshnessVerdict#STALE} iff {@code tokenEpoch} is lower than the stored epoch,
   *     or, when the store cannot answer or the instance is degraded-open, lower than the epoch
   *     this instance last saw; {@link FreshnessVerdict#SKIPPED_ERROR} when the store could not
   *     answer; {@link FreshnessVerdict#SKIPPED_DEGRADED} while degraded-open; {@link
   *     FreshnessVerdict#UNAVAILABLE} while degraded-closed, for the caller to turn into a 503
   */
  public FreshnessVerdict check(UUID tenantId, UUID userId, long tokenEpoch) {
    Timer.Sample sample = Timer.start();
    FreshnessVerdict verdict = evaluate(new UserKey(tenantId, userId), tokenEpoch);
    sample.stop(checkLatency);
    outcomeCounters.get(verdict).increment();
    return verdict;
  }

  private FreshnessVerdict evaluate(UserKey key, long tokenEpoch) {
    Instant now = clock.instant();
    return switch (refreshState(now)) {
      case DEGRADED_CLOSED -> FreshnessVerdict.UNAVAILABLE;
      case DEGRADED_OPEN -> unverified(key, tokenEpoch, FreshnessVerdict.SKIPPED_DEGRADED, now);
      case HEALTHY, RECOVERING -> {
        OptionalLong current = epochPort.current(key.tenantId(), key.userId());
        if (current.isEmpty()) {
          // Also an adapter that is not connected yet: it answers empty at once (design §9.5).
          recordReadFailure(now);
          yield unverified(key, tokenEpoch, FreshnessVerdict.SKIPPED_ERROR, now);
        }
        recordReadSuccess(now);
        remember(key, current.getAsLong(), now);
        yield tokenEpoch < current.getAsLong() ? FreshnessVerdict.STALE : FreshnessVerdict.FRESH;
      }
    };
  }

  /** The verdict when the store was not consulted: stale if this instance already saw a bump. */
  private FreshnessVerdict unverified(
      UserKey key, long tokenEpoch, FreshnessVerdict fallback, Instant now) {
    OptionalLong seen = lastSeenEpoch(key, now);
    return seen.isPresent() && tokenEpoch < seen.getAsLong() ? FreshnessVerdict.STALE : fallback;
  }

  /**
   * One tick of the scheduler, once a second (design §9.3, §9.5). Replays queued bumps in every
   * state. While Healthy that is all it does. In a degraded state it first probes the store: a
   * failure counts like a failed read (RC-53) and ends the tick; a success is followed by the
   * replay and then moves to Recovering (once the queue is empty), or from Recovering towards
   * Healthy. A replay failure never counts and never restarts the sustain (RC-53, L-4).
   */
  @Scheduled(fixedDelay = 1, timeUnit = TimeUnit.SECONDS)
  public void probe() {
    if (refreshState(clock.instant()) == DegradedState.HEALTHY) {
      drainReplayQueue();
      return;
    }
    boolean answered = epochPort.probe();
    Instant now = clock.instant();
    if (!answered) {
      recordReadFailure(now);
      return;
    }
    drainReplayQueue();
    recordProbeSuccess(now);
  }

  // --- state machine; every method below takes the lock (the fast paths read `state` first) ---

  /** Applies the time-driven DegradedOpen to DegradedClosed transition, and returns the state. */
  private DegradedState refreshState(Instant now) {
    if (state != DegradedState.DEGRADED_OPEN) {
      return state;
    }
    synchronized (lock) {
      if (state == DegradedState.DEGRADED_OPEN && windowElapsed(now)) {
        moveTo(DegradedState.DEGRADED_CLOSED, "window_elapsed", false, now);
      }
      return state;
    }
  }

  private boolean windowElapsed(Instant now) {
    return !Duration.between(t0, now).minus(failOpenWindow).isNegative();
  }

  private void recordReadFailure(Instant now) {
    synchronized (lock) {
      DegradedState current = state;
      if (current != DegradedState.HEALTHY && current != DegradedState.RECOVERING) {
        return;
      }
      if (current == DegradedState.RECOVERING) {
        recoverySince = now;
      }
      while (!recentFailures.isEmpty()
          && !Duration.between(recentFailures.peekFirst(), now).minus(entryFailureWindow)
              .isNegative()) {
        recentFailures.removeFirst();
      }
      recentFailures.addLast(now);
      if (recentFailures.size() < entryFailureThreshold) {
        return;
      }
      Instant firstOfWindow = recentFailures.peekFirst();
      recentFailures.clear();
      if (current == DegradedState.HEALTHY) {
        t0 = firstOfWindow;
        moveTo(DegradedState.DEGRADED_OPEN, "read_failures", true, now);
      } else {
        moveTo(
            windowElapsed(now) ? DegradedState.DEGRADED_CLOSED : DegradedState.DEGRADED_OPEN,
            "relapse",
            true,
            now);
      }
    }
  }

  private void recordReadSuccess(Instant now) {
    if (state != DegradedState.RECOVERING) {
      return;
    }
    synchronized (lock) {
      if (state == DegradedState.RECOVERING
          && !Duration.between(recoverySince, now).minus(recoverySustain).isNegative()) {
        t0 = null;
        recentFailures.clear();
        moveTo(DegradedState.HEALTHY, "sustained_health", false, now);
      }
    }
  }

  private void recordProbeSuccess(Instant now) {
    synchronized (lock) {
      switch (state) {
        case DEGRADED_OPEN, DEGRADED_CLOSED -> {
          if (drainComplete()) {
            recoverySince = now;
            recentFailures.clear();
            moveTo(DegradedState.RECOVERING, "probe_succeeded", false, now);
          }
        }
        case RECOVERING -> recordReadSuccess(now);
        case HEALTHY -> { }
      }
    }
  }

  /** The lost-bump replay queue is empty. */
  private boolean drainComplete() {
    return replayQueue.isEmpty();
  }

  /** Must hold {@code lock}. */
  private void moveTo(DegradedState target, String cause, boolean entry, Instant now) {
    DegradedState from = state;
    state = target;
    if (target == DegradedState.HEALTHY) {
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_DEGRADED_EXIT")
          .addKeyValue(LOG_KEY_INSTANCE, INSTANCE)
          .addKeyValue(LOG_KEY_CAUSE, cause)
          .log("Permission epoch checks healthy again");
      return;
    }
    if (target == DegradedState.RECOVERING) {
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_DEGRADED_RECOVERING")
          .addKeyValue(LOG_KEY_INSTANCE, INSTANCE)
          .addKeyValue(LOG_KEY_CAUSE, cause)
          .log("Permission epoch store answers again, confirming health");
      return;
    }
    log.atWarn()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_DEGRADED_ENTER")
        .addKeyValue(LOG_KEY_INSTANCE, INSTANCE)
        .addKeyValue(LOG_KEY_CAUSE, cause)
        .addKeyValue(LOG_KEY_STATE, target.tag())
        .addKeyValue("from", from.tag())
        .log("Permission epoch checks degraded");
    if (entry) {
      degradedEntries.increment();
      recordEntry(now);
    }
  }

  /** Must hold {@code lock}. */
  private void recordEntry(Instant now) {
    while (!recentEntries.isEmpty()
        && !Duration.between(recentEntries.peekFirst(), now).minus(FLAP_WINDOW).isNegative()) {
      recentEntries.removeFirst();
    }
    recentEntries.addLast(now);
    if (recentEntries.size() >= FLAP_ENTRIES) {
      degradedFlaps.increment();
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_DEGRADED_FLAP")
          .addKeyValue(LOG_KEY_INSTANCE, INSTANCE)
          .addKeyValue("entries", recentEntries.size())
          .log("Permission epoch checks keep degrading");
    }
  }

  // --- locally-seen epochs (security review M-1) ---

  private OptionalLong lastSeenEpoch(UserKey key, Instant now) {
    SeenEpoch seen = lastSeen.get(key);
    if (seen == null) {
      return OptionalLong.empty();
    }
    if (!now.isBefore(seen.expiresAt())) {
      lastSeen.remove(key, seen);
      return OptionalLong.empty();
    }
    return OptionalLong.of(seen.epoch());
  }

  /** Keeps the highest epoch seen; epoch 0 (no bump within the key TTL) is not worth a slot. */
  private void remember(UserKey key, long epoch, Instant now) {
    if (epoch <= 0) {
      return;
    }
    if (lastSeen.size() >= LAST_SEEN_CAPACITY && !lastSeen.containsKey(key)) {
      lastSeen.entrySet().removeIf(e -> !now.isBefore(e.getValue().expiresAt()));
      if (lastSeen.size() >= LAST_SEEN_CAPACITY) {
        lastSeenDropped.increment();
        return;
      }
    }
    lastSeen.merge(
        key,
        new SeenEpoch(epoch, now.plus(lastSeenTtl)),
        (old, fresh) -> fresh.epoch() > old.epoch() ? fresh : old);
  }

  /** After this instance's own successful bump: the same formula the store uses, local time. */
  private void rememberBump(UUID tenantId, Collection<UUID> userIds) {
    Instant now = clock.instant();
    for (UUID userId : userIds) {
      UserKey key = new UserKey(tenantId, userId);
      long seen = lastSeenEpoch(key, now).orElse(0L);
      remember(key, Math.max(seen + 1, now.toEpochMilli()), now);
    }
  }

  private record UserKey(UUID tenantId, UUID userId) {}

  private record SeenEpoch(long epoch, Instant expiresAt) {}

  /**
   * Makes every token of a user minted so far stale. Post-commit only (MC-7b).
   *
   * <p>A store failure is logged as {@code RBAC_EPOCH_BUMP_FAILED}, queued for replay and not
   * rethrown: the change has already committed, so an exception here would only turn the
   * administrator's success into an error.
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
      rememberBump(tenantId, List.of(userId));
    } catch (RuntimeException e) {
      // Not only DataAccessException: a stopped factory or a bad script result must not turn a
      // committed change into a 500 either.
      bumpFailed(tenantId, operation, List.of(userId), e);
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
        rememberBump(tenantId, batch);
      } catch (RuntimeException e) {
        // The failed batch and every batch not yet sent (design §9.3).
        bumpFailed(tenantId, operation, holders.subList(from, holders.size()), e);
        return;
      }
    }
  }

  /** Counts and logs a failed bump, then queues the users for replay (design §9.3). */
  private void bumpFailed(
      UUID tenantId, String operation, List<UUID> userIds, RuntimeException e) {
    bumpFailedCounter(operation, REASON_REDIS).increment();
    log.atError()
        .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_FAILED")
        .addKeyValue(LOG_KEY_OPERATION, operation)
        .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
        .addKeyValue(LOG_KEY_USER_COUNT, userIds.size())
        .addKeyValue("exception", e.getClass().getSimpleName())
        .log("Permission epoch bump failed");
    int dropped = replayQueue.offer(tenantId, userIds, clock.instant());
    if (dropped > 0) {
      bumpFailedCounter(operation, REASON_OVERFLOW).increment(dropped);
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_FAILED")
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue(LOG_KEY_USER_COUNT, dropped)
          .addKeyValue("reason", REASON_OVERFLOW)
          .log("Permission epoch bump dropped, replay queue full");
    }
  }

  private Counter bumpFailedCounter(String operation, String reason) {
    return bumpFailedCounters.apply(operation, reason);
  }

  /**
   * Replays queued bumps in batches of {@value #FANOUT_BATCH_SIZE} until the queue is empty or a
   * batch fails. A failed batch goes back with its original {@code failedAt}; what was not yet
   * polled stays queued. Called only from the scheduler.
   */
  private void drainReplayQueue() {
    while (!replayQueue.isEmpty()) {
      Instant now = clock.instant();
      Optional<EpochReplayQueue.Batch> polled =
          replayQueue.poll(FANOUT_BATCH_SIZE, now.minus(lastSeenTtl));
      if (polled.isEmpty()) {
        return;
      }
      EpochReplayQueue.Batch batch = polled.get();
      List<UUID> userIds = batch.userIds();
      try {
        epochPort.bump(batch.tenantId(), userIds);
      } catch (RuntimeException e) {
        replayQueue.requeue(batch);
        bumpFailedCounter(OPERATION_REPLAY, REASON_REDIS).increment();
        log.atError()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_FAILED")
            .addKeyValue(LOG_KEY_OPERATION, OPERATION_REPLAY)
            .addKeyValue(LOG_KEY_TENANT_ID, batch.tenantId())
            .addKeyValue(LOG_KEY_USER_COUNT, userIds.size())
            .addKeyValue("exception", e.getClass().getSimpleName())
            .log("Permission epoch replay failed");
        return;
      }
      rememberBump(batch.tenantId(), userIds);
      bumpReplayed.increment(userIds.size());
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_REPLAYED")
          .addKeyValue(LOG_KEY_TENANT_ID, batch.tenantId())
          .addKeyValue(LOG_KEY_USER_COUNT, userIds.size())
          .addKeyValue("ageMs", Duration.between(batch.oldestFailedAt(), now).toMillis())
          .log("Permission epoch bump replayed");
    }
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
