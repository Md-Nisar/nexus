package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.EpochUnparseableException;
import com.example.nexus.rbac.application.port.out.PermissionEpochPort;
import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PreDestroy;
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
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
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
 * #FANOUT_BATCH_SIZE}; a failed batch goes back with its original failure times; a user is dropped
 * only once their <b>newest</b> lost bump is older than {@code key-ttl-seconds} (M-1). Signals:
 * {@code nexus.rbac.epoch.bump_failed{operation, reason=redis|overflow|holder_read}}, {@code
 * nexus.rbac.epoch.bump_replayed} (users replayed) and the gauge {@code
 * nexus.rbac.epoch.replay_queue_users}; ERROR {@code RBAC_EPOCH_BUMP_FAILED} and INFO {@code
 * RBAC_EPOCH_BUMP_REPLAYED}, never with user ids.
 *
 * <p><b>Lost holder read (M7 part 2 review M-2).</b> When the post-commit read of a detached
 * role's holders fails twice, {@link #holderReadFailed} queues the role (tenant, role, failure time)
 * in a bounded {@link RoleReplayQueue} ({@code replay-capacity-roles}), coalesced per role. The same
 * scheduler tick, before it drains users, re-reads the role's holders and passes them to {@link
 * #invalidateHolders}, so a failed bump falls into the user queue above. A role whose read keeps
 * failing stays queued until its newest failure is older than {@code key-ttl-seconds}; the first
 * failed read ends that tick's role replay. The read runs on its own thread and is abandoned after
 * one second (the entry is requeued with its original failure time), so a hung
 * database cannot stall the tick's purge, probe and user replay. Signals: the paging counter {@code bump_failed{reason=
 * holder_read}} (kept), {@code bump_failed{operation=role_replay, reason=holder_read}} for a failed
 * tick read, {@code bump_failed{reason=role_overflow}} for a role refused by a full queue, {@code
 * nexus.rbac.epoch.role_replayed} and the gauge {@code nexus.rbac.epoch.role_replay_queue_roles}.
 * The degraded state is left only when both queues are empty.
 *
 * <p><b>Locally known bumps (security review M-1).</b> While reads fail, an attacker who drives
 * the instance into fail-open could replay a revoked token. The service therefore keeps a bounded
 * per-instance map of the highest epoch it has seen per user (from successful reads and from its
 * own bumps), expiring at {@code key-ttl-seconds}. When the store cannot answer, or the
 * instance is degraded-open, a token below that epoch is {@link FreshnessVerdict#STALE}. The map
 * holds only users with an epoch above 0, that is, users bumped within the key TTL. It holds at
 * most {@value #LAST_SEEN_CAPACITY} entries, and one tenant at most {@code
 * last-seen-tenant-percent} of that (M7 part 2 review L-3), so one tenant's large detach cannot
 * crowd the others out. The bounds apply to entries derived from reads: a new such user beyond
 * either is not recorded and counted in {@code nexus.rbac.epoch.last_seen_dropped{reason=
 * tenant_cap|capacity}}. An entry from this instance's own bump lives in a separate pool, bounded
 * per tenant ({@value #LAST_SEEN_BUMP_CEILING_FACTOR} times the tenant's read share) and globally
 * ({@value #LAST_SEEN_BUMP_GLOBAL_LIMIT}), so it is never refused for a read bound; beyond a bound
 * it is dropped ({@code bump_dropped}, paged) and its tenant fails closed (stale while the store
 * cannot answer or the instance is degraded-open) for one key TTL. Expired entries are purged by
 * the scheduled tick, never on a request thread (H-1).
 *
 * <p>A successful bump records exactly the epoch the store wrote and returned (H-2); no instance
 * clock enters the value. A failed bump records the lower bound {@code seen + 1} (L-5): it cannot
 * make a token that the store would accept look stale, and it makes every token the instance has
 * already seen stale during a full outage. A replayed bump records the value the replay wrote.
 *
 * <p>An epoch that the store could not confirm (the read failed or the instance is degraded) is
 * reported by {@link #mintEpoch} as unverified, so the minter does not cache the permission set
 * under it (L-3). A stored value that is not an epoch makes that user's tokens stale and is not
 * counted as a store failure (L-1). It is counted as {@code nexus.rbac.epoch.check{outcome=
 * unparseable}} (the verdict stays {@link FreshnessVerdict#STALE}), and its WARN is logged once per
 * tenant per minute with the number of occurrences it suppressed (M7 part 2 review L-2).
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
  static final String METRIC_ROLE_REPLAYED = "nexus.rbac.epoch.role_replayed";
  static final String METRIC_ROLE_REPLAY_QUEUE = "nexus.rbac.epoch.role_replay_queue_roles";

  private static final String REASON_REDIS = "redis";
  private static final String REASON_OVERFLOW = "overflow";
  private static final String REASON_HOLDER_READ = "holder_read";
  private static final String REASON_ROLE_OVERFLOW = "role_overflow";
  private static final String REASON_TENANT_CAP = "tenant_cap";
  private static final String REASON_CAPACITY = "capacity";
  private static final String OPERATION_REPLAY = "replay";
  private static final String OPERATION_ROLE_REPLAY = "role_replay";
  private static final String TAG_REASON = "reason";
  private static final String OUTCOME_UNPARSEABLE = "unparseable";

  /** Entries into a degraded state within {@link #FLAP_WINDOW} that raise the flap signal. */
  static final int FLAP_ENTRIES = 3;

  static final Duration FLAP_WINDOW = Duration.ofMinutes(15);

  /** Upper bound of the locally-seen epoch map (security review M-1). */
  static final int LAST_SEEN_CAPACITY = 100_000;

  /**
   * Own-bump entries have their own pool, per tenant: at most this multiple of the tenant's
   * read-derived share. No tenant's bumps count against another's, or against the read capacity.
   */
  static final int LAST_SEEN_BUMP_CEILING_FACTOR = 4;

  /** The own-bump pool of all tenants together: memory stays bounded however many tenants bump. */
  static final int LAST_SEEN_BUMP_GLOBAL_LIMIT = 2 * LAST_SEEN_CAPACITY;

  /** Most tenants remembered as having lost an own bump; beyond it every tenant fails closed. */
  static final int LOST_TENANTS_MAX = 1000;

  /** The role replay's holder read must answer within this, or the tick moves on. */
  static final Duration ROLE_READ_TIMEOUT = Duration.ofSeconds(1);

  /** One {@code RBAC_EPOCH_UNPARSEABLE} WARN per tenant per this window (L-2). */
  static final Duration UNPARSEABLE_WARN_WINDOW = Duration.ofMinutes(1);

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
  private static final String LOG_KEY_ROLE_ID = "roleId";

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
  private final Counter lastSeenDroppedTenantCap;
  private final Counter lastSeenDroppedCapacity;
  private final Counter lastSeenDroppedBump;
  private final Counter bumpReplayed;
  private final Counter rolesReplayed;
  private final Counter unparseableCounter;
  private final Counter storeRegressedCounter;
  private final EpochReplayQueue replayQueue;
  private final RoleReplayQueue roleReplayQueue;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final int lastSeenTenantCap;
  private final Map<UserKey, SeenEpoch> lastSeen = new ConcurrentHashMap<>();
  // Slot accounting, two pools. Every change happens inside lastSeen.compute for the entry's key,
  // or after the remove(k, v) that really removed it, so the counters follow the map exactly.
  private final Map<UUID, Integer> readsPerTenant = new ConcurrentHashMap<>();
  private final Map<UUID, Integer> bumpsPerTenant = new ConcurrentHashMap<>();
  private final AtomicInteger readTotal = new AtomicInteger();
  private final AtomicInteger bumpTotal = new AtomicInteger();
  // Tenants whose own bump could not be recorded (ceiling or global bound), until when. Bounded by
  // LOST_TENANTS_MAX; past it `lostAllUntil` makes every tenant fail closed instead.
  private final Map<UUID, Instant> lostRevocations = new ConcurrentHashMap<>();
  private volatile Instant lostAllUntil = Instant.MIN;
  private final int lastSeenBumpCeiling;
  private final ExecutorService roleReadExecutor;
  private volatile RoleRead currentRoleRead;
  private final Map<UUID, UnparseableWindow> unparseableWindows = new ConcurrentHashMap<>();

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
   * @param userRoleAssignmentPort reads a role's holders when the tick resolves a queued role
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
   * @param replayCapacityRoles {@code nexus.rbac.epoch.replay-capacity-roles}: the most distinct
   *     roles whose holder read is queued for replay
   * @param lastSeenTenantPercent {@code nexus.rbac.epoch.last-seen-tenant-percent}: the share of
   *     the locally-seen map one tenant may fill, 1 to 100
   * @throws IllegalArgumentException if the threshold is below 1, a duration is not positive or
   *     the percentage is outside 1 to 100
   */
  public PermissionFreshnessService(
      PermissionEpochPort epochPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      MeterRegistry meterRegistry,
      Clock clock,
      @Value("${nexus.rbac.epoch.fail-open-window}") Duration failOpenWindow,
      @Value("${nexus.rbac.epoch.entry-failure-threshold}") int entryFailureThreshold,
      @Value("${nexus.rbac.epoch.entry-failure-window}") Duration entryFailureWindow,
      @Value("${nexus.rbac.epoch.recovery-sustain}") Duration recoverySustain,
      @Value("${nexus.rbac.epoch.key-ttl-seconds}") long keyTtlSeconds,
      @Value("${nexus.rbac.epoch.replay-capacity-users}") int replayCapacityUsers,
      @Value("${nexus.rbac.epoch.replay-capacity-roles:1000}") int replayCapacityRoles,
      @Value("${nexus.rbac.epoch.last-seen-tenant-percent:10}") int lastSeenTenantPercent) {
    if (entryFailureThreshold < 1
        || !failOpenWindow.isPositive()
        || !entryFailureWindow.isPositive()
        || !recoverySustain.isPositive()
        || keyTtlSeconds < 1
        || replayCapacityUsers < 1
        || replayCapacityRoles < 1
        || lastSeenTenantPercent < 1
        || lastSeenTenantPercent > 100) {
      throw new IllegalArgumentException("permission epoch outage policy settings must be positive");
    }
    this.epochPort = epochPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.lastSeenTenantCap = Math.max(1, LAST_SEEN_CAPACITY * lastSeenTenantPercent / 100);
    this.lastSeenBumpCeiling = lastSeenTenantCap * LAST_SEEN_BUMP_CEILING_FACTOR;
    // Operation is a caller-supplied label, so the counter is looked up per call (get or create).
    this.bumpFailedCounters = (operation, reason) -> Counter.builder(METRIC_BUMP_FAILED)
        .description("Failed permission-epoch bumps and replays; overflow counts dropped users")
        .tag(LOG_KEY_OPERATION, operation)
        .tag(TAG_REASON, reason)
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
    this.unparseableCounter = Counter.builder(METRIC_CHECK)
        .description("Request-time permission-epoch checks, by outcome")
        .tag("outcome", OUTCOME_UNPARSEABLE)
        .register(meterRegistry);
    this.storeRegressedCounter = Counter.builder("nexus.rbac.epoch.store_regressed")
        .description("Reads or mints where the store answered below an epoch this instance knows")
        .register(meterRegistry);
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
    this.lastSeenDroppedTenantCap = Counter.builder(METRIC_LAST_SEEN_DROPPED)
        .description("Locally-seen epochs not recorded because a bound of the map was reached")
        .tag(TAG_REASON, REASON_TENANT_CAP)
        .register(meterRegistry);
    this.lastSeenDroppedCapacity = Counter.builder(METRIC_LAST_SEEN_DROPPED)
        .description("Locally-seen epochs not recorded because a bound of the map was reached")
        .tag(TAG_REASON, REASON_CAPACITY)
        .register(meterRegistry);
    this.lastSeenDroppedBump = lastSeenCounter(meterRegistry, "bump_dropped");
    this.roleReadExecutor = Executors.newSingleThreadExecutor(runnable -> {
      Thread thread = new Thread(runnable, "epoch-role-replay-read");
      thread.setDaemon(true);
      return thread;
    });
    this.replayQueue = new EpochReplayQueue(replayCapacityUsers);
    this.roleReplayQueue = new RoleReplayQueue(replayCapacityRoles);
    this.rolesReplayed = Counter.builder(METRIC_ROLE_REPLAYED)
        .description("Roles whose holders were read and bumped by the tick after a failed read")
        .register(meterRegistry);
    Gauge.builder(METRIC_ROLE_REPLAY_QUEUE, roleReplayQueue::size)
        .description("Roles whose post-commit holder read failed and awaits replay on this instance")
        .strongReference(true)
        .register(meterRegistry);
    this.bumpReplayed = Counter.builder(METRIC_BUMP_REPLAYED)
        .description("Users whose lost permission-epoch bump was replayed")
        .register(meterRegistry);
    Gauge.builder(METRIC_REPLAY_QUEUE, replayQueue::size)
        .description("Users whose permission-epoch bump failed and awaits replay on this instance")
        .strongReference(true)
        .register(meterRegistry);
  }

  private static Counter lastSeenCounter(MeterRegistry meterRegistry, String reason) {
    return Counter.builder(METRIC_LAST_SEEN_DROPPED)
        .description("Locally-seen epochs not recorded because a bound of the map was reached")
        .tag(TAG_REASON, reason)
        .register(meterRegistry);
  }

  /** Stops the thread that reads role holders for the replay. */
  @PreDestroy
  void shutdown() {
    roleReadExecutor.shutdownNow();
  }

  /** Test hook: a role holder read is running on the replay thread. */
  boolean roleReadInFlight() {
    return roleReadBusy();
  }

  /** Test hook: occupies the replay thread, to leave a role read queued behind it. */
  Future<?> runOnRoleReadThread(Runnable task) {
    return roleReadExecutor.submit(task);
  }

  /** Returns the outage state of this instance. */
  public DegradedState state() {
    return state;
  }

  /**
   * Returns the epoch to embed in a token about to be minted. See {@link #mintEpoch}.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the epoch of {@link #mintEpoch}
   */
  public long epochForMint(UUID tenantId, UUID userId) {
    return mintEpoch(tenantId, userId).epoch();
  }

  /**
   * Returns the epoch to embed in a token about to be minted, and whether the store confirmed it.
   *
   * @param tenantId the user's tenant
   * @param userId the user
   * @return the current epoch, verified; when the store cannot answer (after one retry, or at once
   *     while degraded) the epoch this instance last saw for the user, else {@code 0}, unverified
   *     (a token minted with a lower epoch than a later-recovered one is rejected once, which is
   *     safe). A stored value that is not an epoch yields {@code 0}, unverified
   */
  public MintEpoch mintEpoch(UUID tenantId, UUID userId) {
    UserKey key = new UserKey(tenantId, userId);
    Instant now = clock.instant();
    // A degraded instance does not spend 50 ms per read on a store it knows is down; the probe
    // finds out when it is back. Minting with the epoch seen last is safe: a later bump makes the
    // token stale once. Mint reads never count towards the state machine (design §9.5).
    DegradedState current = refreshState(now);
    if (current == DegradedState.DEGRADED_OPEN || current == DegradedState.DEGRADED_CLOSED) {
      return unverifiedMint(key, now);
    }
    try {
      // One retry: a single 50 ms read failure would otherwise mint perm_epoch=0 for a recently
      // revoked user, who is then rejected, refreshes and is rejected again.
      OptionalLong read = epochPort.current(tenantId, userId);
      if (read.isEmpty()) {
        read = epochPort.current(tenantId, userId);
      }
      if (read.isPresent()) {
        remember(key, read.getAsLong(), now, false);
        // The store answered, but below what this instance knows, or while a bump this instance
        // could not write is still owed: do not vouch for the store's value (M-1). The token
        // carries the local bound and the permission set is resolved uncached, because the
        // epoch-keyed cache entry was never deleted.
        SeenEpoch known = lastSeenEntry(key, now);
        if (known != null && (known.epoch() > read.getAsLong() || known.failedBumpAt() != null)) {
          if (known.epoch() > read.getAsLong()) {
            storeRegressedCounter.increment();
          }
          return new MintEpoch(Math.max(known.epoch(), read.getAsLong()), false);
        }
        return new MintEpoch(read.getAsLong(), true);
      }
    } catch (EpochUnparseableException e) {
      logUnparseable(tenantId, now);
      return new MintEpoch(0L, false);
    }
    return unverifiedMint(key, now);
  }

  private MintEpoch unverifiedMint(UserKey key, Instant now) {
    return new MintEpoch(lastSeenEpoch(key, now).orElse(0L), false);
  }

  /**
   * The epoch for a token about to be minted.
   *
   * @param epoch the epoch to embed
   * @param verified whether the store confirmed it; when not, the minter must not cache the
   *     permission set under it, because no bump deletes that key (L-3)
   */
  public record MintEpoch(long epoch, boolean verified) {}

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
    return check(tenantId, userId, tokenEpoch, Long.MAX_VALUE);
  }

  /**
   * As {@link #check(UUID, UUID, long)}, and also {@link FreshnessVerdict#STALE} for a token
   * issued at or before the second of a bump this instance could not write (M-1): the lower bound
   * {@code seen + 1} cannot catch a user this instance had not seen, whose real epochs are Redis
   * time in milliseconds.
   *
   * @param tenantId the token's tenant
   * @param userId the token's subject
   * @param tokenEpoch the token's {@code perm_epoch} ({@code 0} for a v2 token)
   * @param issuedAtSeconds the token's {@code iat} in epoch seconds; {@link Long#MAX_VALUE} when
   *     unknown, which never matches the failed-bump marker
   * @return the verdict of {@link #check(UUID, UUID, long)}
   */
  public FreshnessVerdict check(
      UUID tenantId, UUID userId, long tokenEpoch, long issuedAtSeconds) {
    Timer.Sample sample = Timer.start();
    AtomicBoolean unparseable = new AtomicBoolean();
    FreshnessVerdict verdict =
        evaluate(new UserKey(tenantId, userId), tokenEpoch, issuedAtSeconds, unparseable);
    sample.stop(checkLatency);
    // An unparseable value is STALE for the caller but its own outcome for the operator (L-2).
    (unparseable.get() ? unparseableCounter : outcomeCounters.get(verdict)).increment();
    return verdict;
  }

  private FreshnessVerdict evaluate(
      UserKey key, long tokenEpoch, long issuedAt, AtomicBoolean unparseable) {
    Instant now = clock.instant();
    return switch (refreshState(now)) {
      case DEGRADED_CLOSED -> FreshnessVerdict.UNAVAILABLE;
      case DEGRADED_OPEN ->
          unverified(key, tokenEpoch, issuedAt, FreshnessVerdict.SKIPPED_DEGRADED, now);
      case HEALTHY, RECOVERING -> {
        OptionalLong current;
        try {
          current = epochPort.current(key.tenantId(), key.userId());
        } catch (EpochUnparseableException e) {
          // The store answered; this user's key is corrupt. Not a read failure (L-1), so it never
          // moves the state machine, and the user's tokens cannot be vouched for.
          logUnparseable(key.tenantId(), now);
          unparseable.set(true);
          yield FreshnessVerdict.STALE;
        }
        if (current.isEmpty()) {
          // Also an adapter that is not connected yet: it answers empty at once (design §9.5).
          recordReadFailure(now);
          yield unverified(key, tokenEpoch, issuedAt, FreshnessVerdict.SKIPPED_ERROR, now);
        }
        recordReadSuccess(now);
        remember(key, current.getAsLong(), now, false);
        // The store is not the whole truth (M-1): a bump it refused or lost leaves it below what
        // this instance knows, and its read side keeps answering. The local bound still holds.
        SeenEpoch known = lastSeenEntry(key, now);
        if (known != null && known.epoch() > current.getAsLong()) {
          storeRegressedCounter.increment();
        }
        yield tokenEpoch < current.getAsLong() || staleByLocalKnowledge(known, tokenEpoch, issuedAt)
            ? FreshnessVerdict.STALE
            : FreshnessVerdict.FRESH;
      }
    };
  }

  /**
   * Logs once per tenant per {@link #UNPARSEABLE_WARN_WINDOW}, with the occurrences since the last
   * line (L-2). A corrupt keyspace would otherwise log once per request, twice per refresh loop.
   * The count of every occurrence is {@code nexus.rbac.epoch.check{outcome=unparseable}}.
   */
  private void logUnparseable(UUID tenantId, Instant now) {
    long[] suppressed = {-1};
    unparseableWindows.compute(tenantId, (id, window) -> {
      if (window == null || !now.isBefore(window.endsAt())) {
        suppressed[0] = window == null ? 0 : window.suppressed();
        return new UnparseableWindow(now.plus(UNPARSEABLE_WARN_WINDOW), 0);
      }
      return new UnparseableWindow(window.endsAt(), window.suppressed() + 1);
    });
    if (suppressed[0] >= 0) {
      log.atWarn()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_UNPARSEABLE")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue("suppressed", suppressed[0])
          .log("Stored permission epoch is not a number; treating the user's tokens as stale");
    }
  }

  private record UnparseableWindow(Instant endsAt, long suppressed) {}

  /** The verdict when the store was not consulted: stale if this instance already saw a bump. */
  private FreshnessVerdict unverified(
      UserKey key, long tokenEpoch, long issuedAt, FreshnessVerdict fallback, Instant now) {
    if (staleByLocalKnowledge(lastSeenEntry(key, now), tokenEpoch, issuedAt)) {
      return FreshnessVerdict.STALE;
    }
    return revocationLost(key.tenantId(), now) ? FreshnessVerdict.STALE : fallback;
  }

  /**
   * Whether what this instance knows alone makes the token stale: its epoch is below the highest
   * one seen, or it was issued at or before the second of a bump that could not be written and has
   * not been replayed since. The second is compared whole, so a token issued in the same second as
   * the failure is refused once and refreshed.
   */
  private static boolean staleByLocalKnowledge(SeenEpoch known, long tokenEpoch, long issuedAt) {
    if (known == null) {
      return false;
    }
    return tokenEpoch < known.epoch()
        || (known.failedBumpAt() != null && issuedAt <= known.failedBumpAt().getEpochSecond());
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
    purgeExpiredSeen(clock.instant());
    if (refreshState(clock.instant()) == DegradedState.HEALTHY) {
      drainRoleQueue();
      drainReplayQueue();
      return;
    }
    boolean answered = epochPort.probe();
    if (!answered) {
      recordReadFailure(clock.instant());
      return;
    }
    drainRoleQueue();
    drainReplayQueue();
    // The sustain starts when the drain is done, not when the probe answered (L-2, RC-31.2): a
    // long drain must not let the next read count as sixty seconds of health.
    recordProbeSuccess(clock.instant());
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

  /** Neither the lost-bump replay queue nor the lost-holder-read queue holds anything. */
  private boolean drainComplete() {
    return replayQueue.isEmpty() && roleReplayQueue.isEmpty();
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
    SeenEpoch seen = lastSeenEntry(key, now);
    return seen == null ? OptionalLong.empty() : OptionalLong.of(seen.epoch());
  }

  /** The unexpired entry of the user, or {@code null}; an expired one is removed on the way. */
  private SeenEpoch lastSeenEntry(UserKey key, Instant now) {
    SeenEpoch seen = lastSeen.get(key);
    if (seen == null) {
      return null;
    }
    if (!now.isBefore(seen.expiresAt())) {
      if (lastSeen.remove(key, seen)) {
        release(key.tenantId(), seen.ownBump());
      }
      return null;
    }
    return seen;
  }

  /**
   * Keeps the highest epoch seen; epoch 0 (no bump within the key TTL) is not worth a slot. Never
   * scans the map (H-1). Two pools, so that nothing one tenant does costs another a slot:
   *
   * <ul>
   *   <li><b>Read-derived</b> entries: at most {@value #LAST_SEEN_CAPACITY} in all and {@code
   *       last-seen-tenant-percent} of that per tenant (L-3). A new user beyond either is only
   *       counted ({@code last_seen_dropped{reason=capacity|tenant_cap}}); the tick frees expired
   *       slots.
   *   <li><b>Own-bump</b> entries (this instance's bumps, failed bumps and replays): never subject
   *       to those bounds, because dropping one would let a revoked token through while the store
   *       is down. They are bounded per tenant, at {@value #LAST_SEEN_BUMP_CEILING_FACTOR} times
   *       the tenant's read share, and for all tenants together at {@value
   *       #LAST_SEEN_BUMP_GLOBAL_LIMIT}; beyond either the entry is dropped, counted ({@code
   *       reason=bump_dropped}, paged), and the tenant fails closed for one key TTL (see {@link
   *       #markRevocationLost}), so a lost revocation is never silently accepted.
   * </ul>
   *
   * An entry first derived from a read and then bumped moves to the bump pool.
   */
  private void remember(UserKey key, long epoch, Instant now, boolean ownBump) {
    remember(key, epoch, now, ownBump, null);
  }

  /**
   * As above; {@code failedBumpAt} is the instant of a bump this instance could not write (M-1).
   * The marker stays on the entry until a later epoch at or after that instant is recorded, which
   * only a bump that landed (or a store that has caught up) can produce: the store writes at least
   * Redis time.
   */
  private void remember(
      UserKey key, long epoch, Instant now, boolean ownBump, Instant failedBumpAt) {
    if (epoch <= 0) {
      return;
    }
    SeenEpoch fresh = new SeenEpoch(epoch, now.plus(lastSeenTtl), ownBump, failedBumpAt);
    Counter[] dropped = {null};
    boolean[] moveRefused = {false};
    lastSeen.compute(key, (k, old) -> {
      if (old == null) {
        dropped[0] = claim(k.tenantId(), ownBump);
        return dropped[0] == null ? fresh : null;
      }
      SeenEpoch winner = fresh.epoch() > old.epoch() ? fresh : old;
      boolean bump = old.ownBump();
      if (ownBump && !old.ownBump()) {
        if (claim(k.tenantId(), true) == null) {
          release(k.tenantId(), false);
          bump = true;
        } else {
          // The epoch is still recorded, as a read-derived entry; only the pool move failed.
          moveRefused[0] = true;
        }
      }
      Instant marker = failedBumpAt;
      if (marker == null && old.failedBumpAt() != null
          && fresh.epoch() < old.failedBumpAt().toEpochMilli()) {
        marker = old.failedBumpAt();
      }
      return winner.ownBump() == bump && Objects.equals(winner.failedBumpAt(), marker)
          ? winner
          : new SeenEpoch(winner.epoch(), winner.expiresAt(), bump, marker);
    });
    if (dropped[0] != null) {
      dropped[0].increment();
      if (ownBump && dropped[0] == lastSeenDroppedBump) {
        markRevocationLost(key.tenantId(), now);
      }
    }
    if (moveRefused[0]) {
      lastSeenDroppedBump.increment();
    }
  }

  /**
   * An own bump could not be recorded, so this instance may not know a revocation of the tenant.
   * Fail closed for that tenant for one key TTL: while the store cannot answer, or the instance is
   * degraded-open, its tokens are stale ({@link #unverified}). Logged once per marking.
   */
  private void markRevocationLost(UUID tenantId, Instant now) {
    Instant until = now.plus(lastSeenTtl);
    if (lostRevocations.size() >= LOST_TENANTS_MAX && !lostRevocations.containsKey(tenantId)) {
      lostAllUntil = until;
      return;
    }
    if (lostRevocations.put(tenantId, until) == null) {
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_LAST_SEEN_BUMP_DROPPED")
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue(LOG_KEY_INSTANCE, INSTANCE)
          .log("Own permission epoch bump not recorded locally; tenant fails closed while the "
              + "store is unavailable");
    }
  }

  private boolean revocationLost(UUID tenantId, Instant now) {
    Instant until = lostRevocations.get(tenantId);
    return now.isBefore(lostAllUntil) || (until != null && now.isBefore(until));
  }

  /** Takes a slot of the pool; returns the counter of the reason when it is refused. */
  private Counter claim(UUID tenantId, boolean bump) {
    if (!bump && readTotal.incrementAndGet() > LAST_SEEN_CAPACITY) {
      readTotal.decrementAndGet();
      return lastSeenDroppedCapacity;
    }
    if (bump && bumpTotal.incrementAndGet() > LAST_SEEN_BUMP_GLOBAL_LIMIT) {
      bumpTotal.decrementAndGet();
      return lastSeenDroppedBump;
    }
    int limit = bump ? lastSeenBumpCeiling : lastSeenTenantCap;
    boolean[] claimed = {false};
    (bump ? bumpsPerTenant : readsPerTenant).compute(tenantId, (id, count) -> {
      int held = count == null ? 0 : count;
      if (held >= limit) {
        return count;
      }
      claimed[0] = true;
      return held + 1;
    });
    if (claimed[0]) {
      return null;
    }
    (bump ? bumpTotal : readTotal).decrementAndGet();
    return bump ? lastSeenDroppedBump : lastSeenDroppedTenantCap;
  }

  private void release(UUID tenantId, boolean bump) {
    (bump ? bumpTotal : readTotal).decrementAndGet();
    (bump ? bumpsPerTenant : readsPerTenant)
        .computeIfPresent(tenantId, (id, count) -> count <= 1 ? null : count - 1);
  }

  /**
   * Frees the slots of expired entries, once a second from the scheduler thread (H-1). A slot is
   * released only for an entry this call really removed: an entry that a concurrent write
   * replaced is left, and its slot stays claimed.
   */
  private void purgeExpiredSeen(Instant now) {
    for (Map.Entry<UserKey, SeenEpoch> entry : lastSeen.entrySet()) {
      SeenEpoch seen = entry.getValue();
      if (!now.isBefore(seen.expiresAt()) && lastSeen.remove(entry.getKey(), seen)) {
        release(entry.getKey().tenantId(), seen.ownBump());
      }
    }
    lostRevocations.values().removeIf(until -> !now.isBefore(until));
    // A window that ended a full window ago has nothing left to report (L-2).
    unparseableWindows.values().removeIf(
        window -> !now.isBefore(window.endsAt().plus(UNPARSEABLE_WARN_WINDOW)));
  }

  /** Slot counts per pool; the test hooks compare what the map holds with what the counters say. */
  record SeenCounts(
      Map<UUID, Integer> reads, Map<UUID, Integer> bumps, int readTotal, int bumpTotal) {}

  /** Test hook: how many entries the map really holds. */
  SeenCounts lastSeenCountsFromMap() {
    Map<UUID, Integer> reads = new HashMap<>();
    Map<UUID, Integer> bumps = new HashMap<>();
    int readSum = 0;
    int bumpSum = 0;
    for (Map.Entry<UserKey, SeenEpoch> entry : lastSeen.entrySet()) {
      boolean bump = entry.getValue().ownBump();
      (bump ? bumps : reads).merge(entry.getKey().tenantId(), 1, Integer::sum);
      readSum += bump ? 0 : 1;
      bumpSum += bump ? 1 : 0;
    }
    return new SeenCounts(reads, bumps, readSum, bumpSum);
  }

  /** Test hook: what the slot counters say. */
  SeenCounts lastSeenCountsFromCounters() {
    return new SeenCounts(
        new HashMap<>(readsPerTenant), new HashMap<>(bumpsPerTenant), readTotal.get(),
        bumpTotal.get());
  }

  /**
   * After a successful bump: exactly what the store wrote (H-2). A user the store did not report,
   * which a conforming store never does, gets the lower bound instead.
   */
  private void rememberBump(UUID tenantId, Collection<UUID> userIds, Written written) {
    Instant now = clock.instant();
    for (UUID userId : userIds) {
      UserKey key = new UserKey(tenantId, userId);
      Long epoch = written.epochs().get(userId);
      remember(key, epoch != null ? epoch : lowerBound(key, now), now, true);
    }
  }

  /**
   * After a failed bump (L-5): {@code seen + 1}. It can never exceed what the store holds or will
   * hold, so it cannot make a token the store would accept look stale; it does make stale every
   * token minted below what this instance has seen, and, for a user it has not seen, a token with
   * epoch 0.
   */
  private void rememberFailedBump(UUID tenantId, Collection<UUID> userIds) {
    Instant now = clock.instant();
    for (UUID userId : userIds) {
      UserKey key = new UserKey(tenantId, userId);
      remember(key, lowerBound(key, now), now, true, now);
    }
  }

  private long lowerBound(UserKey key, Instant now) {
    return lastSeenEpoch(key, now).orElse(0L) + 1;
  }

  /** The epochs the store wrote for one bump; a record because application methods take no Map. */
  private record Written(Map<UUID, Long> epochs) {}

  private Written bump(UUID tenantId, Collection<UUID> userIds) {
    return new Written(epochPort.bump(tenantId, userIds));
  }

  private record UserKey(UUID tenantId, UUID userId) {}

  /** {@code failedBumpAt} is non-null while a bump this instance could not write is unreplayed. */
  private record SeenEpoch(long epoch, Instant expiresAt, boolean ownBump, Instant failedBumpAt) {}

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
      rememberBump(tenantId, List.of(userId), bump(tenantId, List.of(userId)));
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
        rememberBump(tenantId, batch, bump(tenantId, batch));
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
    rememberFailedBump(tenantId, userIds);
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

  /**
   * Counts a post-commit holder read that failed after its retry, so a detach whose revocation
   * could not be applied pages an operator ({@code bump_failed{reason=holder_read}}), and queues
   * the role: the scheduler tick reads its holders again and bumps them (M7 part 2 review M-2). A
   * role already queued is coalesced; one refused by a full queue is counted as {@code
   * bump_failed{reason=role_overflow}} and logged.
   *
   * @param tenantId the role's tenant
   * @param roleId the role whose permission set shrank
   * @param operation what shrank the permission set (for example {@code detach})
   */
  public void holderReadFailed(UUID tenantId, UUID roleId, String operation) {
    bumpFailedCounter(operation, REASON_HOLDER_READ).increment();
    if (!roleReplayQueue.offer(tenantId, roleId, clock.instant())) {
      bumpFailedCounter(operation, REASON_ROLE_OVERFLOW).increment();
      log.atError()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_HOLDER_READ_REPLAY_DROPPED")
          .addKeyValue(LOG_KEY_OPERATION, operation)
          .addKeyValue(LOG_KEY_TENANT_ID, tenantId)
          .addKeyValue(LOG_KEY_ROLE_ID, roleId)
          .log("Role holder replay queue full; the revocation of this role needs a manual re-apply");
    }
  }

  private Counter bumpFailedCounter(String operation, String reason) {
    return bumpFailedCounters.apply(operation, reason);
  }

  /**
   * Replays queued bumps in batches of {@value #FANOUT_BATCH_SIZE} until the queue is empty or a
   * batch fails. A failed batch goes back with its original failure times; what was not yet
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
      Written written;
      try {
        written = bump(batch.tenantId(), userIds);
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
      rememberBump(batch.tenantId(), userIds, written);
      bumpReplayed.increment(userIds.size());
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_EPOCH_BUMP_REPLAYED")
          .addKeyValue(LOG_KEY_TENANT_ID, batch.tenantId())
          .addKeyValue(LOG_KEY_USER_COUNT, userIds.size())
          .addKeyValue("ageMs", Duration.between(batch.oldestFailedAt(), now).toMillis())
          .log("Permission epoch bump replayed");
    }
  }

  /**
   * Resolves queued roles: reads each role's holders, outside any transaction of ours, and passes
   * them to {@link #invalidateHolders}, whose failed bumps land in the user queue. The first failed
   * read puts the role back at the end and ends the tick's role replay, so a database outage costs
   * one read and one ERROR line a second. Called only from the scheduler.
   */
  private void drainRoleQueue() {
    while (!roleReplayQueue.isEmpty()) {
      Instant now = clock.instant();
      Optional<RoleReplayQueue.Entry> polled = roleReplayQueue.poll(now.minus(lastSeenTtl));
      if (polled.isEmpty()) {
        return;
      }
      RoleReplayQueue.Entry entry = polled.get();
      List<UUID> holders;
      try {
        holders = readHoldersBounded(entry.roleId());
      } catch (RuntimeException e) {
        roleReplayQueue.requeue(entry);
        bumpFailedCounter(OPERATION_ROLE_REPLAY, REASON_HOLDER_READ).increment();
        log.atError()
            .addKeyValue(LOG_KEY_EVENT, "RBAC_HOLDER_READ_FAILED")
            .addKeyValue(LOG_KEY_OPERATION, OPERATION_ROLE_REPLAY)
            .addKeyValue(LOG_KEY_TENANT_ID, entry.tenantId())
            .addKeyValue(LOG_KEY_ROLE_ID, entry.roleId())
            .addKeyValue("exception", e.getClass().getSimpleName())
            .log("Reading role holders for replay failed");
        return;
      }
      invalidateHolders(entry.tenantId(), holders, OPERATION_ROLE_REPLAY);
      rolesReplayed.increment();
      log.atInfo()
          .addKeyValue(LOG_KEY_EVENT, "RBAC_HOLDER_READ_REPLAYED")
          .addKeyValue(LOG_KEY_TENANT_ID, entry.tenantId())
          .addKeyValue(LOG_KEY_ROLE_ID, entry.roleId())
          .addKeyValue("holderCount", holders.size())
          .addKeyValue("ageMs", Duration.between(entry.oldestFailedAt(), now).toMillis())
          .log("Role holders read and bumped by the replay");
    }
  }

  /**
   * Reads a role's holders on the replay thread and waits at most {@link #ROLE_READ_TIMEOUT}, so a
   * hung database cannot stall the tick's purge, probe and user replay. While an earlier read is
   * still running the thread is busy and this one fails at once rather than queueing behind it.
   *
   * @throws IllegalStateException if the read timed out, is still running from an earlier tick,
   *     or was interrupted; any exception of the read itself is rethrown as thrown
   */
  private List<UUID> readHoldersBounded(UUID roleId) {
    if (roleReadBusy()) {
      throw new IllegalStateException("previous role holder read still running");
    }
    RoleRead tracker = new RoleRead();
    currentRoleRead = tracker;
    Future<List<UUID>> read;
    try {
      read = roleReadExecutor.submit(() -> {
        if (!tracker.state.compareAndSet(RoleRead.PENDING, RoleRead.RUNNING)) {
          return List.<UUID>of(); // abandoned before it started; nobody waits for it
        }
        try {
          return userRoleAssignmentPort.findActiveUserIdsForRole(roleId);
        } finally {
          tracker.state.set(RoleRead.DONE);
        }
      });
    } catch (RuntimeException e) {
      tracker.state.set(RoleRead.DONE);
      throw e;
    }
    try {
      return read.get(ROLE_READ_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      abandon(read, tracker);
      throw new IllegalStateException("role holder read timed out", e);
    } catch (InterruptedException e) {
      abandon(read, tracker);
      Thread.currentThread().interrupt();
      throw new IllegalStateException("role holder read interrupted", e);
    } catch (ExecutionException e) {
      if (e.getCause() instanceof RuntimeException cause) {
        throw cause;
      }
      throw new IllegalStateException("role holder read failed", e.getCause());
    }
  }

  /**
   * Gives up on a read. One that has not started never will, so it no longer blocks the next tick;
   * one that is running keeps the thread busy until it returns, which {@link #roleReadBusy} sees
   * from the tracker's state, not from the future (a cancelled running future reports done).
   */
  private static void abandon(Future<?> read, RoleRead tracker) {
    read.cancel(true);
    tracker.state.compareAndSet(RoleRead.PENDING, RoleRead.ABANDONED);
  }

  private boolean roleReadBusy() {
    RoleRead tracker = currentRoleRead;
    return tracker != null && tracker.state.get() == RoleRead.RUNNING;
  }

  /** Progress of one holder read on the replay thread. */
  private static final class RoleRead {
    static final int PENDING = 0;
    static final int RUNNING = 1;
    static final int DONE = 2;
    static final int ABANDONED = 3;

    final AtomicInteger state = new AtomicInteger(PENDING);
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
