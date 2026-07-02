package com.example.nexus.identity.infrastructure.audit;

import com.example.nexus.identity.application.port.out.AuditAlertPort;
import com.example.nexus.identity.domain.AuditAlert;
import com.example.nexus.identity.domain.AuditAlertType;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.AuthEventType;
import com.example.nexus.identity.infrastructure.persistence.JpaAuthEventRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * US-008 T-08-15 (design §4.2, ADR 0011) — in-process, two-lane, bounded retry buffer for {@code
 * auth_events} writes that fail their primary synchronous insert.
 *
 * <p><b>Two independent lanes</b> ({@link AuditLane#PRIORITY} / {@link AuditLane#STANDARD}), each
 * a fixed-capacity {@link ArrayBlockingQueue}. Routing is via {@code AuthEventType.isPriority()}.
 * A full standard lane can never block, evict from, or otherwise affect the priority lane's
 * capacity, and vice versa — this is the mechanism that closes threat-model finding T-D1 (a
 * login-failure flood can no longer evict a genuine {@code LOCKOUT} event). See ADR 0011 §1.
 *
 * <p><b>Non-blocking enqueue:</b> {@link #enqueue(AuthEvent)} resolves the lane and calls {@code
 * offer()} — never {@code put()} or {@code add()} — so a full lane rejects the *newest* arrival
 * (drop-newest) in O(1) without blocking the caller. This keeps the failure-path 5 ms budget
 * (design §4.3/T-D3) intact regardless of buffer state.
 *
 * <p><b>Scheduled drain:</b> {@link #drain()} runs on a single {@code @Scheduled(fixedDelay)}
 * thread, priority lane drained to completion before the standard lane every tick. Each iteration
 * only ever holds the queue's own internal lock for the O(1) {@code poll()}/{@code offer()} calls;
 * the {@code repository.save(...)} call itself runs with no lock held, so concurrent {@code
 * enqueue()} calls are never blocked by an in-flight retry attempt. Any unexpected exception from
 * a single item's retry is caught, logged, and counted so the scheduler thread never dies (T-D4);
 * the drain call itself never throws.
 *
 * <p><b>Idempotent retries:</b> {@code drain()} calls {@link JpaAuthEventRepository#save} directly
 * — never through {@code JpaAuthEventAdapter} — to avoid a re-enqueue recursion loop on repeated
 * failure. Each {@link AuthEvent} carries a pre-generated UUIDv7 id, so re-{@code save()}-ing the
 * same entity after a partially-applied earlier attempt cannot create a duplicate row (design
 * §10.1).
 *
 * <p><b>Metrics:</b> registers 2 gauges ({@code nexus.audit.buffer.depth}, {@code
 * nexus.audit.buffer.oldest.age.seconds}, both tagged {@code lane}) backed by live suppliers over
 * this buffer's own queues (no push, no cached value — {@link ArrayBlockingQueue#size()} is O(1)
 * and already internally synchronized, so the gauge can never observe a torn value), plus 3
 * counters ({@code nexus.audit.retry.success}, {@code nexus.audit.retry.exhausted}, {@code
 * nexus.audit.buffer.dropped}). The sixth §4.5 metric, {@code nexus.audit.alert.raised}, is
 * registered by {@code LoggingAuditAlertAdapter} (T-08-14) — not this class.
 *
 * <p><b>Depth/age alert thresholds</b> configured on {@link AuditRetryProperties} are exposed only
 * as gauge values for external Prometheus/Grafana alert rules (T-08-21) to bind to; this buffer
 * does not itself evaluate or debounce a sustained-duration condition from them. The only alert
 * this class raises directly is {@link AuditAlertType#RETRY_EXHAUSTED} — a discrete, per-event,
 * non-duration-based trigger fired on an event's final failed attempt.
 */
@Component
public class AuthEventRetryBuffer {

  private static final Logger log = LoggerFactory.getLogger(AuthEventRetryBuffer.class);

  private static final String METRIC_DEPTH = "nexus.audit.buffer.depth";
  private static final String METRIC_OLDEST_AGE = "nexus.audit.buffer.oldest.age.seconds";
  private static final String METRIC_RETRY_SUCCESS = "nexus.audit.retry.success";
  private static final String METRIC_RETRY_EXHAUSTED = "nexus.audit.retry.exhausted";
  private static final String METRIC_DROPPED = "nexus.audit.buffer.dropped";
  private static final String TAG_LANE = "lane";
  private static final String TAG_REASON = "reason";
  private static final String REASON_OVERFLOW = "overflow";

  private final JpaAuthEventRepository repository;
  private final AuditAlertPort alertPort;
  private final Clock clock;
  private final AuditRetryProperties properties;

  private final Map<AuditLane, BlockingQueue<BufferedAuthEvent>> queues =
      new EnumMap<>(AuditLane.class);
  private final Map<AuditLane, Counter> retrySuccessCounters = new EnumMap<>(AuditLane.class);
  private final Map<AuditLane, Counter> retryExhaustedCounters = new EnumMap<>(AuditLane.class);
  private final Map<AuditLane, Counter> droppedCounters = new EnumMap<>(AuditLane.class);

  /**
   * Constructs the buffer, sizing both lanes from {@code properties} and registering all 5
   * buffer-owned Micrometer metrics (see class Javadoc).
   */
  public AuthEventRetryBuffer(
      JpaAuthEventRepository repository,
      AuditAlertPort alertPort,
      MeterRegistry meterRegistry,
      Clock clock,
      AuditRetryProperties properties) {
    this.repository = repository;
    this.alertPort = alertPort;
    this.clock = clock;
    this.properties = properties;

    queues.put(AuditLane.PRIORITY, new ArrayBlockingQueue<>(properties.priorityCapacity()));
    queues.put(AuditLane.STANDARD, new ArrayBlockingQueue<>(properties.standardCapacity()));

    registerMetrics(meterRegistry);
  }

  /**
   * Non-blocking. Routes to {@link AuditLane#PRIORITY} or {@link AuditLane#STANDARD} via {@code
   * AuthEventType.isPriority()}, then {@code offer()}s onto that lane's queue only.
   *
   * @return {@code true} if enqueued; {@code false} if that lane is at capacity (drop-newest —
   *     the caller's event is the one rejected, nothing already queued is evicted). A full
   *     standard lane never affects the priority lane's available capacity, and vice versa.
   */
  public boolean enqueue(AuthEvent event) {
    AuditLane lane = laneFor(event);
    boolean offered =
        queues.get(lane).offer(new BufferedAuthEvent(event, 0, null, clock.instant()));
    if (!offered) {
      droppedCounters.get(lane).increment();
      log.warn("Audit retry buffer lane full — dropping newest event [lane={}, type={}]",
          lane, event.getEventType());
    }
    return offered;
  }

  /**
   * Scheduled drain: drains the priority lane to completion first, then the standard lane. Any
   * unexpected exception escaping a single item's retry attempt is caught, logged, and counted —
   * this method itself never throws, so the next {@code fixedDelay} tick always runs (T-D4).
   */
  @Scheduled(fixedDelayString = "${nexus.identity.audit.retry-buffer.drain-interval-ms:10000}")
  public void drain() {
    try {
      drainLane(AuditLane.PRIORITY);
      drainLane(AuditLane.STANDARD);
    } catch (RuntimeException e) {
      // Structural T-D4 guard: a bug in the drain loop itself (not a single item's save failure,
      // which is already caught inside drainLane) must never kill the @Scheduled thread.
      log.error("Unexpected exception in AuthEventRetryBuffer.drain() — scheduler continues", e);
    }
  }

  /**
   * Current depth of the given lane. Cheap O(1) gauge source — {@link
   * ArrayBlockingQueue#size()}.
   */
  int depth(AuditLane lane) {
    return queues.get(lane).size();
  }

  /**
   * Age in seconds of the oldest un-drained event in the given lane; {@code 0} if the lane is
   * empty. {@link BlockingQueue#peek()} is O(1) and non-blocking.
   */
  long oldestAgeSeconds(AuditLane lane) {
    BufferedAuthEvent oldest = queues.get(lane).peek();
    if (oldest == null) {
      return 0L;
    }
    return Duration.between(oldest.enqueuedAt(), clock.instant()).toSeconds();
  }

  private AuditLane laneFor(AuthEvent event) {
    return isPriorityWireName(event.getEventType()) ? AuditLane.PRIORITY : AuditLane.STANDARD;
  }

  /**
   * {@code AuthEvent.eventType} is a plain String (design §2.3), so lane routing re-derives
   * priority status from the wire name rather than requiring callers to pass the enum separately.
   * Historical/non-canonical literals (design §2.2 — Gap 6, no backfill) do not match any {@link
   * AuthEventType} constant and route to the standard lane, which is the correct conservative
   * default (only the 4 named priority types are ever elevated).
   */
  private boolean isPriorityWireName(String wireName) {
    for (AuthEventType type : AuthEventType.values()) {
      if (type.wireName().equals(wireName)) {
        return type.isPriority();
      }
    }
    return false;
  }

  private void drainLane(AuditLane lane) {
    BlockingQueue<BufferedAuthEvent> queue = queues.get(lane);
    int due = queue.size();
    Instant now = clock.instant();

    for (int i = 0; i < due; i++) {
      BufferedAuthEvent buffered = queue.poll();
      if (buffered == null) {
        break; // lane drained concurrently below the snapshot size
      }
      if (buffered.isNotYetDue(now)) {
        requeueOrDrop(lane, queue, buffered); // not due yet this tick — put back, don't retry
        continue;
      }
      attemptRetry(lane, queue, buffered, now);
    }
  }

  private void attemptRetry(
      AuditLane lane, BlockingQueue<BufferedAuthEvent> queue, BufferedAuthEvent buffered,
      Instant now) {
    try {
      repository.save(buffered.event());
      retrySuccessCounters.get(lane).increment();
    } catch (DataAccessException e) {
      handleRetryFailure(lane, queue, buffered, now, e);
    } catch (RuntimeException e) {
      // A single item's unexpected failure must not abort the rest of the lane's drain pass.
      log.error("Unexpected exception retrying buffered audit event [lane={}]", lane, e);
      handleRetryFailure(lane, queue, buffered, now, e);
    }
  }

  private void handleRetryFailure(
      AuditLane lane, BlockingQueue<BufferedAuthEvent> queue, BufferedAuthEvent buffered,
      Instant now, Exception cause) {
    int nextAttemptNumber = buffered.attempts() + 1;
    if (nextAttemptNumber >= properties.maxAttempts()) {
      retryExhaustedCounters.get(lane).increment();
      alertPort.raise(
          new AuditAlert(
              AuditAlertType.RETRY_EXHAUSTED,
              "Audit event exhausted retries [lane=" + lane + ", type="
                  + buffered.event().getEventType() + "]: " + cause.getMessage(),
              now,
              depth(lane)));
      log.warn("Audit event dropped after exhausting retries [lane={}, type={}]",
          lane, buffered.event().getEventType());
      return;
    }
    Duration backoff = backoffFor(nextAttemptNumber);
    BufferedAuthEvent retried = buffered.withAttemptFailed(now.plus(backoff));
    requeueOrDrop(lane, queue, retried);
  }

  /**
   * Puts a not-yet-due or retry-pending event back onto its own lane's queue. The slot this item
   * was just {@code poll()}ed from is normally free again, so {@code offer()} here almost always
   * succeeds — but a concurrent {@link #enqueue} flood could race in and fill that slot first. If
   * so, this is a genuine drop-newest-equivalent loss (the buffer is at capacity for this lane),
   * so it is counted identically to an {@link #enqueue} overflow rather than silently discarded.
   */
  private void requeueOrDrop(AuditLane lane, BlockingQueue<BufferedAuthEvent> queue,
      BufferedAuthEvent event) {
    if (!queue.offer(event)) {
      droppedCounters.get(lane).increment();
      log.warn("Audit retry buffer lane filled during drain — dropping requeued event "
          + "[lane={}, type={}]", lane, event.event().getEventType());
    }
  }

  private Duration backoffFor(int attemptNumber) {
    var schedule = properties.backoffSchedule();
    int index = Math.min(attemptNumber - 1, schedule.size() - 1);
    return schedule.get(index);
  }

  private void registerMetrics(MeterRegistry meterRegistry) {
    for (AuditLane lane : AuditLane.values()) {
      Tags laneTag = Tags.of(TAG_LANE, lane.name().toLowerCase());

      meterRegistry.gauge(METRIC_DEPTH, laneTag, this, buffer -> buffer.depth(lane));
      meterRegistry.gauge(
          METRIC_OLDEST_AGE, laneTag, this, buffer -> (double) buffer.oldestAgeSeconds(lane));

      retrySuccessCounters.put(lane, meterRegistry.counter(METRIC_RETRY_SUCCESS, laneTag));
      retryExhaustedCounters.put(lane, meterRegistry.counter(METRIC_RETRY_EXHAUSTED, laneTag));
      droppedCounters.put(
          lane,
          meterRegistry.counter(
              METRIC_DROPPED, laneTag.and(TAG_REASON, REASON_OVERFLOW)));
    }
  }
}
