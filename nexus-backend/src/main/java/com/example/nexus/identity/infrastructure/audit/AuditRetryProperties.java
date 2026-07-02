package com.example.nexus.identity.infrastructure.audit;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * US-008 T-08-15 (design §4.1/§4.2, ADR 0011) — configuration for {@link AuthEventRetryBuffer}.
 *
 * <p>Every default below is bound 1:1 to the concrete SLO/capacity table in {@code
 * docs/features/US-008/03-design.md} §4.1 and {@code
 * docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md} §2 — do not change a
 * default without updating both documents.
 *
 * <p>{@code priority} and {@code standard} carry independently-shaped thresholds (not a single
 * shared set) because the design's own numbers are structurally different per lane (e.g. priority
 * depth-warn is "≥1", standard depth-warn is "≥250") — collapsing them into shared fields would
 * either lose that distinction or require per-lane overrides anyway.
 *
 * <p>These threshold fields are pure gauge-adjacent configuration for external Prometheus/Grafana
 * alert rules (T-08-21) to bind to; {@link AuthEventRetryBuffer} does not itself evaluate or
 * debounce a sustained-duration condition from them — it only ever raises {@code
 * RETRY_EXHAUSTED} directly (a discrete, non-duration-based, per-event trigger).
 *
 * @param enabled escape hatch (design §10.3) — {@code false} disables the scheduler entirely
 *     ({@link SchedulingConfig}); {@code true} is default (Open Unknown #3 / ADR 0011 §4)
 * @param priorityCapacity bounded capacity of the priority lane (default 200)
 * @param standardCapacity bounded capacity of the standard lane (default 800)
 * @param drainIntervalMs {@code @Scheduled(fixedDelay)} interval in milliseconds (default 10000)
 * @param maxAttempts maximum retry attempts before an event is dropped + exhausted (default 5)
 * @param backoffSchedule per-attempt backoff durations, identical for both lanes (default
 *     1s, 5s, 30s, 2m, 10m — exactly {@code maxAttempts} entries)
 * @param priority depth/age alert thresholds for the priority lane (defaults to {@link
 *     LaneThresholds#priorityDefaults()} when the YAML block is omitted or {@code null})
 * @param standard depth/age alert thresholds for the standard lane (defaults to {@link
 *     LaneThresholds#standardDefaults()} when the YAML block is omitted or {@code null})
 */
@ConfigurationProperties(prefix = "nexus.identity.audit.retry-buffer")
public record AuditRetryProperties(
    boolean enabled,
    int priorityCapacity,
    int standardCapacity,
    long drainIntervalMs,
    int maxAttempts,
    List<Duration> backoffSchedule,
    LaneThresholds priority,
    LaneThresholds standard) {

  /**
   * Canonical constructor — carries the {@code @DefaultValue} bindings (a record's compact/header
   * annotations are copied onto the implicit canonical constructor only; declaring this
   * constructor explicitly requires repeating them here for Spring's constructor-bound binder to
   * see them) and substitutes lane-correct defaults ({@link LaneThresholds#priorityDefaults()} /
   * {@link LaneThresholds#standardDefaults()}) whenever the corresponding YAML block is absent, so
   * this record is safe to construct directly (in tests) without a full property binder, and safe
   * under partial YAML overrides.
   *
   * <p>A single shared {@code @DefaultValue} on the nested {@link LaneThresholds} type cannot
   * express the per-lane defaults, because the two lanes' numbers are numerically different
   * (priority depth-warn ≥1 vs. standard depth-warn ≥250, per design §4.1) — a bare {@code
   * @DefaultValue} on a nested record type applies the *same* nested defaults to both parameters.
   */
  public AuditRetryProperties(
      @DefaultValue("true") boolean enabled,
      @DefaultValue("200") int priorityCapacity,
      @DefaultValue("800") int standardCapacity,
      @DefaultValue("10000") long drainIntervalMs,
      @DefaultValue("5") int maxAttempts,
      @DefaultValue({"1s", "5s", "30s", "2m", "10m"}) List<Duration> backoffSchedule,
      LaneThresholds priority,
      LaneThresholds standard) {
    this.enabled = enabled;
    this.priorityCapacity = priorityCapacity;
    this.standardCapacity = standardCapacity;
    this.drainIntervalMs = drainIntervalMs;
    this.maxAttempts = maxAttempts;
    // Defensive copy + immutable wrap (List.copyOf) — this record must not expose or be
    // constructed from an externally-mutable list (SpotBugs EI_EXPOSE_REP/EI_EXPOSE_REP2).
    this.backoffSchedule = List.copyOf(backoffSchedule);
    this.priority = priority != null ? priority : LaneThresholds.priorityDefaults();
    this.standard = standard != null ? standard : LaneThresholds.standardDefaults();
  }

  /**
   * Depth/age alert thresholds for a single lane (design §4.1). These values are exposed for
   * external alert-rule binding only — see the class-level Javadoc.
   *
   * @param depthWarn ticket-worthy sustained depth (Prometheus rule window: "for 1 min")
   * @param depthCritical page-worthy sustained depth (90% of that lane's capacity)
   * @param ageCritical page-worthy oldest-un-drained-event age
   */
  public record LaneThresholds(int depthWarn, int depthCritical, Duration ageCritical) {

    /** Priority-lane defaults per design §4.1: depth-warn ≥1, depth-critical ≥180 (90% of 200). */
    public static LaneThresholds priorityDefaults() {
      return new LaneThresholds(1, 180, Duration.ofMinutes(15));
    }

    /** Standard-lane defaults per design §4.1: depth-warn ≥250, depth-critical ≥720 (90% of
     *  800). */
    public static LaneThresholds standardDefaults() {
      return new LaneThresholds(250, 720, Duration.ofMinutes(15));
    }
  }
}
