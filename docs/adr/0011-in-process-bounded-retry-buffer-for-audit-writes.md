# ADR 0011 — In-Process Two-Lane Bounded Retry Buffer for Audit Writes

**Status:** Accepted
**Date:** 2026-07-01
**Feature:** US-008 (Emit audit events for all authentication actions)

---

## Context

`JpaAuthEventAdapter.record` today performs a single synchronous `INSERT` into `auth_events` and nothing else — there is no retry, no backpressure, and no observability if that insert fails. If the audit store degrades or goes down during live auth traffic, every audit write for the duration of the outage is silently lost: the primary auth flow (login/logout/etc.) must still return its real outcome (AC4), so the audit failure cannot be allowed to block or fail the request, but today that failure also has nowhere to go.

`02-impact.md`'s Open Unknown #3 asked for concrete WS-3 SLOs (capacity, overflow policy, backoff, drain cadence, alert thresholds) and `03-design.md` §4 resolves them. This ADR records that resolution.

The design was not settled in one pass. The Gate-2 threat-modeling review (`03b-threat-model.md`, **T-D1**) identified a High-severity flaw in the originally proposed single-FIFO bounded buffer: an attacker who floods failed logins during a concurrent (or attacker-induced) DB outage can fill a single 1000-capacity queue with `LOGIN_FAILURE` noise, evicting genuine `LOCKOUT` events — exactly the security-critical signal an audit trail must not have a blind spot for. **The two-lane split described below is the design's response to that finding and is the central decision this ADR records.** T-D2 (unbounded-queue OOM risk), T-D4 (scheduler-thread death silently halting all draining), and T-R3 (audit events lost during a store outage, need for observability over silence) round out the requirements this buffer must satisfy.

Constraints carried over from ADR 0009 and `02-impact.md` §9: no new dependency should be introduced unless clearly justified, and the classpath already carries everything needed (`spring-boot-starter-actuator` + `micrometer-registry-prometheus`; JDK `java.util.concurrent.ArrayBlockingQueue`; Spring `@Scheduled`). No `@EnableScheduling`, `MeterRegistry` usage, `RetryTemplate`, or second `DataSource` existed anywhere in `src/main` prior to this story.

---

## Decision

### 1. Two-lane bounded buffer, not a single FIFO — closes T-D1

`AuthEventRetryBuffer` (`identity/infrastructure/audit/`) holds **two independent bounded queues** (`ArrayBlockingQueue<BufferedAuthEvent>`), not one:

- **Priority lane — capacity 200.** Carries exactly the four highest-value forensic/security-incident event types, routed via a new `AuthEventType.isPriority()` method: `LOCKOUT`, `TOKEN_REFRESH_REUSE`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED_WRITE_FAILED`.
- **Standard lane — capacity 800.** Carries every other `AuthEventType`, including the high-volume, unauthenticated-and-attacker-reachable `LOGIN_FAILURE`.
- **Total capacity 1000**, unchanged from the original single-lane proposal — the split is a re-partition of the same budget, not an increase.

`enqueue(AuthEvent)` is non-blocking: it resolves the lane via `isPriority()` and `offer()`s onto that lane's queue only. **Overflow (drop-newest) is per lane, independently:** a full standard lane rejects new standard-lane events and increments that lane's drop counter, but this has **no effect whatsoever on the priority lane's available capacity** — a `LOGIN_FAILURE` flood cannot touch, block, or evict a `LOCKOUT` event. This is the specific mechanism that closes T-D1: the original single-FIFO design allowed exactly the cross-contamination this split eliminates.

Drop-newest (not drop-oldest, and not block-the-caller) was chosen within each lane for the same reasons in both lanes: dropping the newest preserves the oldest events — the ones closest to the incident's root cause — while keeping `enqueue` O(1) and non-blocking (the 5 ms failure-path budget). Blocking or rejecting the caller was rejected because it would propagate the DB outage into the auth path itself, violating AC4 (the auth flow must return its real outcome regardless of audit-store health).

The drainer (§2 below) also processes the priority lane to completion before touching the standard lane on every tick, so security-critical events get DB-write priority during recovery, not just protected shelf space while buffered.

### 2. Concrete capacity, backoff, drain, and alert parameters

| Parameter | Value |
|-----------|-------|
| Total capacity | 1000 events, split 200 priority / 800 standard |
| Overflow policy | Drop-newest, per lane independently; increments `nexus.audit.buffer.dropped{reason=overflow,lane}` |
| Retry backoff schedule | **1s → 5s → 30s → 2m → 10m**, identical for both lanes, capped at **5 attempts** |
| On attempt-5 exhaustion | Event dropped; `AuditAlertPort.raise(RETRY_EXHAUSTED)`; `nexus.audit.retry.exhausted{lane}`++ |
| Drain cadence | `@Scheduled(fixedDelay = 10s)` — a single drainer thread; **priority lane drained to completion before the standard lane, every tick** |
| Depth-warn | ≥ 250 standard-lane events for 1 min, **or** any priority-lane depth ≥ 1 for 1 min → ticket |
| Depth-critical | ≥ 720 standard-lane (90% of 800) for 1 min, **or** ≥ 180 priority-lane (90% of 200) for 1 min → page |
| Age-critical | Oldest un-drained event in either lane > 15 min → page |
| Max event-loss window (accepted residual) | ≤ buffer contents at crash — ≤ 1000 events across both lanes combined |

`fixedDelay` (not `fixedRate`) is deliberate: it prevents overlapping drain invocations from stacking up against a slow-but-not-yet-failed DB. The depth/age thresholds are tuned so that any *sustained* priority-lane backlog at all (depth ≥ 1 for a full minute) already tickets — priority-lane volume is expected to be low enough that even a small backlog is anomalous and worth a human looking at it, whereas the standard lane (dominated by `LOGIN_FAILURE` noise) only warrants attention once it is a meaningful fraction full.

### 3. JDK primitives, not a new dependency

The buffer is built entirely from what is already on the classpath: two `java.util.concurrent.ArrayBlockingQueue` instances, Spring's `@Scheduled` (behind a dedicated `SchedulingConfig` — the single `@EnableScheduling` point in the codebase, verified absent elsewhere), and Micrometer (already present via `micrometer-registry-prometheus`) for the six named gauges/counters. No `RetryTemplate`, no Resilience4j, no Redis, no new table. The full comparison against the alternatives that were considered and rejected — including the single-FIFO design this ADR's two-lane decision replaces — is in **Alternatives Considered** below.

### 4. Escape-hatch configuration flag

`nexus.identity.audit.retry-buffer.enabled` (default `true`, `matchIfMissing=true` on the `@ConditionalOnProperty` guarding `SchedulingConfig`). Setting it to `false`:

- Disables the scheduler bean entirely (no drain thread is started).
- Reverts `JpaAuthEventAdapter` to synchronous-swallow-and-WARN-only behavior — the pre-US-008 posture: a failed audit insert is logged and dropped immediately, with no buffering, no retry, and no lane distinction.

This is the documented instant-rollback path for the gradual-confidence rollout in `03-design.md` §10.4: ship enabled by default, watch `nexus.audit.buffer.dropped`/`nexus.audit.retry.exhausted` stay at zero under normal load and through the load test and audit-store-down IT, and flip the flag to `false` if the buffer itself proves problematic in production before those signals are trusted.

### 5. Accepted residual: data loss on pod crash/restart

The buffer is **in-memory only** and is not durable across a pod crash or restart. If the process dies while events are buffered and undrained, those events are lost — up to **1000 events total across both lanes**. This was explicitly accepted in Open Unknown #3 rather than solved with a durable store, for MVP scope reasons (see §6 / Alternatives Considered — transactional outbox). The loss is bounded and **observable**, not silent: depth and oldest-age gauges make an in-progress backlog visible in real time, and any exhaustion or overflow raises an alert and increments a counter before the loss window can grow unnoticed (T-R3).

A narrower, related residual is worth calling out explicitly rather than leaving implicit: **the priority lane itself remains bounded at 200** and could theoretically saturate if `LOCKOUT`/`TOKEN_REFRESH_REUSE`/`PASSWORD_CHANGED`/`ACCOUNT_LOCKED_WRITE_FAILED` volume spiked independently of any `LOGIN_FAILURE` flood during an outage. This is accepted as **Low** residual (down from the original **High**-severity single-lane finding) because: (a) priority-type volume is inherently far lower than generic login-failure traffic under any realistic attack or outage scenario, and (b) the depth-warn threshold pages on *any* sustained priority-lane depth ≥ 1, so saturation is caught essentially immediately rather than silently, unlike the original single-lane design where a priority event could be evicted before anyone noticed the lane was under pressure.

### 6. Outbox as the future zero-loss upgrade path

A transactional outbox table + poller is explicitly named as the upgrade path if a future compliance or reliability requirement mandates zero audit-event loss across process restarts. It is **deferred, not rejected** for this story: an outbox eliminates the in-memory residual in §5 by making the buffered state durable, but it requires a new table, a poller process, and its own append-only/cleanup lifecycle — materially larger scope than an MVP retry buffer — and, critically, the outbox *write itself* would hit the same database that is presumed to be down in the exact failure scenario this buffer exists to survive (an outbox only fully pays off once writes can be staged to a separate durable medium, e.g. a local WAL or a broker, which is its own future decision). If audit durability requirements tighten, this is where the next design iteration should start.

### 7. Cross-story obligation: downstream rendering of `user_agent`/`metadata` (T-I2, tracked here for EPIC-007)

This buffer stores and drains `AuthEvent` rows whose `user_agent` column and `metadata` JSON (`traceId`, `ip`, `userAgent`) are **fully attacker-controlled, unbounded-content strings** (`03-design.md` §3.4) — this story's own storage-layer controls (512-char cap, JSON-escaping via `jsonEscape`) are sufficient to persist the data safely and are **not** HTML-escaping. `03b-threat-model.md` **T-I2** identifies the resulting Stored-XSS risk as a **deferred, Medium-severity, downstream obligation**: a value such as `User-Agent: <script>...</script>` survives storage intact by design (forensic data must not be lossily mangled at write time) and would render unescaped if a future viewer naively injects it into HTML.

**This is recorded here, not silently assumed, because no EPIC-007 planning document exists yet in this repository** (verified — no `EPIC-007` artifacts found under `docs/` or `story/` at the time of writing) to serve as its natural home. Until EPIC-007's own planning docs exist, **this ADR is the authoritative tracking location** for the obligation below; EPIC-007's discovery/requirements phase MUST carry this forward (and may then supersede this note with its own ADR/design reference).

> **Tracked obligation (EPIC-007 — any future `auth_events` viewer/audit-log UI):** any component that renders `auth_events.user_agent` or `auth_events.metadata` (or any field derived from them) **MUST HTML-escape the value on render** and **MUST apply a Content-Security-Policy** that mitigates script execution even if an escaping gap is later introduced. Treat both fields as hostile input at render time, identically to how they are already treated as hostile input at write time (T-T1/T-T2, this story). This obligation is NOT satisfied by this story's JSON-escaping — JSON-escaping and HTML-escaping are different controls for different contexts, and only the former exists today.

Cross-linked from `docs/features/US-008/monitoring.md` (T-08-21) so operators building dashboards/log-query tooling against this data are also aware of the render-time hazard, even though `monitoring.md` itself only queries `auth_events` for operational (non-HTML-rendering) purposes and does not itself require HTML-escaping.

---

## Consequences

**Benefits:**
- The original High-severity T-D1 finding (a login-failure flood evicting `LOCKOUT` events during an outage) is mitigated to a Low, bounded, paged residual — a standard-lane flood now structurally cannot touch priority-lane capacity.
- The auth path never blocks on, or fails because of, audit-store health (AC4) — enqueue is O(1) and non-blocking on the failure path only; the healthy-path synchronous insert is unchanged.
- Heap impact is bounded and small: ≈1000 buffered `AuthEvent` objects × ~1 KB ≈ 1 MB worst case.
- Loss is observable rather than silent: six Micrometer metrics (`nexus.audit.buffer.depth`, `buffer.oldest.age.seconds`, `retry.success`, `retry.exhausted`, `buffer.dropped`, `alert.raised`, all tagged `lane` where applicable) plus `AuditAlertPort` alerts on depth/age/exhaustion thresholds replace what was previously a completely silent failure mode.
- Zero new dependency, hence zero new CVE surface — everything is JDK `ArrayBlockingQueue` + Spring `@Scheduled` + Micrometer, already present on the classpath.
- Idempotent retries: each `AuthEvent` carries a pre-generated UUIDv7 id, so a retried `save()` after a partially-applied earlier attempt cannot create a duplicate row.
- A drainer iteration that throws is caught, logged, and counted rather than propagating — T-D4 is closed structurally, not just by convention: the scheduler thread never dies silently, and the next tick always runs.

**Trade-offs:**
- Not durable: an in-flight buffer of up to 1000 events is lost on a pod crash or forced restart. Accepted (§5); mitigated by observability, not eliminated.
- Two lanes add marginally more complexity than a single queue would — one `AuthEventType.isPriority()` routing check and a second bounded queue/gauge pair — in exchange for closing a High-severity threat-model finding. The complexity cost was judged small relative to the risk closed.
- The priority lane, while far less likely to saturate than the standard lane, is still itself bounded (200) and carries its own (Low) residual — see §5.
- The escape-hatch flag, if ever set to `false` in production, reintroduces the pre-US-008 silent-loss behavior (synchronous-swallow-and-WARN, no buffering, no lane protection at all) — it is a deliberate full opt-out, not a partial degradation.
- Draining is single-threaded by design (`fixedDelay`, one drainer): under a very slow (not fully down) DB, a long-running priority-lane drain could delay the start of standard-lane draining within a given tick. This is accepted as consistent with the deliberate "priority lane first" ordering.

---

## Alternatives Considered

| Option | Rejected because |
|--------|-------------------|
| **`@Async` + `ApplicationEventPublisher`** (reusing the existing `MailEventListener` fire-and-forget pattern) | No retry, no bounded backpressure, and no depth/age visibility — it would recreate the exact silent-loss gap AC4 targets, just moved one layer later. Also moves the write off the request thread, complicating the "audit within 1s" (AC1) timing assertion. |
| **Transactional outbox table + poller** | Durable across restarts (would eliminate the §5 residual entirely) but requires a new table, a poller process, and its own append-only/cleanup story — materially larger than MVP scope. The outbox write itself would hit the same DB presumed down in the failure scenario the buffer exists to survive. Deferred as the documented future upgrade path (§6) if zero-loss durability is later mandated, not rejected outright. |
| **Resilience4j / Spring Retry dependency** | A new dependency for behavior the JDK already provides via `ArrayBlockingQueue` + `@Scheduled`. Both `02-impact.md` §9 and ADR 0009's "no new dependency until clearly justified" stance argue against introducing one here. Rejected for MVP. |
| **Redis-backed queue** | ADR 0009 already explicitly defers Redis as a dependency; reintroducing it here for this buffer would be out of scope and would contradict the established "boring tech / no new infra" posture for this codebase. |
| **Unbounded in-memory queue** | Removes the drop-newest/backpressure question entirely but creates real OOM risk under a sustained DB outage with continued auth traffic — it would turn an audit-store outage into a full application crash. Rejected in favor of the bounded, capped-at-1000, drop-newest design. |
| **Single FIFO lane (no priority split)** | This was the design as originally proposed, before the Gate-2 threat-modeling pass. Simpler — one queue, one drop counter — but a `LOGIN_FAILURE` flood during a DB outage can fill and evict newer `LOCKOUT` events before they drain, which is precisely threat-model finding **T-D1** (originally High severity): the exact scenario a security/compliance audit log must not have a blind spot for. Rejected in favor of the two-lane (200 priority / 800 standard) design in §1, which costs one `isPriority()` branch and a second bounded queue — a small increase in complexity to close a High-severity finding. |

---

### Cross-references
- `docs/features/US-008/03-design.md` §4 (full WS-3 design — capacities, backoff, drain cadence, alert thresholds, alternatives table), §11 (ADR summary row)
- `docs/features/US-008/03b-threat-model.md` — **T-D1** (the central finding this ADR's two-lane decision resolves), T-D2 (unbounded-queue OOM), T-D4 (drainer-exception survival), T-R3 (accepted data-loss-on-restart residual, alerting requirement), **T-I2** (Stored-XSS-on-render obligation recorded in §7 above)
- `docs/features/US-008/04-tasks.md` — T-08-13 (this ADR), T-08-14 (`AuditAlertPort`/`LoggingAuditAlertAdapter`), T-08-15 (`AuthEventRetryBuffer` two-lane implementation + metrics), T-08-16 (`JpaAuthEventAdapter` enqueue-on-failure), T-08-17 (lane-isolation/overflow/drainer-survival unit tests), T-08-18 (audit-store-down IT), T-08-21 (dashboard/alert spec + this §7 note)
- `docs/features/US-008/monitoring.md` — T-08-21 dashboard/alert-rule specification bound to §2's thresholds; cross-links back to §7's T-I2 obligation
- ADR 0009 — REQUIRES_NEW transaction pattern; source of the "no new dependency until clearly justified" stance applied to the alternatives above
- ADR 0012 — Least-privilege runtime DB user for `auth_events` (sibling ADR, same story, WS-2)
