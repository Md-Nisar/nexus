# US-008 — Solution Design: Emit Audit Events for All Authentication Actions

_Output of `/design` (architect). Gate 2 deliverable. Feeds the threat model (`03b-threat-model.md`) and task breakdown (`04-tasks.md`)._

**Binding inputs:** `01-requirements.md` §11 (Gate 1 Decisions) and `02-impact.md` §1 (WS-1..WS-6) and §12 (Open Unknowns). This document resolves all seven §12 unknowns with concrete decisions. It does not revisit Gate-1 scope.

**Verification basis (re-checked at design time, not trusted from impact doc):** all source line references below were re-read directly. Key facts confirmed as still true:
- Migrations on disk: `V1__baseline.sql`, `V2__identity_schema.sql`, `V3__add_password_hash_to_users.sql`. **US-007's `V4__auth_tokens_reset_throttle_index.sql` is referenced in `US-007/03-design.md` §4 and is on the `feature/US-007` lineage (merged at commit `ff761a1`), but is not present in the working tree of this branch.** US-008 must therefore claim **V5** to avoid colliding with V4. See §3.
- `auth_events` schema: `id, user_id (NULL), tenant_id (NULL), event_type VARCHAR(64), outcome VARCHAR(20), ip_address VARCHAR(45), metadata JSON, created_at` + two append-only triggers (`V2__identity_schema.sql:76-110`).
- `RequestContext` is a 2-arg record `(ipAddress, traceId)` (`common/domain/RequestContext.java`). No `userAgent`, no `tenantId`.
- `AuthEvent` has no `withTenantId`, no `withUserAgent` (`identity/domain/AuthEvent.java:60-76`).
- `LogoutUseCase.execute(UUID userId, String rawRefreshToken, String clientIp)` records via `authEventPort.record(...)` **inline in the same TX**, with **no metadata** at all (`LogoutUseCase.java:79-82`).
- `RegisterUserUseCase` and `VerifyEmailUseCase`/`ResendVerificationUseCase` record via `authEventPort.record(...)` inline in the same TX.
- `User` has Lombok `@Getter` → `getTenantId()` exists (`User.java:18,26-27`).
- Classpath: `spring-boot-starter-actuator` + `micrometer-registry-prometheus` present (`pom.xml:78,88-89`). **No `@EnableScheduling`, no `MeterRegistry` usage, no `RetryTemplate`, no second `DataSource` anywhere in `src/main`.**
- App connects as `root` today (`docker-compose.yml:29`, `application.yml:18` `username: ${DB_USERNAME:root}`).

---

## 0. Resolution of the 7 Gate-2 Open Unknowns (summary table)

| # | Unknown (impact §12) | Decision | Detail |
|---|----------------------|----------|--------|
| 1 | Migration numbering | **V5** | `V5__auth_events_add_user_agent.sql`. V1–V3 on disk; V4 owned by US-007 (merged). Re-confirm `V5` is still free at implementation time. §3 |
| 2 | WS-2 topology | **Single least-privilege app user, single DataSource. Grants provisioned out-of-band per environment (NOT a Flyway migration).** | A second DataSource is rejected — disproportionate to a defense-in-depth control layered on top of triggers that already pass the test. §6 |
| 3 | WS-3 SLOs | **Capacity 1000, split into a 200-event priority lane (LOCKOUT/TOKEN_REFRESH_REUSE/PASSWORD_CHANGED/ACCOUNT_LOCKED_WRITE_FAILED) and an 800-event standard lane, so a LOGIN_FAILURE flood cannot evict security-critical events (closes threat model T-D1); drop-newest per lane on overflow; backoff 1s→5s→30s→2m→10m (cap, 5 attempts); drain every 10s, priority lane first; per-lane depth/age alert thresholds; max event-loss window = the in-flight buffer at crash (≤1000 events total, accepted residual).** | §4 |
| 4 | WS-5 logout/register atomicity | **Keep Logout and Register audit writes in the SAME outer TX (do NOT move to REQUIRES_NEW). Standardize on durability via the WS-3 retry buffer instead of REQUIRES_NEW.** This satisfies OQ-6's intent (no silent loss) without breaking the documented atomicity invariant. §7 |
| 5 | WS-4 tenant resolution for Logout/Verify/Refresh | **Accept NULL; no extra lookup for Logout.** Populate from the loaded `User` where one is already loaded (Verify/Refresh/Reset post-resolution). §5 |
| 6 | WS-6 storage shape | **First-class `user_agent VARCHAR(512) NULL` column AND mirrored into `metadata` JSON.** AC2 lists it as a schema field; column wins. §3, §8 |
| 7 | Ops alert channel | **Define `AuditAlertPort` (application port.out) + a default `LoggingAuditAlertAdapter` (infrastructure). No concrete vendor.** §4.4 |

---

## 1. Architecture Overview

```
interfaces (REST): LoginController, RegistrationController, PasswordResetController
        |
        v
application: LoginUseCase, LogoutUseCase, RegisterUserUseCase, VerifyEmailUseCase,
              ForgotPasswordUseCase, ResetPasswordUseCase, ResendVerificationUseCase,
              RefreshTokenUseCase, SecureEventService (REQUIRES_NEW)
              ports: AuthEventPort, AuditAlertPort
        |
        v
domain: AuthEvent, AuthEventType (enum), RequestContext (common.domain)
        |
        v
infrastructure: JpaAuthEventAdapter, AuthEventRetryBuffer (bounded queue + drainer + metrics),
                 LoggingAuditAlertAdapter
        |
        v
auth_events (MySQL — least-priv `nexus_app` user, triggers + INSERT/SELECT grant)
```

Flow: Login/Refresh/Forgot/Reset use cases call `SecureEventService` (REQUIRES_NEW); Logout/Register/Verify/Resend call `AuthEventPort` directly (same TX — see §7). Both paths converge on `JpaAuthEventAdapter`, which synchronously inserts and, on failure, enqueues into `AuthEventRetryBuffer`. The buffer's scheduled drainer retries via the repository directly and raises alerts through `AuditAlertPort` on backlog/exhaustion.

**Layering compliance (docs/ARCHITECTURE.md, ArchUnit-enforced):**
- `AuthEventType` and `AuthEvent` → **domain** (no outer imports).
- `RequestContext` stays in **common.domain** (cross-context carrier; consistent with `AccountLockedException` living in `common.domain`).
- `AuthEventPort`, `AuditAlertPort` → **application.port.out**.
- `JpaAuthEventAdapter`, `AuthEventRetryBuffer`, `LoggingAuditAlertAdapter`, scheduler config → **infrastructure**. The retry buffer is an adapter concern (it owns persistence-retry mechanics), so it lives in a new `identity.infrastructure.audit` sub-package, not domain/application.
- `SecureEventService` stays in **application.service** (transaction demarcation at the application layer, per ADR 0009's rule).

---

## 2. WS-1 — Event Taxonomy (`AuthEventType` enum)

### 2.1 New domain type

`identity/domain/AuthEventType.java` — an `enum`. **Each constant carries its canonical `wireName` String** (the value persisted to `event_type`), so renaming the constant name never silently changes the stored literal, and the stored value is auditable in one place.

```java
public enum AuthEventType {
  // AC1 canonical 9 (renames applied per OQ-1)
  LOGIN_SUCCESS("LOGIN_SUCCESS"),
  LOGIN_FAILURE("LOGIN_FAILURE"),
  LOCKOUT("LOCKOUT"),                         // renamed from ACCOUNT_LOCKED
  LOGOUT("LOGOUT"),
  REGISTER("REGISTER"),                       // renamed from REGISTRATION_SUCCESS
  VERIFY("VERIFY"),                           // renamed from VERIFICATION_SUCCESS
  PASSWORD_RESET_REQUESTED("PASSWORD_RESET_REQUESTED"),
  PASSWORD_CHANGED("PASSWORD_CHANGED"),
  TOKEN_REFRESH_REUSE("TOKEN_REFRESH_REUSE"), // renamed from REFRESH_FAMILY_REVOKED

  // Retained granular states (beyond AC1's 9 — superset, per OQ-1)
  LOGIN_PENDING_ACCOUNT("LOGIN_PENDING_ACCOUNT"),
  ACCOUNT_UNLOCKED("ACCOUNT_UNLOCKED"),
  ACCOUNT_LOCKED_WRITE_FAILED("ACCOUNT_LOCKED_WRITE_FAILED"),
  REGISTRATION_DUPLICATE_EMAIL("REGISTRATION_DUPLICATE_EMAIL"),
  VERIFICATION_FAILED("VERIFICATION_FAILED"),
  TOKEN_REFRESH_SUCCESS("TOKEN_REFRESH_SUCCESS"),
  TOKEN_REFRESH_FAILURE("TOKEN_REFRESH_FAILURE"),
  PASSWORD_RESET_THROTTLED("PASSWORD_RESET_THROTTLED"),
  PASSWORD_RESET_FAILED("PASSWORD_RESET_FAILED"),
  RESEND_REQUESTED("RESEND_REQUESTED"),
  RESEND_THROTTLED("RESEND_THROTTLED");

  private final String wireName;
  AuthEventType(String wireName) { this.wireName = wireName; }
  public String wireName() { return wireName; }

  private static final Set<AuthEventType> PRIORITY = EnumSet.of(
      LOCKOUT, TOKEN_REFRESH_REUSE, PASSWORD_CHANGED, ACCOUNT_LOCKED_WRITE_FAILED);

  /** Used by AuthEventRetryBuffer (§4.2) to route into the priority vs. standard buffer lane. */
  public boolean isPriority() { return PRIORITY.contains(this); }
}
```

### 2.2 Name-mapping table (Gap 3 in requirements — the canonical mapping)

| Old literal (historical rows) | New `wireName` | Flow |
|-------------------------------|----------------|------|
| `ACCOUNT_LOCKED` | **`LOCKOUT`** | `SecureEventService.persistFailedAttempt` (line 89) |
| `REFRESH_FAMILY_REVOKED` | **`TOKEN_REFRESH_REUSE`** | `RefreshTokenUseCase` (line 116) |
| `REGISTRATION_SUCCESS` | **`REGISTER`** | `RegisterUserUseCase` (line 112) |
| `VERIFICATION_SUCCESS` | **`VERIFY`** | `VerifyEmailUseCase` (line 107) |
| all others | unchanged | — |

**Historical rows keep old literals (Gap 6 — no backfill in scope).** Any future consumer (EPIC-007) MUST tolerate both `ACCOUNT_LOCKED`/`LOCKOUT`, `REFRESH_FAMILY_REVOKED`/`TOKEN_REFRESH_REUSE`, etc. This obligation is recorded here as the authoritative source.

### 2.3 Entity wiring

`AuthEvent.eventType` **stays a `String` column** (no `@Enumerated`). Rationale: (a) historical rows hold non-enum literals that `@Enumerated(STRING)` would fail to read; (b) `VARCHAR(64)` already fits every `wireName`; (c) keeps the entity tolerant of taxonomy evolution. The constructor changes to accept the enum and store its wire name:

```java
public AuthEvent(UUID id, AuthEventType eventType, String outcome) {
  this(id, eventType.wireName(), outcome);   // delegates to existing String ctor
}
```
The existing `AuthEvent(UUID, String, String)` constructor is **retained** (package-private or kept public) so historical/test code and the read path are unaffected. Every call site in the 8 files switches to the enum constructor; the four renamed literals change value as a side effect.

### 2.4 Layer / size
Domain (enum) + application (8 call-site files). Mechanical, wide, low-risk. No DDL.

---

## 3. WS-6 + DB — `user_agent` Column & Migration (DB section)

### 3.1 Flyway migration (additive, ADR 0003-compliant)

**File:** `nexus-backend/src/main/resources/db/migration/V5__auth_events_add_user_agent.sql`
**Number confirmation:** V1–V3 on disk, V4 = US-007 (merged). **V5 is the next free number; re-verify against `main` immediately before merge** (if another story lands a V5 first, bump to V6 — the file is otherwise environment-agnostic).

```sql
-- V5__auth_events_add_user_agent.sql
-- US-008 WS-6: add first-class user_agent column to auth_events.
-- Attacker-controlled, unbounded free text -> capped at 512 chars at the application
-- boundary (RequestContext) before insert; column width is the storage-side backstop.
-- Additive / expand-only (ADR 0003) -- append-only, never edited after first apply.
-- No expand/contract sequencing needed: nullable add, no existing-column change.
ALTER TABLE auth_events
    ADD COLUMN user_agent VARCHAR(512) NULL AFTER ip_address;
```

- **No index** on `user_agent` (free text, never a query key; impact §9 confirms).
- **No backfill** — historical rows keep `NULL` (Gap 6, accepted).
- `ddl-auto=validate`: the `AuthEvent.userAgent` field (below) **must land in the same PR** as this migration or boot fails validation. This couples WS-6 entity + migration into one task.
- `IdentitySchemaMigrationIT` — add a column-presence assertion for `auth_events.user_agent`.

### 3.2 Storage shape decision (Open Unknown #6)
**First-class column AND mirrored in `metadata` JSON.** AC2 lists `user_agent` as a schema-level field → a queryable column is required. It is *also* emitted into `metadata` by `RequestContext.toMetadataJson()` (matching the documented shape in `observability-standards.md:199-204`, which shows `userAgent` inside `metadata`). The minor duplication is intentional: the column serves future EPIC-007 filtering; the JSON serves log/shape continuity. `correlation_id` stays in `metadata` only (already there as `traceId`; AC2's "correlation_id" is satisfied by the existing `traceId` JSON field — **no new column**, recorded here as the explicit decision so it isn't re-litigated).

### 3.3 Entity & RequestContext changes (component side of WS-6)

`AuthEvent` gains a column + builder:
```java
@Column(name = "user_agent", length = 512)
private String userAgent;

public AuthEvent withUserAgent(String userAgent) { this.userAgent = userAgent; return this; }
```

`common/domain/RequestContext.java` becomes a **3-arg record** `(String ipAddress, String traceId, String userAgent)`:
- 512-char truncation + JSON-escape applied inside the record (reuse existing private `jsonEscape`); a static factory keeps construction clean:
  ```java
  public static RequestContext of(String ipAddress, String traceId, String userAgent) { ... }  // truncates userAgent to 512
  public static final RequestContext UNKNOWN = new RequestContext("unknown", null, null);
  ```
- `toMetadataJson()` extends to append `"userAgent":"..."` (escaped) when non-null.

**Arity ripple (must all change in one PR — source-incompatible but fully internal, no published API):**
- Production: `LoginController:114`, `RegistrationController` (its `requestContext`), `PasswordResetController:309-311`, `RequestContext.UNKNOWN`.
- Controllers read `req.getHeader("User-Agent")` and pass it through.
- Tests hard-coding 2-arg: `ForgotPasswordUseCaseTest`, `ResetPasswordUseCaseTest`, `LoginUseCaseSecurityTest`, `LoginUseCaseTest` (and any others) — sweep to 3-arg.

### 3.4 Security note (feeds threat model)
`User-Agent` is fully attacker-controlled, unbounded. Controls: 512-char cap (row-bloat + JSON-column bloat) and `jsonEscape` (JSON-injection into the native `JSON` column). `CorrelationIdFilter`'s charset restriction does **not** cover `User-Agent` (different header) → escaping is the only injection control. Stored-XSS on render is an EPIC-007 obligation (escape-on-render) and is flagged here for the threat model, not solved in this story.

---

## 4. WS-3 — In-Process Bounded Retry Buffer + Ops Alert (highest risk)

Per OQ-3: synchronous write stays the primary path; on failure, enqueue to a bounded in-memory buffer with scheduled backoff retry; alert ops on backlog/exhaustion. **Zero new dependencies** (JDK `BlockingQueue` + Spring `@Scheduled` + Micrometer — all on classpath). New ADR **0011** records this (see §11).

### 4.1 Concrete SLO / capacity parameters (Open Unknown #3 — resolves Gaps 1 & 2)

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Buffer capacity | **1000 events total, split into two lanes: 200 priority + 800 standard** | At the load-test target of 100 RPS (Test Scenario 5), 1000 ≈ 10s of *total* traffic and far more of *failed*-write traffic. Bounded to cap heap (≈1000 × ~1KB AuthEvent ≈ 1MB worst case). The split closes threat-model finding **T-D1** (a login-failure flood during a DB outage could otherwise evict newer LOCKOUT events from a single FIFO lane). |
| Lane assignment | **Priority lane:** `LOCKOUT`, `TOKEN_REFRESH_REUSE`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED_WRITE_FAILED`. **Standard lane:** every other `AuthEventType` (incl. `LOGIN_FAILURE`, `LOGIN_SUCCESS`, `REGISTER`, `VERIFY`, etc.) | These four types are the highest-value forensic/security-incident signals (account-compromise indicators) and are also comparatively low-volume relative to `LOGIN_FAILURE` noise — reserving capacity for them is cheap and directly addresses T-D1 without complicating the common path. |
| Overflow policy | **Drop-newest within each lane independently** (reject incoming, increment a per-lane drop counter); **the standard lane filling never displaces or blocks the priority lane** | The buffer only fills when the DB is already failing; dropping the *newest* preserves the oldest events (closest to the incident's root cause) and keeps the enqueue path O(1) and non-blocking (the 5ms budget, OQ-4). Drop-oldest was rejected: it would silently destroy the earliest evidence. Block/reject-caller was rejected: it would propagate DB outage into the auth path, violating AC4. Two independent lanes (rather than one FIFO) ensure a `LOGIN_FAILURE` flood can saturate and drop from the standard lane while the priority lane — and therefore `LOCKOUT` — remains available. |
| Retry backoff schedule | **1s → 5s → 30s → 2m → 10m**, 5 attempts max, identical for both lanes | Fast first retries ride out transient blips (lock waits, failover); widening intervals avoid hammering a down DB. After attempt 5 the event is **dropped + exhaustion counter incremented + alert fired**. |
| Drain interval | **`@Scheduled(fixedDelay = 10s)`**, priority lane drained before standard lane each tick | A single drainer thread polls due-for-retry events every 10s, processing the priority lane to completion first so security-critical events get DB-write priority during recovery. `fixedDelay` (not `fixedRate`) prevents overlapping drains under a slow DB. |
| Depth-warn threshold | **≥ 250 standard-lane events for 1 min, OR any priority-lane depth ≥ 1 for 1 min** → ticket | 25% of the standard lane sustained = DB write path degraded but recoverable. Any sustained priority-lane backlog is itself worth a ticket given its low expected volume. |
| Depth-critical threshold | **≥ 720 standard-lane (90% of 800) for 1 min, OR priority-lane ≥ 180 (90% of 200) for 1 min** → page | 90% full = imminent drop; aligns with the existing "DB connection pool exhausted >90%" page convention (`observability-standards.md:182`). |
| Age-critical threshold | **oldest un-drained event in either lane > 15 min** → page | Bounds the audit-completeness gap; matches the 1-year-retention seriousness of audit data. |
| Max event-loss window (accepted residual) | **≤ buffer contents at crash (≤ 1000 events across both lanes)** | In-memory buffer does **not** survive pod restart/crash (explicitly accepted in OQ-3; no durable outbox/broker for MVP). Documented in ADR 0011. Escape hatch: `nexus.identity.audit.retry-buffer.enabled=false` reverts to synchronous-swallow-and-WARN only (single-lane behavior, no priority distinction). |

### 4.2 Components (infrastructure)

`identity/infrastructure/audit/AuthEventRetryBuffer.java` — **infrastructure**, `@Component`.
Responsibilities: bounded queue of failed events with per-event attempt count + next-retry time; non-blocking enqueue; scheduled drain that re-invokes the synchronous insert; depth/age/drop/exhaustion accounting; Micrometer registration.

```java
@Component
public class AuthEventRetryBuffer {

  AuthEventRetryBuffer(JpaAuthEventRepository repository,   // direct repo, NOT the adapter, to avoid re-enqueue recursion
                       AuditAlertPort alertPort,
                       MeterRegistry meterRegistry,
                       Clock clock,
                       AuditRetryProperties props);

  /** Non-blocking. Routes to the priority or standard lane based on AuthEventType.isPriority().
      Returns false and increments that lane's drop counter if its capacity is full (drop-newest).
      A full standard lane never blocks or evicts from the priority lane, and vice versa. */
  boolean enqueue(AuthEvent event);

  /** Scheduled drain: drains the priority lane to completion first, then the standard lane;
      retries all events whose next-retry time is due; backoff or drop-on-exhaustion per lane. */
  @Scheduled(fixedDelayString = "${nexus.identity.audit.retry-buffer.drain-interval-ms:10000}")
  void drain();

  int depth(AuditLane lane);                 // gauge source, per lane
  long oldestAgeSeconds(AuditLane lane);      // gauge source, per lane
}

enum AuditLane { PRIORITY, STANDARD }
```

A small `record BufferedAuthEvent(AuthEvent event, int attempts, Instant nextRetryAt)` holds retry state. **Two independent queues**, each an `ArrayBlockingQueue<BufferedAuthEvent>` — priority lane capacity 200, standard lane capacity 800 (§4.1). `enqueue` first resolves the lane via `AuthEventType.isPriority()` (a new method on the WS-1 enum: `true` for `LOCKOUT`, `TOKEN_REFRESH_REUSE`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED_WRITE_FAILED`; `false` otherwise), then `offer(...)`s onto that lane's queue (non-blocking, returns false when that lane is full → drop-newest within the lane only).

`identity/infrastructure/audit/AuditRetryProperties.java` — `@ConfigurationProperties("nexus.identity.audit.retry-buffer")`: `enabled`, `priority-capacity` (200), `standard-capacity` (800), `drain-interval-ms`, `max-attempts`, `backoff-schedule` (list of durations), `depth-warn`, `depth-critical`, `age-critical` (the latter three accept per-lane overrides, defaulting per §4.1's table).

`identity/infrastructure/audit/SchedulingConfig.java` — `@Configuration @EnableScheduling` (JaCoCo-excluded config class). **Design-time check:** verified no other `@EnableScheduling` exists in `src/main`; this is the single enablement point. Guard with `@ConditionalOnProperty(name="nexus.identity.audit.retry-buffer.enabled", havingValue="true", matchIfMissing=true)` so the escape hatch also disables the scheduler.

### 4.3 `JpaAuthEventAdapter` change

```java
@Override
public void record(AuthEvent event) {
  try {
    authEventRepository.save(event);
  } catch (DataAccessException e) {
    log.warn("Audit write failed [type={}] — enqueueing for retry: {}",
        event.getEventType(), e.getMessage());
    retryBuffer.enqueue(event);   // never throws; drop-newest if full
  }
}
```
- The 5ms budget (OQ-4) applies only to this `catch` + `enqueue` path (O(1) `offer`), **not** the synchronous insert baseline.
- `AuthEventPort` Javadoc updated: "...on failure, implementations enqueue for bounded retry; the call never throws and never blocks the primary flow."
- To avoid a re-enqueue loop, the buffer's `drain()` calls `repository.save(...)` **directly** (not back through the adapter).

### 4.4 Ops alert port (Open Unknown #7 — interface only, no vendor)

`identity/application/port/out/AuditAlertPort.java` — **application.port.out**:
```java
public interface AuditAlertPort {
  /** Raised when the retry buffer crosses a depth/age threshold or exhausts retries for an event.
      Implementations must be non-throwing and side-effect-cheap (no synchronous network call on the
      hot path -- fan out asynchronously if a real channel is later wired). */
  void raise(AuditAlert alert);
}
```
`identity/domain/AuditAlert.java` (domain record): `(AuditAlertType type, String message, Instant occurredAt, int bufferDepth)` with `enum AuditAlertType { BUFFER_DEPTH_WARN, BUFFER_DEPTH_CRITICAL, BUFFER_AGE_CRITICAL, RETRY_EXHAUSTED }`.

`identity/infrastructure/audit/LoggingAuditAlertAdapter.java` — **infrastructure**, the only concrete adapter shipped: logs at `WARN`/`ERROR` by severity and increments a Micrometer counter tagged by `type`. **No Slack/PagerDuty/etc.** — a real channel is wired later by replacing/supplementing this adapter behind the port (Gap 2; out of this team's control per requirements). This keeps WS-3 testable and complete today while leaving channel choice to ops.

### 4.5 Micrometer metric names (concrete)

| Metric | Type | Tags | Meaning |
|--------|------|------|---------|
| `nexus.audit.buffer.depth` | Gauge | `lane=priority\|standard` | Current buffered (un-drained) events, per lane |
| `nexus.audit.buffer.oldest.age.seconds` | Gauge | `lane=priority\|standard` | Age of oldest buffered event, per lane |
| `nexus.audit.retry.success` | Counter | `lane=priority\|standard` | Buffered events later persisted |
| `nexus.audit.retry.exhausted` | Counter | `lane=priority\|standard` | Events dropped after max attempts |
| `nexus.audit.buffer.dropped` | Counter | `reason=overflow`, `lane=priority\|standard` | Drop-newest on full buffer, per lane |
| `nexus.audit.alert.raised` | Counter | `type=<AuditAlertType>` | Alerts emitted via `AuditAlertPort` |

Scraped via existing `/actuator/prometheus`. Dashboard sketch: one row per lane — depth gauge + oldest-age gauge (left), retry-success vs exhausted+dropped rate (right), alert-raised count by type (bottom). Alert rules map 1:1 to the §4.1 thresholds. The priority-lane panels are the ones that matter most during an incident: if priority-lane depth/age stays near zero while standard-lane drops climb, the system is behaving as designed (T-D1 mitigated).

### 4.6 Alternatives considered (WS-3 — highest risk, required by brief)

| Option | Rejected because |
|--------|------------------|
| **`@Async` + `ApplicationEventPublisher` reuse** (the existing `MailEventListener` pattern) | That path is fire-and-forget with **no retry, no bounded backpressure, no depth visibility** — it would re-create the exact silent-loss gap AC4 targets. Async hand-off also moves the write off the request thread, complicating the "audit within 1s" (AC1) timing assertion. Rejected. |
| **Transactional outbox table + poller** | Durable across restarts (would eliminate the accepted data-loss residual) but: needs a new table, a poller, and its own append-only/cleanup story — materially larger than MVP, and the outbox write *itself* hits the same DB that's presumed down in the failure scenario. Deferred; called out in ADR 0011 as the upgrade path if compliance later mandates zero-loss. |
| **Resilience4j / Spring Retry dependency** | New dependency for behavior the JDK already provides (`ArrayBlockingQueue` + `@Scheduled`). Impact §9 and ADR 0009's "no new dep until justified" stance both push back. Rejected for MVP. |
| **Redis-backed queue** | ADR 0009 explicitly defers Redis; reintroducing it here is out of scope and contradicts the "boring tech / no new infra" posture. Rejected. |
| **Unbounded queue** | OOM risk under sustained DB outage — turns an audit-store outage into an app crash. Rejected in favor of the bounded + drop-newest design. |
| **Single FIFO lane (no priority split)** | Simpler, but a `LOGIN_FAILURE` flood during a DB outage can evict newer `LOCKOUT` events before they drain (threat model **T-D1**, High severity) — the exact scenario a security/compliance audit log must not have a blind spot for. Rejected in favor of the two-lane (200 priority / 800 standard) design in §4.1, which costs one `enum.isPriority()` check and a second bounded queue — small complexity for closing a High-severity finding. |

---

## 5. WS-4 — `tenant_id` Population (Open Unknown #5)

`AuthEvent` gains `withTenantId(UUID)` (mirrors `withUserId`):
```java
public AuthEvent withTenantId(UUID tenantId) { this.tenantId = tenantId; return this; }
```

Per-flow tenant source (verified per file):

| Flow / file | tenant source | NULL when |
|-------------|---------------|-----------|
| `LoginUseCase` | `tenantId` param — set on success + all **post-resolution** events (LOCKED pre-check, PENDING, non-ACTIVE, UNLOCKED, SUCCESS) | the unknown-email `LOGIN_FAILURE` (no user) stays NULL |
| `SecureEventService.persistFailedAttempt` (LOCKOUT) | `user.getTenantId()` (user is loaded here) | n/a — always resolvable in this method |
| `RegisterUserUseCase` | `tenantId` param — `REGISTER` + `REGISTRATION_DUPLICATE_EMAIL` | n/a |
| `ForgotPasswordUseCase` | `tenantId` param — resolved-user events (REQUESTED, THROTTLED) | unknown-email fast path emits no event |
| `ResetPasswordUseCase` | `user.getTenantId()` after load (PASSWORD_CHANGED) | pre-user-resolution `PASSWORD_RESET_FAILED` stays NULL |
| `VerifyEmailUseCase` | `user.getTenantId()` after load (VERIFY) | token-not-found / pre-load `VERIFICATION_FAILED` stays NULL |
| `RefreshTokenUseCase` | `user.getTenantId()` after Step 6 load (TOKEN_REFRESH_SUCCESS) | pre-lookup failures + `TOKEN_REFRESH_REUSE` (only `token.getUserId()` known) stay NULL |
| `ResendVerificationUseCase` | `tenantId` param — RESEND_REQUESTED / RESEND_THROTTLED | n/a |
| **`LogoutUseCase`** | **NULL accepted — no extra lookup** (Open Unknown #5 decision) | always NULL |

**Logout decision (Open Unknown #5): accept NULL, do not add a lookup.** Adding a `findById` purely to populate `tenant_id` on a LOGOUT event would add a DB round-trip to every logout for a low-value field — the user is frequently resolved only from the refresh-cookie hash, not a `User` load. NULL is consistent with the existing nullable `tenant_id`/`user_id` pattern and EPIC-007 already must tolerate NULL tenant on pre-auth rows. Recorded as accepted.

No DDL (column exists). `AuthAuditIT` gains assertions: post-auth events carry expected `tenantId`; pre-auth/logout events carry NULL.

---

## 6. WS-2 — Least-Privilege DB Role (Open Unknown #2)

Per OQ-2: **additive defense-in-depth alongside the retained triggers.** New ADR **0012** (see §11).

### 6.1 Topology decision — single least-privilege app user, single DataSource

**Decision: the whole application connects as ONE non-root user that has `INSERT, SELECT` on `auth_events` and full DML on the other identity tables. Reject a second DataSource dedicated to the audit write path.**

Justification:
- A second `DataSource` would mean a second connection pool, a second `PlatformTransactionManager`, and routing logic — and would directly collide with the REQUIRES_NEW pattern (`SecureEventService` would need to know which manager to join). That is a large structural change for a defense-in-depth control whose *functional* guarantee (no UPDATE/DELETE) is already delivered by the triggers.
- A single least-privilege user achieves AC3's "INSERT/SELECT only on `auth_events`" intent (the app literally cannot UPDATE/DELETE audit rows even if a trigger were dropped) while keeping one pool, one TX manager, and the existing REQUIRES_NEW semantics untouched.
- The triggers remain as belt-and-suspenders (kept per OQ-2).

Grant shape (the app user — `nexus_app`):
```sql
-- auth_events: append + read only (no UPDATE/DELETE) -- privilege-level backstop to the triggers
GRANT INSERT, SELECT ON nexus.auth_events TO 'nexus_app'@'%';
-- all other identity tables: normal DML
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users          TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.refresh_tokens TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_tokens    TO 'nexus_app'@'%';
```

### 6.2 Where grant DDL lives (per environment) — NOT a Flyway migration

**Decision: grants are provisioned out-of-band, not in a `V<N>` migration.** Flyway runs as the *migration* user and grant DDL is environment-specific (Testcontainers vs dev vs prod use different credentials and host specs `@'%'` vs `@'localhost'`); a versioned migration would be fragile and would couple schema history to credential topology. Placement:

| Environment | Mechanism |
|-------------|-----------|
| **Testcontainers (`*IT`)** | An init SQL script mounted via `withInitScript(...)` (or a `@DynamicPropertyRegistrar`-time `CREATE USER`/`GRANT`) that creates `nexus_app` with the restricted grant, so the privilege-level append-only `*IT` runs as that user. Flyway still runs as root inside the container. |
| **Local dev (docker-compose)** | A new `mysql/init/01-grants.sql` mounted into `/docker-entrypoint-initdb.d`; `docker-compose.yml` switches `DB_USERNAME` from `root` to `nexus_app`. (Migrations may still be applied by a separate root-credentialed Flyway run, or by granting the migration user DDL on first boot.) |
| **Prod** | Handed to ops as a runbook step (credential creation + rotation). `application-prod.*` is hook-denied to Claude (CLAUDE.md) — wiring is explicitly out-of-band. ADR 0012 records the rotation expectation. |

### 6.3 Migration interplay
Flyway needs DDL privileges to apply `V5`; the **restricted `nexus_app` user is for runtime, not migration**. Keep migration execution under a DDL-capable credential (root in dev/Testcontainers; a dedicated migration user in prod). This separation is the standard Flyway-owns-schema posture (ADR 0003) and must be documented in ADR 0012 so nobody grants `nexus_app` DDL by mistake.

### 6.4 Test
New `*IT` (Testcontainers, running as `nexus_app`): assert `UPDATE`/`DELETE` on `auth_events` is **denied at the privilege level** (distinct from `AuthEventsAppendOnlyIT`'s trigger proof). `INSERT` and `SELECT` succeed.

---

## 7. WS-5 — Transaction-Durability Standardization & the Logout/Register Atomicity Decision (Open Unknown #4)

OQ-6 said "standardize Logout + Register onto REQUIRES_NEW." Impact §6 flagged that doing so **breaks `LogoutUseCase`'s documented atomicity invariant** (revocation + audit commit together to prevent a "phantom LOGOUT" with no revocation) and creates an analogous "REGISTER event for a user that doesn't exist" hazard.

### 7.1 Decision — resolve the tension by NOT moving Logout/Register to REQUIRES_NEW

**Keep `LogoutUseCase` and `RegisterUserUseCase` audit writes in the same outer transaction as their primary operation. Achieve OQ-6's durability *intent* through the WS-3 retry buffer, not through REQUIRES_NEW.**

Reasoning:
- **The REQUIRES_NEW pattern (ADR 0009) was introduced specifically for writes that must survive an *outer-TX rollback caused by a thrown exception on the failure path*** — Login failure throws `AuthenticationException`, Reset failure throws `TokenExpiredException`, and the audit row must outlive that rollback. **Logout and Register have no such rollback-on-throw audit requirement:** their happy paths *commit*, and their audit events describe the very operation in that committing transaction. Same-TX is therefore the *correct* durability model for them, not an oversight to "fix."
- For Logout specifically, REQUIRES_NEW would actively *regress* a deliberate, documented security invariant: a refresh-token-revocation rollback after a committed REQUIRES_NEW audit row would record a LOGOUT that never revoked anything — a phantom logout. The existing Javadoc is correct; honor it.
- For Register, REQUIRES_NEW could record a `REGISTER` for a user whose `INSERT` later rolls back — an audit row referencing a non-existent user. Same-TX prevents this by construction.
- **OQ-6's real concern — "a rollback silently drops the audit row with no alert" — is now addressed by WS-3 at the infrastructure layer, not by transaction propagation.** With same-TX commits, the only way the audit row is lost is if the *whole operation* also rolled back (in which case there is nothing to audit — correct). And any *persistence-level* failure of the audit insert (the case AC4 cares about) is caught by `JpaAuthEventAdapter` and routed to the retry buffer regardless of which TX it ran in.

This is a justified deviation from OQ-6's literal wording, kept within OQ-6's intent. **ADR 0009 is referenced, not superseded; this design records the Logout/Register exception to the "standardize on REQUIRES_NEW" guidance with the above rationale** (impact §10 noted no new ADR is needed for WS-5 — this design doc is the system of record for the deviation).

### 7.2 What WS-5 actually changes

- **No constructor swap to `SecureEventService` for Logout/Register.** They keep `AuthEventPort`. (This also avoids the `LogoutUseCaseTest`/`RegisterUserUseCaseTest` constructor-mock churn impact §6 predicted — those tests stay structurally intact; only event-name and metadata assertions update.)
- **Logout metadata enrichment is the real WS-5/WS-6 coupling that DOES happen:** `LogoutUseCase.execute` changes signature from `(UUID, String, String clientIp)` to `(UUID, String, RequestContext ctx)` so LOGOUT finally carries `traceId` + `userAgent` (today it carries neither). `LoginController.logout` builds and passes the `RequestContext`. The LOGOUT event gains `.withIpAddress(ctx.ipAddress()).withMetadata(ctx.toMetadataJson())`.
- Net: WS-5 becomes **(a) a metadata-enrichment + signature change for Logout, (b) a no-op on transaction propagation for both flows, (c) durability delegated to WS-3.** Lower risk than the impact doc's REQUIRES_NEW scenario, and it preserves both documented invariants.

---

## 8. Data Flow / Sequence — Login Failure → Lockout → Audit (with audit-store outage)

This composes WS-1 (enum), WS-3 (buffer), WS-4 (tenant), WS-6 (userAgent), and the WS-5 durability model.

```
1.  Client → LoginController: POST /login (bad password)
2.  LoginController builds ctx = RequestContext.of(ip, traceId, User-Agent[<=512, escaped])
3.  LoginController → LoginUseCase.execute(tenantId, email, pwd, ctx)
    (Argon2 always runs -- anti-enumeration; user found, password mismatch)
4.  LoginUseCase → SecureEventService.persistFailedAttempt(userId, now)  [REQUIRES_NEW]
    -- count reaches LOCKOUT_THRESHOLD -> lockAccount()
5.  SecureEventService → AuthEventPort.record(AuthEvent(LOCKOUT, FAILURE)
        .withUserId(...).withTenantId(user.getTenantId()))
6.  JpaAuthEventAdapter → INSERT into auth_events
       healthy:  commits in the REQUIRES_NEW tx
       DB down:  catch DataAccessException, WARN, enqueue(event) to AuthEventRetryBuffer
                 (O(1), non-blocking, <=5ms); if buffer full -> drop-newest,
                 nexus.audit.buffer.dropped++
7.  SecureEventService returns (never throws) -> LoginUseCase
8.  LoginUseCase → SecureEventService.recordEvent(AuthEvent(LOGIN_FAILURE, FAILURE)
        .withIpAddress(...).withMetadata(ctx.toMetadataJson()))  [REQUIRES_NEW]
    -- same INSERT-or-enqueue behavior as step 6
9.  LoginUseCase throws AuthenticationException(AUTH_001)
    -- outer @Transactional rolls back, but LOCKOUT/LOGIN_FAILURE already committed
       via REQUIRES_NEW (or are safely buffered)
10. LoginController → Client: 401 RFC-7807 (code AUTH_001, traceId)

Background (every 10s while buffer non-empty):
    AuthEventRetryBuffer.drain() -> repository.save(event) directly
        success -> nexus.audit.retry.success++, remove from buffer
        still failing -> backoff 1s->5s->30s->2m->10m;
                         on attempt 5 -> AuditAlertPort.raise(RETRY_EXHAUSTED),
                         nexus.audit.retry.exhausted++
        depth >= 900 (1m) OR oldest age > 15m -> raise(BUFFER_DEPTH_CRITICAL / BUFFER_AGE_CRITICAL)
```

**Key composition properties shown:** the auth path always returns its real outcome (401) regardless of audit-store health (AC4); LOCKOUT/LOGIN_FAILURE survive the outer rollback via REQUIRES_NEW (lockout reliability, ADR 0009); on DB outage the events are buffered, not lost (until pod crash — accepted residual); tenant + userAgent + traceId now ride on the events (AC2). Same enqueue/drain mechanics apply identically to the same-TX Logout/Register writes (WS-5) — the buffer is propagation-agnostic.

---

## 9. API, Frontend, Caching — explicit N/A statements

- **API: N/A.** No REST contract changes. No new endpoints, no request/response DTO changes, no status-code changes (impact §9 confirmed). The only controller edits are internal: `RequestContext` construction gains `User-Agent`, and `LoginController.logout` passes a `RequestContext` instead of a bare IP string. `auth_events` has no read API in this story (EPIC-007 is the consumer, out of scope).
- **Frontend: N/A.** Zero Angular changes. No `nexus-frontend/` files touched, no routes, components, services, guards, or state. Confirmed by requirements ("Angular component changes: none") and impact §9.
- **Caching: N/A.** No cache touched or introduced. Nexus does not use Redis (ADR 0009 defers it); the WS-3 buffer is a bounded in-memory retry queue, explicitly **not** a cache, and deliberately does not reintroduce the Redis conversation.

---

## 10. Error Handling, Idempotency, Observability, Feature Flags, Rollout

### 10.1 Error handling & idempotency
- Audit-write failures are **swallowed at the port** and routed to the buffer; they never surface as RFC-7807 errors and never alter the primary flow's status. Primary-flow errors are unchanged (existing `GlobalExceptionHandler`, RFC-7807 with `code` + `traceId`).
- **Idempotency:** each `AuthEvent` carries a pre-generated UUIDv7 `id`. Buffer retries `save()` the *same* entity with the *same* id → a successful retry after a partially-applied earlier attempt cannot create a duplicate (PK collision would be caught and treated as already-persisted). No idempotency key beyond the event id is needed.
- Buffer `drain()` and `enqueue()` are non-throwing; any unexpected exception inside the drainer is caught, logged, and counted (`nexus.audit.retry.exhausted` path) so the scheduler thread never dies silently.

### 10.2 Observability plan
- **Metrics:** the six `nexus.audit.*` metrics in §4.5.
- **Log fields:** existing MDC `traceId` (via `CorrelationIdFilter`) on all paths; audit WARN on each enqueue includes `event_type` (never PII); alert ERROR/WARN includes `AuditAlertType` + `bufferDepth`. **No raw email/password/token** in any audit log line or `auth_events` payload (AC5) — enforced by the new log-scrubbing test.
- **Dashboard:** one Grafana row (depth + oldest-age gauges; retry-success vs exhausted+dropped rates; alert-raised-by-type). Alert rules bind to §4.1 thresholds with runbook links.
- This story completes the `observability-standards.md` Phase-9 checklist item "audit events fired for all security-relevant actions" and implements the already-documented audit-log JSON shape (`userAgent` + `traceId` in `metadata`).

### 10.3 Feature flag strategy
- **Flag:** `nexus.identity.audit.retry-buffer.enabled` (the WS-3 escape hatch from OQ-3). **Default: `true`** (`matchIfMissing=true`). When `false`, `JpaAuthEventAdapter` reverts to synchronous-swallow-and-WARN only (today's behavior) and the scheduler is not enabled. This is the documented fallback to synchronous-only if the buffer proves too costly.
- The taxonomy rename, `tenant_id` population, `user_agent` column, and Logout enrichment are **not** flagged — they are correctness/schema changes with no consumer to gate against (EPIC-007 not started); a flag would be dead config.

### 10.4 Rollout plan
- **Migration V5** is additive/nullable → zero-downtime, no expand/contract (ADR 0003). Deploy migration with the code that adds the `userAgent` field (same PR, `ddl-auto=validate`).
- **WS-2 (DB user):** stage independently — provision `nexus_app` + grants and flip `DB_USERNAME` in dev first, validate the privilege-level `*IT`, then hand the prod runbook to ops. The triggers remain throughout, so a misconfigured grant cannot weaken append-only enforcement.
- **WS-3:** ship enabled by default but **gradual confidence**: deploy, watch `nexus.audit.buffer.dropped` and `nexus.audit.retry.exhausted` stay at zero under normal load, run the load test (100 RPS / 10 min) and the audit-store-down `*IT` in CI before promoting. Instant rollback path = set the flag to `false`.
- **Sequencing recommendation (matches impact risk):** WS-1 (enum) → WS-6 (column + RequestContext) → WS-4 (tenant) → WS-5 (logout enrichment) → WS-2 (DB user) → **WS-3 last** (highest risk, most threat-modeled).

---

## 11. ADRs Required

| ADR | Title | Records |
|-----|-------|---------|
| **0011** | In-process bounded retry buffer for audit writes | JDK-primitives-not-new-dep; two-lane design (200 priority / 800 standard, 1000 total) to prevent security-critical event eviction under flood+outage (threat model T-D1); drop-newest overflow per lane; backoff 1s→5s→30s→2m→10m (5 attempts); 10s drain, priority lane first; accepted data-loss-on-restart residual; the synchronous-only escape-hatch flag; SLO thresholds; outbox as the future zero-loss upgrade path |
| **0012** | Least-privilege runtime DB user for `auth_events` | Single `nexus_app` user (INSERT/SELECT on `auth_events`), single DataSource (second-DataSource rejected); grants provisioned out-of-band per environment (not Flyway); migration runs under a separate DDL credential; rotation handed to ops; layered on the retained triggers |

WS-1 and WS-5 need **no new ADR**: WS-1 is a refactor (mapping table in §2.2 is the record); WS-5 is governed by ADR 0009, with the Logout/Register same-TX deviation recorded in §7 of this document.

---

## 12. Task Seeds (for `/breakdown` — one line per implementable unit; NOT the task breakdown)

1. Create `AuthEventType` enum (domain) with `wireName`; add enum-constructor overload to `AuthEvent`; add `AuthEventTypeTest`.
2. Sweep all 8 call sites (6 use cases + `ResendVerificationUseCase` + `SecureEventService`) from String literals to `AuthEventType`; apply the 4 renames.
3. Update breaking tests for the rename (`SecureEventServiceTest`, `AuthAuditIT`, use-case unit tests).
4. Migration `V5__auth_events_add_user_agent.sql`; add `AuthEvent.userAgent` column + `withUserAgent`; extend `IdentitySchemaMigrationIT`.
5. Make `RequestContext` 3-arg (add `userAgent`, 512-cap, escape, extend `toMetadataJson`); fix all call sites + tests (arity ripple).
6. Controllers read `User-Agent` header into `RequestContext` (Login, Registration, PasswordReset).
7. Add `AuthEvent.withTenantId`; populate `tenant_id` per §5 table across the flows; assert in `AuthAuditIT`.
8. Change `LogoutUseCase.execute` to take `RequestContext`; enrich LOGOUT with ip + metadata; update `LoginController.logout`; keep same-TX (no REQUIRES_NEW); update `LogoutUseCaseTest` assertions.
9. Confirm Register stays same-TX with metadata; verify `RegisterUserUseCaseTest` event assertions.
10. `AuditAlertPort` (application) + `AuditAlert`/`AuditAlertType` (domain) + `LoggingAuditAlertAdapter` (infra).
11. `AuthEventRetryBuffer` (infra), two-lane (priority/standard) per §4.1-§4.2, + `AuthEventType.isPriority()` (WS-1 enum) + `AuditRetryProperties` + `SchedulingConfig` (`@EnableScheduling`, conditional); register the 6 Micrometer metrics with `lane` tags.
12. Extend `JpaAuthEventAdapter.record` to enqueue on failure; update `AuthEventPort` Javadoc; extend `JpaAuthEventAdapterTest`.
13. Provision `nexus_app` least-privilege user: Testcontainers init/grant, `docker-compose` init SQL + `DB_USERNAME` switch, prod runbook stub.
14. New `*IT`s: privilege-level append-only (runs as `nexus_app`); audit-store-down → auth succeeds + event buffered + drains on recovery; `auth_events`-payload log-scrubbing test (AC5).
15. Write ADR 0011 and ADR 0012.
16. Load-test harness: 100 RPS / 10 min sustained login, assert no event loss while DB healthy (Test Scenario 5).
17. Add Grafana dashboard panels + alert rules bound to §4.1 thresholds; update `observability-standards` Phase-9 checkboxes.

---

### File paths referenced (all absolute)
- This design: `C:\entomo\AI\nexus\docs\features\US-008\03-design.md`
- Inputs: `C:\entomo\AI\nexus\docs\features\US-008\01-requirements.md`, `C:\entomo\AI\nexus\docs\features\US-008\02-impact.md`
- Format precedent: `C:\entomo\AI\nexus\docs\features\US-007\03-design.md`
- Verified sources: `nexus-backend\src\main\java\com\example\nexus\identity\domain\AuthEvent.java`, `...\identity\domain\User.java`, `...\identity\application\service\SecureEventService.java`, `LoginUseCase.java`, `LogoutUseCase.java`, `RefreshTokenUseCase.java`, `...\identity\application\RegisterUserUseCase.java`, `VerifyEmailUseCase.java`, `ForgotPasswordUseCase.java`, `ResetPasswordUseCase.java`, `ResendVerificationUseCase.java`, `...\identity\application\port\out\AuthEventPort.java`, `...\identity\infrastructure\persistence\JpaAuthEventAdapter.java`, `...\common\domain\RequestContext.java`, `...\identity\interfaces\rest\LoginController.java`, `nexus-backend\src\main\resources\db\migration\V2__identity_schema.sql`, `docker-compose.yml`, `nexus-backend\src\main\resources\application.yml`, `nexus-backend\pom.xml`
- ADRs: `C:\entomo\AI\nexus\docs\adr\0003-flyway-schema-migrations.md`, `C:\entomo\AI\nexus\docs\adr\0009-requires-new-transaction-for-lockout-counters.md` (next free: 0011, 0012)
- Standards: `C:\entomo\AI\nexus\docs\observability-standards.md`, `docs/ARCHITECTURE.md`, `docs\coding-standards.md`
