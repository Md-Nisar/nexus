# US-008 — Task Breakdown

_Output of `/breakdown` (architect + backend-engineer + qa-engineer). Gate 3 deliverable. Turns the approved, Gate-2-amended design (`03-design.md`, incl. the two-lane priority/standard retry buffer) and threat model (`03b-threat-model.md`) into a sequenced, implementable task list. No design decisions are re-opened here._

**Test-first.** Backend tasks use Spring Boot 4 / Java 25 / JUnit 5 + Testcontainers MySQL conventions (no H2 for `*IT`, per TESTING.md). **Zero frontend** — the design declares Angular/API/Caching explicitly N/A (`03-design.md` §9). Owner role is `backend-engineer` or `qa-engineer` only.

**Sequencing follows the design's own recommended order (`03-design.md` §10.4):** WS-1 (enum) → WS-6 (column + RequestContext) → WS-4 (tenant) → WS-5 (logout enrichment) → WS-2 (DB user) → **WS-3 last** (highest risk, most threat-modeled, two-lane buffer). Tasks within a wave can be parallelised; cross-wave dependencies are explicit.

**Size legend:** S = <0.5d, M = 0.5–1.5d, L = 1.5–3d. **Risk** flagged per task; WS-3 tasks carry the story's highest risk (concurrency correctness, accepted data-loss-on-restart residual, scheduler lifecycle).

---

## Task Map

```
T-08-01 (V5 migration + AuthEvent.userAgent column + IdentitySchemaMigrationIT)   -- must go first (DDL/validate coupling)
   |
T-08-02 (AuthEventType enum + isPriority() + AuthEvent enum ctor + AuthEventTypeTest)   -- parallel with T-08-01
   |
   +--> T-08-03 (sweep 8 call sites to enum + 4 renames; fix breaking unit/IT assertions)        [needs 02]
   |
   +--> T-08-04 (RequestContext -> 3-arg userAgent; toMetadataJson; T-T1/T-T2 tests; arity sweep) [needs 01]
   |        +--> T-08-05 (controllers read User-Agent header)                                     [needs 04]
   |
   +--> T-08-06 (AuthEvent.withTenantId + per-flow tenant population + AuthAuditIT/T-I5/T-E4)     [needs 02,03]
   |
   +--> T-08-07 (LogoutUseCase RequestContext signature + metadata enrich; same-TX; T-R1)         [needs 04,05]
        +--> T-08-08 (Register same-TX confirm + metadata; T-R2)                                  [needs 02,03,06]

T-08-09  (ADR 0012 least-privilege DB role)                                -- alongside WS-2
T-08-10  (nexus_app provisioning: Testcontainers + docker-compose + prod runbook stub; T-E2/T-E3)
T-08-11  (privilege-level append-only *IT as nexus_app; T-T3/T-E1)          [needs 10]
T-08-12  (runtime DB-privilege self-check actuator/WARN; T-E2/T-T4)         [needs 10]

T-08-13  (ADR 0011 two-lane retry buffer)                                   -- alongside WS-3
T-08-14  (AuditAlertPort + AuditAlert/AuditAlertType + LoggingAuditAlertAdapter)  [needs 02]
T-08-15  (AuthEventRetryBuffer two-lane + AuditRetryProperties + SchedulingConfig + 6 metrics)  [needs 02,14]
T-08-16  (JpaAuthEventAdapter enqueue-on-failure + port Javadoc + adapter test)   [needs 15]
T-08-17  (buffer unit tests: T-D1 lane isolation, T-D2 overflow, T-D4 drainer-survives, idempotency)  [needs 15]
T-08-18  (audit-store-down *IT: buffer + drain on recovery + alert; T-R3)   [needs 16,11]
T-08-19  (auth_events payload PII/log-scrub test, all 8 flows; AC5/T-I3/T-I1)  [needs 03,04,06,07,08]
T-08-20  (load test 100 RPS/10min, no loss healthy; failure-path <=5ms; T-D3 / Test Scenario 5)  [needs 16]
T-08-21  (Grafana panels + alert rules + observability-standards Phase-9 checkboxes + T-I2 EPIC-007 note)  [needs 15,18]
```

---

## WAVE 1 — Foundations (WS-1 + WS-6 DB)

### T-08-01 — Flyway migration (`user_agent` column) + `AuthEvent.userAgent` + schema IT

- **Owner:** backend-engineer
- **Depends on:** none (foundational — must merge first; `ddl-auto=validate` couples migration + entity field in one PR)
- **Size / Risk:** S / Low
- **Files:**
  - **Create** `nexus-backend/src/main/resources/db/migration/V5__auth_events_add_user_agent.sql` (additive `ALTER TABLE auth_events ADD COLUMN user_agent VARCHAR(512) NULL AFTER ip_address`; no index; no backfill — `03-design.md` §3.1)
  - **Modify** `identity/domain/AuthEvent.java` — add `@Column(name="user_agent", length=512) private String userAgent;` + `withUserAgent(String)` builder (`03-design.md` §3.3)
  - **Modify** `nexus-backend/.../IdentitySchemaMigrationIT` — add `auth_events.user_agent` column-presence assertion
- **Acceptance criteria:**
  - **AC#:** AC2 (`user_agent` schema field present).
  - **Migration numbering caveat (binding):** Before creating the file, **confirm the next free Flyway version against current `main`** — V1–V3 are on disk, US-007's V4 may or may not be merged. If V4 (or a newer V5) has landed, bump accordingly (V5→V6). Do **not** assume V5; this is an explicit acceptance step, not a default.
  - Migration runs cleanly on a blank Testcontainers MySQL; Flyway checksum stable in CI.
  - Boot succeeds under `ddl-auto=validate` (entity field + column land in the same PR, or boot fails — `03-design.md` §3.1).
  - Column is `VARCHAR(512) NULL`; no index added; historical rows remain `NULL`.
- **Test plan:** `IdentitySchemaMigrationIT` (Testcontainers) asserts column presence/type/nullability; context-loads under `validate`.

---

### T-08-02 — `AuthEventType` enum (+ `isPriority()`) + `AuthEvent` enum constructor

- **Owner:** backend-engineer
- **Depends on:** none (parallel with T-08-01)
- **Size / Risk:** S / Low
- **Files:**
  - **Create** `identity/domain/AuthEventType.java` — enum with per-constant `wireName`; the 9 AC1 canonical names (incl. the 4 renames) + retained granular states; `PRIORITY = EnumSet.of(LOCKOUT, TOKEN_REFRESH_REUSE, PASSWORD_CHANGED, ACCOUNT_LOCKED_WRITE_FAILED)` and `boolean isPriority()` (`03-design.md` §2.1 — `isPriority()` is the Gate-2-amendment routing key for the two-lane buffer)
  - **Modify** `identity/domain/AuthEvent.java` — add `AuthEvent(UUID, AuthEventType, String)` constructor delegating to existing String ctor via `eventType.wireName()`; **retain** the existing `(UUID, String, String)` ctor for the read path / historical literals (`03-design.md` §2.3)
  - **Create** `nexus-backend/.../AuthEventTypeTest` (domain unit)
- **Acceptance criteria:**
  - **AC#:** AC1 (named taxonomy centralised). OQ-1 mapping table (`03-design.md` §2.2) honoured: `ACCOUNT_LOCKED→LOCKOUT`, `REFRESH_FAMILY_REVOKED→TOKEN_REFRESH_REUSE`, `REGISTRATION_SUCCESS→REGISTER`, `VERIFICATION_SUCCESS→VERIFY`.
  - `event_type` stays a `String` column (no `@Enumerated`) — historical non-enum literals must still read.
  - `isPriority()` returns `true` for exactly the 4 priority types, `false` for all others (closes the routing contract that T-08-15/T-08-17 depend on for **T-D1**).
- **Test plan:** `AuthEventTypeTest` — every constant's `wireName()` equals its expected literal (name-stability against accidental rename); `isPriority()` true-set is exactly the 4 priority types; enum covers all literals referenced by the 8 call sites. Companion `toString()`/coverage if any record-style members exist (JaCoCo toString gap — see project memory).

---

### T-08-03 — Sweep 8 call sites to `AuthEventType`; apply 4 renames; fix breaking tests

- **Owner:** backend-engineer
- **Depends on:** T-08-02
- **Size / Risk:** M / Low (mechanical but wide — 8 prod files + ~6 test files)
- **Files (modify):** `LoginUseCase`, `SecureEventService` (`ACCOUNT_LOCKED→LOCKOUT` lines 89/100; keep `ACCOUNT_LOCKED_WRITE_FAILED`), `RefreshTokenUseCase` (`REFRESH_FAMILY_REVOKED→TOKEN_REFRESH_REUSE` line 116), `RegisterUserUseCase` (`REGISTRATION_SUCCESS→REGISTER` line 112), `VerifyEmailUseCase` (`VERIFICATION_SUCCESS→VERIFY` line 107), `ForgotPasswordUseCase`, `ResetPasswordUseCase`, `ResendVerificationUseCase` — all under `identity/application[/service]/` (`03-design.md` §2; `02-impact.md` §2)
  - **Modify tests:** `SecureEventServiceTest` (lines 93/126/184/257 `ACCOUNT_LOCKED→LOCKOUT`), `AuthAuditIT` (line 194 `REFRESH_FAMILY_REVOKED`, lines 316–321 `ACCOUNT_LOCKED`), and any use-case test asserting on `getEventType()` strings.
- **Acceptance criteria:**
  - **AC#:** AC1. All 8 emit sites construct events via `new AuthEvent(id, AuthEventType.X, outcome)`; the 4 renamed literals now persist their new `wireName`.
  - Historical-row tolerance documented: no backfill (Gap 6); `AuthEventsAppendOnlyIT` unaffected (uses ad-hoc literals as trigger fodder).
  - `mvnw verify -DskipITs` green (no stray String literal left; CI catches a missed test literal).
- **Test plan:** updated `SecureEventServiceTest`, `AuthAuditIT`, use-case unit tests assert new `wireName`s end-to-end.

---

## WAVE 2 — `user_agent` carrier + capture (WS-6 component side)

### T-08-04 — `RequestContext` → 3-arg (`userAgent`), `toMetadataJson` extension, T-T1/T-T2 tests, arity sweep

- **Owner:** backend-engineer
- **Depends on:** T-08-01 (column must exist for end-to-end mirroring)
- **Size / Risk:** M / Low–Medium (broadest call-site ripple)
- **Files:**
  - **Modify** `common/domain/RequestContext.java` — record becomes `(String ipAddress, String traceId, String userAgent)`; static `of(...)` factory applies **512-char truncation (by character, not byte)** + reuses existing private `jsonEscape`; `UNKNOWN = new RequestContext("unknown", null, null)`; `toMetadataJson()` appends `"userAgent":"..."` (escaped) when non-null (`03-design.md` §3.3)
  - **Modify (arity sweep, must compile in one PR):** `LoginController`, `RegistrationController`, `PasswordResetController`, plus tests hard-coding 2-arg: `ForgotPasswordUseCaseTest`, `ResetPasswordUseCaseTest`, `LoginUseCaseSecurityTest`, `LoginUseCaseTest` (sweep all) (`03-design.md` §3.3; `02-impact.md` §7)
  - **Create/extend** `nexus-backend/.../RequestContextTest`
- **Acceptance criteria:**
  - **AC#:** AC2 (`user_agent` mirrored into `metadata`), AC5 (escaping discipline).
  - **T-T1 (threat, P0):** `toMetadataJson()` against `User-Agent` payloads containing `"`, `\`, `},{`, control chars, and embedded JSON produces **valid, parser-validated escaped JSON** with no `metadata` key injection (no forged `traceId`/`ip`).
  - **T-T2 (threat, P1):** truncation is **character-based** using `String` length semantics — an over-512 multi-byte UA at the boundary never splits a code point; result ≤512 chars and valid UTF-8.
- **Test plan:** `RequestContextTest` — T-T1 injection cases (assert `JsonParser`-valid + key set unchanged); T-T2 multi-byte boundary + over-cap cases; null-UA omits the key.

---

### T-08-05 — Controllers read `User-Agent` header into `RequestContext`

- **Owner:** backend-engineer
- **Depends on:** T-08-04
- **Size / Risk:** S / Low
- **Files (modify):** `interfaces/rest/LoginController.java`, `RegistrationController.java`, `PasswordResetController.java` — each builds `ctx = RequestContext.of(ip, traceId, req.getHeader("User-Agent"))` (`03-design.md` §3.3; §8 flow step 2)
- **Acceptance criteria:**
  - **AC#:** AC2. The `User-Agent` request header is captured at the interface boundary and threaded through; **API contract unchanged** (`03-design.md` §9 — no new endpoint/DTO/status).
  - **T-S2 / §3.4 doc note:** `user_agent` is advisory forensic context only, never an authz input — captured verbatim (capped+escaped), never parsed for trust. Record the inline comment.
- **Test plan:** existing `@WebMvcTest` controller tests extended to assert the UA header flows into the constructed context (where observable); no status-code change.

---

## WAVE 3 — `tenant_id` population (WS-4)

### T-08-06 — `AuthEvent.withTenantId` + per-flow tenant population + audit assertions (T-I5/T-E4)

- **Owner:** backend-engineer
- **Depends on:** T-08-02, T-08-03
- **Size / Risk:** S–M / Medium (per-flow tenant source differs; pre-auth NULL correctness matters)
- **Files (modify):** `identity/domain/AuthEvent.java` (add `withTenantId(UUID)`); populate per the `03-design.md` §5 per-flow table in `LoginUseCase`, `SecureEventService.persistFailedAttempt` (LOCKOUT via `user.getTenantId()`), `RegisterUserUseCase`, `ForgotPasswordUseCase`, `ResetPasswordUseCase` (from loaded `User`), `VerifyEmailUseCase` (from loaded `User`), `RefreshTokenUseCase` (post-Step-6 `User`), `ResendVerificationUseCase`. **`LogoutUseCase`: accept NULL — no extra lookup** (Open Unknown #5 decision).
  - **Modify** `AuthAuditIT` — tenant assertions.
- **Acceptance criteria:**
  - **AC#:** AC2 (`tenant_id` populated where resolvable; NULL for pre-auth/unknown-tenant, mirroring `user_id` nullable pattern).
  - **T-I5 / T-E4 (threat, P0):** post-auth events carry the **principal-derived** `tenant_id` (from method param resolved from JWT or `user.getTenantId()`), pre-auth events are NULL, and **no `withTenantId(...)` argument traces to client-supplied request body/path** (SECURITY.md §3).
  - No DDL (column already exists); no extra DB round-trip added to Logout.
- **Test plan:** `AuthAuditIT` — login success / LOCKOUT / register / reset / verify / refresh carry expected tenant; unknown-email `LOGIN_FAILURE`, pre-load failures, and LOGOUT carry NULL. Use-case unit tests assert `withTenantId` set where resolvable; a code-review/static assertion that no `withTenantId` arg is request-derived (T-E4).

---

## WAVE 4 — Logout enrichment + Register confirm (WS-5)

### T-08-07 — `LogoutUseCase` `RequestContext` signature + metadata enrichment (same-TX; T-R1)

- **Owner:** backend-engineer
- **Depends on:** T-08-04, T-08-05
- **Size / Risk:** M / Medium (changes a shipped flow's signature; preserves a documented atomicity invariant)
- **Files (modify):** `application/service/LogoutUseCase.java` — signature `execute(UUID, String, String clientIp)` → `execute(UUID, String, RequestContext ctx)`; LOGOUT event gains `.withIpAddress(ctx.ipAddress()).withMetadata(ctx.toMetadataJson())` (now carries `traceId` + `userAgent`, previously neither). **Keep `AuthEventPort` — do NOT swap to `SecureEventService`/REQUIRES_NEW** (`03-design.md` §7.1, §7.2). `LoginController.logout` builds and passes the `RequestContext`. Update `LogoutUseCaseTest` (event-name + metadata assertions only; constructor/mock structure stays intact).
- **Acceptance criteria:**
  - **AC#:** AC1 (LOGOUT), AC2 (LOGOUT now carries `traceId`+`userAgent`).
  - **Justified-deviation record:** Logout audit write stays in the **same outer TX** — this is the design's deliberate deviation from OQ-6's literal "move to REQUIRES_NEW," governed by ADR 0009 + `03-design.md` §7 (no new ADR; §7 is the system of record).
  - **T-R1 (threat, P1):** a forced refresh-token-revocation failure leaves **NO** LOGOUT row (atomicity holds — no phantom logout).
- **Test plan:** `LogoutUseCaseTest` (unit) — LOGOUT event carries ip + `toMetadataJson()`; **new IT** asserting forced revocation rollback → zero LOGOUT rows in `auth_events` (T-R1).

---

### T-08-08 — `RegisterUserUseCase` same-TX confirm + metadata; T-R2 IT

- **Owner:** backend-engineer
- **Depends on:** T-08-02, T-08-03, T-08-06
- **Size / Risk:** S / Low
- **Files (modify):** `application/RegisterUserUseCase.java` — confirm `REGISTER`/`REGISTRATION_DUPLICATE_EMAIL` stay **same-TX via `AuthEventPort`** (no REQUIRES_NEW swap — `03-design.md` §7.1); carry metadata/tenant. Update `RegisterUserUseCaseTest` event assertions (structure intact).
- **Acceptance criteria:**
  - **AC#:** AC1 (REGISTER).
  - **T-R2 (threat, P1):** a registration that rolls back **post-audit** leaves **neither** a `users` row **nor** a `REGISTER` event (no partial "registered + no audit" or "audit + no user" state) — strictly safer than REQUIRES_NEW.
- **Test plan:** `RegisterUserUseCaseTest` (unit) event assertions; **new IT** — forced post-audit rollback → no user row AND no REGISTER event (T-R2).

---

## WAVE 5 — Least-privilege DB role (WS-2) — ADR 0012 alongside

### T-08-09 — ADR 0012: least-privilege runtime DB role for `auth_events`

- **Owner:** backend-engineer (architect-reviewed)
- **Depends on:** none (sequence alongside T-08-10..12)
- **Size / Risk:** S / Low
- **Files (create):** `docs/adr/0012-least-privilege-runtime-db-user-for-auth-events.md`
- **Acceptance criteria (must record — `03-design.md` §11; threats T-T4/T-E2/T-E3):**
  - Single `nexus_app` user (`INSERT, SELECT` on `auth_events`; scoped DML on `users`/`refresh_tokens`/`auth_tokens`); **second-DataSource rejected** (single pool, single TX manager, REQUIRES_NEW untouched).
  - Grants provisioned **out-of-band per environment** (NOT Flyway); migration runs under a **separate DDL-capable credential** — **never grant `nexus_app` DDL** (T-E3).
  - **Accepted residual T-T4:** append-only is enforced against the **application principal + trigger path**, NOT against `root`/DBA; recommend distinct, rotated migration credential and locked-down prod `root`. Rotation handed to ops.
  - Triggers retained as belt-and-suspenders (defense-in-depth).
- **Test plan:** N/A (doc). Cross-referenced by T-08-11/T-08-12 acceptance.

---

### T-08-10 — Provision `nexus_app`: Testcontainers + docker-compose + prod runbook stub (T-E2/T-E3)

- **Owner:** backend-engineer
- **Depends on:** none (T-08-09 in parallel)
- **Size / Risk:** M / Medium (credential/connection-pool/CI-provisioning surface; no business logic)
- **Files:**
  - **Create** `mysql/init/01-grants.sql` (dev) — `CREATE USER`/`GRANT INSERT,SELECT ON nexus.auth_events` + scoped DML (`03-design.md` §6.1)
  - **Modify** `docker-compose.yml` — flip `DB_USERNAME` from `root` to `nexus_app`; mount init SQL into `/docker-entrypoint-initdb.d`; keep a DDL-capable credential for Flyway (`03-design.md` §6.2)
  - **Create/modify** Testcontainers support — `withInitScript(...)` or `@DynamicPropertyRegistrar`-time `CREATE USER`/`GRANT` so `*IT` can run as `nexus_app` while Flyway runs as root (note: DynamicPropertyRegistrar timing gotcha — see project memory)
  - **Create** prod runbook stub (ops-handed; `application-prod.*` is hook-denied — wiring stays out-of-band)
- **Acceptance criteria:**
  - **AC#:** AC3 (privilege-level enforcement provisioned). **T-E1/T-E2 (threat, P0):** flipping `DB_USERNAME` off `root` is a **required** task (the EoP reduction only lands once the app stops using `root`); CI/Testcontainers actually creates `nexus_app` every build so the privilege IT in T-08-11 is never silently skipped.
  - Migration credential and runtime credential are **distinct** (T-E3); `nexus_app` has no DDL.
- **Test plan:** consumed by T-08-11 (the IT runs as `nexus_app`); a CI smoke that the container exposes `nexus_app`.

---

### T-08-11 — Privilege-level append-only `*IT` running as `nexus_app` (T-T3/T-E1)

- **Owner:** qa-engineer
- **Depends on:** T-08-10
- **Size / Risk:** M / Medium
- **Files (create):** `nexus-backend/.../AuthEventsPrivilegeAppendOnlyIT` (Testcontainers, connection as `nexus_app`) — distinct from the existing trigger-based `AuthEventsAppendOnlyIT`
- **Acceptance criteria:**
  - **AC#:** AC3 (UPDATE/DELETE denied at privilege level; INSERT/SELECT succeed). **T-T3 / T-E1 (threat, P0):** `UPDATE`/`DELETE` on `auth_events` denied **at the grant level**; assert the grant is **exactly** `INSERT/SELECT` on `auth_events` + scoped DML — **no `DROP`, `ALTER`, `GRANT`, no UPDATE/DELETE on audit rows** (no over-privilege).
- **Test plan:** the new `*IT` — INSERT/SELECT pass; UPDATE/DELETE/DROP/ALTER/GRANT fail with privilege error; grant-scope assertion via `SHOW GRANTS`.

---

### T-08-12 — Runtime DB-privilege self-check (actuator/WARN) (T-E2/T-T4)

- **Owner:** backend-engineer
- **Depends on:** T-08-10
- **Size / Risk:** S / Low
- **Files (create):** a startup self-check / actuator health indicator in `identity/infrastructure` that logs **WARN** if the live connection's user is `root` or can UPDATE/DELETE `auth_events`
- **Acceptance criteria:**
  - **T-E2 (threat, P0):** an un-provisioned environment (still on `root`, or grant drift) is **detectable at runtime**, closing the silent-window where WS-2 is absent while CI tests pass. **T-T4:** the check makes the app-principal vs `root`/DBA boundary observable (does not constrain `root` — accepted residual, documented in ADR 0012).
- **Test plan:** unit/`@SpringBootTest` — indicator reports DOWN/WARN when connected as an over-privileged user, OK as `nexus_app`.

---

## WAVE 6 — Two-lane retry buffer + alert (WS-3, highest risk) — ADR 0011 alongside

> **WS-3 overall risk note (highest in story, per `02-impact.md` §3 and `03-design.md` §4):** concurrency correctness of two bounded `ArrayBlockingQueue` lanes under load; the **accepted data-loss-on-restart residual** (≤1000 in-flight events, OQ-3 / ADR 0011); scheduler-thread lifecycle; and the now-mitigated-but-still-bounded priority lane (T-D1 residual). Ship enabled-by-default behind the `nexus.identity.audit.retry-buffer.enabled` escape-hatch flag; gradual-confidence rollout with instant flag rollback (`03-design.md` §10.3, §10.4).

### T-08-13 — ADR 0011: in-process two-lane bounded retry buffer

- **Owner:** backend-engineer (architect-reviewed)
- **Depends on:** none (sequence right before/with T-08-15)
- **Size / Risk:** S / Low
- **Files (create):** `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md`
- **Acceptance criteria (must record — `03-design.md` §11, §4.1, §4.6):**
  - JDK-primitives-not-new-dep (`ArrayBlockingQueue` + `@Scheduled` + Micrometer; Resilience4j/Spring Retry/Redis/outbox all rejected with rationale).
  - **Two-lane design (200 priority / 800 standard, 1000 total)** to prevent security-critical event eviction under flood+outage — **closes threat-model T-D1**; drop-newest **per lane**; backoff 1s→5s→30s→2m→10m (5 attempts); 10s drain, **priority lane first**.
  - Accepted residuals: data-loss-on-pod-crash (≤1000 events); **T-D1 residual** (priority lane itself bounded at 200, paged at depth ≥1). Escape-hatch flag. SLO thresholds (§4.1). Outbox named as the future zero-loss upgrade path.
- **Test plan:** N/A (doc).

---

### T-08-14 — `AuditAlertPort` + `AuditAlert`/`AuditAlertType` + `LoggingAuditAlertAdapter`

- **Owner:** backend-engineer
- **Depends on:** T-08-02
- **Size / Risk:** S / Low
- **Files (create):** `identity/application/port/out/AuditAlertPort.java` (port.out); `identity/domain/AuditAlert.java` (record `(AuditAlertType, String, Instant, int bufferDepth)` + `enum AuditAlertType { BUFFER_DEPTH_WARN, BUFFER_DEPTH_CRITICAL, BUFFER_AGE_CRITICAL, RETRY_EXHAUSTED }`); `identity/infrastructure/audit/LoggingAuditAlertAdapter.java` (logs WARN/ERROR by severity, increments `nexus.audit.alert.raised{type}`) (`03-design.md` §4.4)
- **Acceptance criteria:**
  - **AC#:** AC4 (ops-alert hook). Port is non-throwing, no synchronous network call; only the logging adapter ships (no Slack/PagerDuty — channel choice left to ops, Gap 2). Layering: port in application.port.out, adapter+record in infra/domain respectively.
- **Test plan:** `LoggingAuditAlertAdapterTest` — WARN/ERROR by severity; counter incremented; never throws. `AuditAlert` record/`toString()` coverage (JaCoCo toString gap — project memory).

---

### T-08-15 — `AuthEventRetryBuffer` (two-lane) + `AuditRetryProperties` + `SchedulingConfig` + 6 metrics

- **Owner:** backend-engineer
- **Depends on:** T-08-02 (needs `isPriority()`), T-08-14
- **Size / Risk:** L / **High**
- **Files (create, all `identity/infrastructure/audit/`):**
  - `AuthEventRetryBuffer.java` (`@Component`) — **two independent `ArrayBlockingQueue<BufferedAuthEvent>`** (priority cap 200, standard cap 800); non-blocking `enqueue(AuthEvent)` routing via `AuthEventType.isPriority()` (drop-newest **within lane**, returns false on full); `@Scheduled(fixedDelayString=...)` `drain()` draining **priority lane to completion first**, backoff 1s→5s→30s→2m→10m, drop+alert on attempt 5; per-lane `depth(lane)`/`oldestAgeSeconds(lane)` gauges; `enum AuditLane { PRIORITY, STANDARD }`; `record BufferedAuthEvent(AuthEvent, int attempts, Instant nextRetryAt)`. Drain calls `JpaAuthEventRepository.save(...)` **directly** (not via adapter — no re-enqueue loop). (`03-design.md` §4.2)
  - `AuditRetryProperties.java` (`@ConfigurationProperties("nexus.identity.audit.retry-buffer")`): `enabled`, `priority-capacity`, `standard-capacity`, `drain-interval-ms`, `max-attempts`, `backoff-schedule`, per-lane `depth-warn`/`depth-critical`/`age-critical` (`03-design.md` §4.1)
  - `SchedulingConfig.java` (`@Configuration @EnableScheduling`, JaCoCo-excluded) guarded by `@ConditionalOnProperty(name="nexus.identity.audit.retry-buffer.enabled", havingValue="true", matchIfMissing=true)` — verified the single `@EnableScheduling` point (Spring Boot 4 conditional-on-property + DynamicPropertyRegistrar precedence gotcha — see project memory)
- **Acceptance criteria:**
  - **AC#:** AC4 (buffered + retried with backoff). Registers the **6 `nexus.audit.*` Micrometer metrics** with `lane` tags exactly per `03-design.md` §4.5 (`buffer.depth`, `buffer.oldest.age.seconds`, `retry.success`, `retry.exhausted`, `buffer.dropped{reason,lane}`, `alert.raised{type}`). Thresholds raise the correct `AuditAlert` per §4.1.
  - Escape-hatch: `enabled=false` disables scheduler and reverts behaviour (synchronous-swallow-and-WARN) (`03-design.md` §10.3).
- **Test plan:** unit coverage carried mainly by T-08-17; this task ensures the buffer + properties + scheduler config compile, wire, and expose metrics (gauge registration asserted via a `SimpleMeterRegistry`).

---

### T-08-16 — `JpaAuthEventAdapter` enqueue-on-failure + port Javadoc + adapter test

- **Owner:** backend-engineer
- **Depends on:** T-08-15
- **Size / Risk:** S / Low
- **Files (modify):** `infrastructure/persistence/JpaAuthEventAdapter.java` — on `DataAccessException`, WARN (log `event.getEventType()` + `e.getMessage()` **only** — never `user_agent`) then `retryBuffer.enqueue(event)` (never throws); `application/port/out/AuthEventPort.java` Javadoc → "on failure, enqueue for bounded retry; never throws, never blocks." Extend `JpaAuthEventAdapterTest`. (`03-design.md` §4.3)
- **Acceptance criteria:**
  - **AC#:** AC4. Failure path is O(1) non-blocking `offer`; `record` never throws. **T-I1 (threat, P1):** the WARN line interpolates only the enum `wireName` + exception message — **never raw `user_agent`** (asserted again broadly in T-08-19).
- **Test plan:** `JpaAuthEventAdapterTest` — save success path; `DataAccessException` → `enqueue` called, no throw, WARN contains no UA.

---

### T-08-17 — Buffer unit tests: T-D1 lane isolation, T-D2 overflow, T-D4 drainer survival, idempotency

- **Owner:** qa-engineer
- **Depends on:** T-08-15
- **Size / Risk:** M / **High** (concurrency correctness)
- **Files (create):** `nexus-backend/.../AuthEventRetryBufferTest`
- **Acceptance criteria (each a named test case):**
  - **T-D1 (threat, P0 — Gate-2 amendment remaining task):** a **standard-lane-only flood** (sustained `LOGIN_FAILURE` enqueues past the 800 standard capacity) **never reduces priority-lane available capacity and never evicts a priority-lane entry**; a priority-type event still enqueues while the standard lane is saturated. (This is the explicit T-D1 residual task, not just the audit-store-down test.)
  - **T-D2 (threat, P0):** bounded-overflow — enqueue past a lane's capacity returns `false`, increments `nexus.audit.buffer.dropped{lane}`, no unbounded growth (drop-newest).
  - **T-D4 (threat, P0):** a `drain()` iteration that throws does **not** propagate or kill scheduling — exception caught/logged/counted; next tick still runs.
  - **Drain/backoff:** priority lane drained before standard each tick; backoff schedule honoured; attempt-5 → `RETRY_EXHAUSTED` alert + `retry.exhausted{lane}`++.
  - **Idempotency (`03-design.md` §10.1):** re-`save()` of the same `AuthEvent` (same UUIDv7 id) after a partially-applied attempt does not create a duplicate (PK-collision treated as already-persisted).
- **Test plan:** `AuthEventRetryBufferTest` with `SimpleMeterRegistry` + fixed `Clock`; lane-isolation, overflow, drainer-survival, backoff, exhaustion-alert, idempotency cases.

---

### T-08-18 — Audit-store-down `*IT`: buffer + drain-on-recovery + alert (T-R3)

- **Owner:** qa-engineer
- **Depends on:** T-08-16, T-08-11 (Testcontainers wiring reuse)
- **Size / Risk:** M / High
- **Files (create):** `nexus-backend/.../AuditStoreDownIT` (Testcontainers MySQL)
- **Acceptance criteria:**
  - **AC#:** AC4. **T-R3 (threat, P0):** with `auth_events` writes failing, the **auth flow still returns its real outcome** (e.g. 401/200), the event is **buffered**, and **drains on recovery**; exhaustion/drop **raises an alert** (`AuditAlertPort`) and increments the corresponding counter. Residual (in-flight loss on crash) referenced to ADR 0011.
- **Test plan:** `AuditStoreDownIT` — induce DB-write failure (revoke INSERT or simulate `DataAccessException`), drive an auth action, assert primary outcome unaffected + event in buffer + metric; restore, assert drain + persisted row + `retry.success`++.

---

## WAVE 7 — Cross-cutting verification, perf, observability

### T-08-19 — `auth_events` payload PII / log-scrub test, all 8 flows (AC5 / T-I3 / T-I1)

- **Owner:** qa-engineer
- **Depends on:** T-08-03, T-08-04, T-08-06, T-08-07, T-08-08
- **Size / Risk:** M / Medium
- **Files (create):** `nexus-backend/.../AuthEventsPiiScrubIT` (Testcontainers)
- **Acceptance criteria:**
  - **AC#:** AC5. **T-I3 (threat, P0):** across **all 8 emit flows**, no email / raw password / token pattern appears in **any** `auth_events` column — including `metadata` and `user_agent`. **T-I1 (threat, P1):** no audit-path **log line** interpolates raw `user_agent` (or other raw UA-derived string); extend the scrub scope to log output.
- **Test plan:** `AuthEventsPiiScrubIT` — drive each of the 8 flows, query every column + scan captured log output for email/password/token regexes; assert none present. (Distinct from `AuthAuditIT.no_raw_refresh_token_in_logs`, which covered logs but not the payload.)

---

### T-08-20 — Load test (100 RPS / 10 min) + failure-path ≤5ms (Test Scenario 5 / T-D3)

- **Owner:** qa-engineer
- **Depends on:** T-08-16
- **Size / Risk:** M / Medium
- **Files (create):** load-test harness (under `nexus-backend` test/perf tooling — none exists today)
- **Acceptance criteria:**
  - **AC#:** AC4 / **Test Scenario 5** — 100 RPS sustained login for 10 min with a **healthy** DB: **zero event loss** (`buffer.dropped` and `retry.exhausted` stay 0; row count == emitted count).
  - **T-D3 (threat, P1):** the **failure-path** catch+enqueue stays within the **5ms budget** (OQ-4 — applies only to the failure path, not the synchronous-insert baseline); assertion/alert hook if synchronous-insert p99 degrades (depth/age gauges cover the failure mode).
- **Test plan:** load harness asserting throughput + zero-loss invariant under healthy DB; micro-benchmark/timed assertion on the enqueue path ≤5ms.

---

### T-08-21 — Grafana panels + alert rules + observability-standards Phase-9 + T-I2 EPIC-007 note

- **Owner:** backend-engineer
- **Depends on:** T-08-15, T-08-18
- **Size / Risk:** S / Low
- **Files:**
  - **Create/modify** Grafana dashboard JSON/panels (per-lane depth + oldest-age gauges; retry-success vs exhausted+dropped; alert-raised-by-type) + alert rules bound 1:1 to `03-design.md` §4.1 thresholds with runbook links
  - **Modify** `docs/observability-standards.md` — tick the Phase-9 checklist item "audit events fired for all security-relevant actions"; confirm the documented `userAgent`+`traceId`-in-`metadata` shape is now implemented
  - **Record T-I2 (threat, P1) cross-story obligation:** add an explicit EPIC-007 tracking note (in ADR 0011/observability-standards or a tracked backlog item): "`auth_events.user_agent` and `metadata` are attacker-controlled; any viewer MUST HTML-escape on render + apply CSP."
- **Acceptance criteria:**
  - **AC#:** AC4 (alerting/observability complete). Priority-lane panels prominent (T-D1 mitigation visible: priority depth/age ~0 while standard drops climb = behaving as designed). T-I2 obligation recorded as a tracked downstream requirement, not silently assumed.
- **Test plan:** N/A (dashboards/docs); alert-rule thresholds cross-checked against §4.1.

---

## Threat → Task Coverage Matrix (all 15 rows of `03b-threat-model.md` accounted for)

| Threat ID(s) | Covered by | Form |
|---|---|---|
| T-S1 | T-08-11 (grant scope) + §9 no-write-API | Existing design mitigation; verified by privilege IT |
| T-S2 | T-08-05 (§3.4 advisory-only comment) | Accepted-risk doc note (no code task) |
| T-T1 | T-08-04 | Named AC + test case |
| T-T2 | T-08-04 | Named AC + test case |
| T-T3, T-E1 | T-08-11 | Privilege-level append-only IT (grant-scope assertion) |
| T-T4, T-E2 | T-08-09 (ADR residual) + T-08-12 (runtime self-check) | ADR + self-check task |
| T-R1 | T-08-07 | New atomicity IT |
| T-R2 | T-08-08 | New rollback IT |
| T-R3, T-D2, T-D4 | T-08-18 (store-down IT) + T-08-17 (overflow, drainer-survival) | IT + unit tests |
| T-I1 | T-08-16 (WARN no-UA) + T-08-19 (scrub scope) | AC + scrub test |
| T-I2 | T-08-21 | EPIC-007 cross-story tracking note |
| T-I3 | T-08-19 | Payload PII-scrub IT, all 8 flows |
| T-I5, T-E4 | T-08-06 | AuthAuditIT assertions + no-client-input check |
| **T-D1** | **T-08-13 (ADR residual) + T-08-17 (lane-isolation unit test)** | **Gate-2-amendment remaining task explicitly included** |
| T-D3 | T-08-20 | Load test + 5ms assertion |
| T-E2 (CI provisioning) | T-08-10 + T-08-11 | `nexus_app` created/exercised every build |
| T-E3 | T-08-09 (ADR) + T-08-10 (distinct credentials) | ADR + provisioning separation |

_(T-I4 and T-D5 are accepted pre-existing risks with no new task, per `03b-threat-model.md` §"Accepted Risks"; T-S1 has no new task beyond T-08-11. All other rows map to a concrete task above.)_

---

## Sequencing Summary

| Wave | Tasks | Notes |
|---|---|---|
| 1 | T-08-01, T-08-02, T-08-03 | WS-1 enum + WS-6 DB; 01/02 parallel, 03 after 02 |
| 2 | T-08-04, T-08-05 | WS-6 `RequestContext` + capture (after 01) |
| 3 | T-08-06 | WS-4 tenant (after 02, 03) |
| 4 | T-08-07, T-08-08 | WS-5 logout enrich (after 04, 05) + register confirm |
| 5 | T-08-09, T-08-10, T-08-11, T-08-12 | WS-2 + ADR 0012; 11/12 after 10 |
| 6 | T-08-13, T-08-14, T-08-15, T-08-16, T-08-17, T-08-18 | **WS-3 last** + ADR 0011; highest risk |
| 7 | T-08-19, T-08-20, T-08-21 | Cross-cutting verification, perf, observability |

---

## Definition of Done

- [ ] **AC1** — all 9 canonical event types emitted end-to-end with correct `wireName` (incl. 4 renames), verified in `AuthAuditIT`/`SecureEventServiceTest`/use-case tests (T-08-02, T-08-03, T-08-07, T-08-08).
- [ ] **AC2** — schema fields populated: `user_agent` column present + mirrored in `metadata` (T-08-01/04/05); `tenant_id` populated where resolvable, NULL pre-auth (T-08-06); `traceId` confirmed as `correlation_id` satisfier (no new column).
- [ ] **AC3** — append-only verified **both** at privilege level (`nexus_app` UPDATE/DELETE denied, grant scope exact — T-08-11) **and** via the retained triggers (`AuthEventsAppendOnlyIT` still green); runtime self-check detects drift (T-08-12).
- [ ] **AC4** — two-lane buffer + per-lane metrics/alerts + escape-hatch flag verified (T-08-15..18, T-08-21); audit-store-down auth-still-succeeds proven (T-08-18).
- [ ] **AC5** — PII/log-scrub test passing across all 8 flows incl. `metadata`/`user_agent` (T-08-19).
- [ ] **All 5 Test Scenarios** covered: enum/event taxonomy (T-08-03), schema completeness (T-08-06/AuthAuditIT), append-only privilege (T-08-11), payload PII-scrub (T-08-19), 100 RPS/10 min load with no loss (T-08-20).
- [ ] **Every threat-model row** mapped (matrix above); **T-D1 lane-isolation unit test green** (Gate-2 amendment).
- [ ] **Both ADRs written:** ADR 0011 (two-lane retry buffer), ADR 0012 (least-privilege DB role).
- [ ] **Migration version reconfirmed against `main`** before merge (T-08-01).
- [ ] **`mvnw verify`** (full gate, Testcontainers MySQL) green — ArchUnit layering, JaCoCo ≥80% (incl. new domain records' `toString()`), all new `*IT`s passing. `mvnw lint`/format clean.

---

### File paths referenced (all absolute)
- This breakdown: `C:\entomo\AI\nexus\docs\features\US-008\04-tasks.md`
- Inputs: `C:\entomo\AI\nexus\docs\features\US-008\01-requirements.md`, `...\02-impact.md`, `...\03-design.md`, `...\03b-threat-model.md`
- Format precedent: `C:\entomo\AI\nexus\docs\features\US-007\04-tasks.md`
- ADRs to author: `C:\entomo\AI\nexus\docs\adr\0011-in-process-bounded-retry-buffer-for-audit-writes.md`, `C:\entomo\AI\nexus\docs\adr\0012-least-privilege-runtime-db-user-for-auth-events.md`
