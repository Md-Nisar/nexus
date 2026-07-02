# US-008 — Impact Analysis

_Output of `/impact-analysis` (architect). Feeds Gate 2._

This document maps blast radius for the six Gate-1-decided work streams (§11 of `01-requirements.md`). It identifies files, layers, migrations, tests, and unknowns only — it does **not** propose class designs, method signatures, or solutions. Those belong to Gate 2 (`03-design.md`).

**Verification basis:** every file referenced below was read directly during this pass. Key as-built facts confirmed:
- `auth_events` table + append-only triggers live in `V2__identity_schema.sql:76-110`; migrations on disk are `V1`, `V2`, `V3`. US-007's `02-impact.md` proposes `V4__auth_tokens_reset_throttle_index.sql` but **that file does not yet exist on disk**. To avoid a numbering collision with the in-flight US-007 branch, US-008 must claim the **next number after whatever US-007 actually merges** — provisionally **`V5`**, re-confirm against `main` at implementation time.
- `RequestContext` (`common.domain.RequestContext`) is a 2-arg record `(ipAddress, traceId)` — **no `userAgent`, no `tenantId` field**. Constructed in 3 controllers: `LoginController:114`, `RegistrationController:111`, `PasswordResetController:90`.
- `LogoutUseCase.execute(UUID userId, String rawRefreshToken, String clientIp)` takes a bare `String clientIp`, **not** a `RequestContext` — it never calls `toMetadataJson()` and has no tenant/trace/userAgent path at all.
- `tenant_id` column exists (`AuthEvent.java:30-31`) but **no `withTenantId(...)` builder method exists**, and no call site sets it.
- All event-type strings are inline literals across 8 files (the 6 AC1 flows + `ResendVerificationUseCase` + `SecureEventService`). No central enum exists today.
- No async/retry/buffer infrastructure exists anywhere in `nexus-backend/src/main` (no `@EnableAsync` for this purpose, no `RetryTemplate`, no `TaskExecutor`, no outbox). `pom.xml` has **no Guava, no Resilience4j, no Spring Retry**.

---

## 1. Work Stream Overview & Sizing

| WS | Gate-1 decision | Primary layers | Size | Risk |
|----|-----------------|----------------|------|------|
| **WS-1** Event taxonomy / `AuthEventType` enum | OQ-1 | domain + application (all flows) | **M** | Low (mechanical, wide) |
| **WS-2** Least-privilege DB role (INSERT+SELECT) | OQ-2 | infra / deployment config (no Java) | **M** | Medium (ops/credential surface) |
| **WS-3** In-process bounded retry buffer + ops alert | OQ-3 | infrastructure (+ thin application hook) | **L** | **High — highest in story** |
| **WS-4** `tenant_id` population | OQ-5 | domain + application | **S–M** | Medium (pre-auth resolution gaps) |
| **WS-5** TX-durability standardization (Logout, Register → REQUIRES_NEW) | OQ-6 | application | **M** | Medium (changes 2 shipped flows' TX semantics) |
| **WS-6** `user_agent` capture (512-cap, escaped) | OQ-7 | domain + application + interfaces + DB | **M** | Low–Medium |

Two migrations are needed and can be combined into a **single additive `V<N>` file** (WS-4 needs no DDL — `tenant_id` column already exists; WS-6 needs the `user_agent` column). WS-2 may or may not require a migration depending on the Gate-2 decision on where grants live (see §4).

---

## 2. WS-1 — Event Taxonomy / `AuthEventType` Enum

### Files created
| File | Layer | Note |
|------|-------|------|
| `identity/domain/AuthEventType.java` | **domain** | New enum. Canonical AC1 names + retained granular values (per OQ-1). Lives in domain because it is a core identity concept referenced by use-cases and the entity; no outer-layer imports. |

### Files modified (literal → enum, plus 4 renames)
| File | Layer | Literals touched |
|------|-------|------------------|
| `identity/domain/AuthEvent.java` | domain | `event_type` stays `String` column (length 64) **or** map enum; Gate 2 decides whether the entity field becomes `@Enumerated(STRING)` or keeps `String` with enum-at-call-site. Current column is `VARCHAR(64)` — `LOCKOUT`/`TOKEN_REFRESH_REUSE` all fit; no DDL change for the rename. |
| `application/service/LoginUseCase.java` | application | `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGIN_PENDING_ACCOUNT`, `ACCOUNT_UNLOCKED` |
| `application/service/SecureEventService.java` | application | `ACCOUNT_LOCKED`→**`LOCKOUT`** (lines 89, 100), `ACCOUNT_LOCKED_WRITE_FAILED` (keep) |
| `application/service/RefreshTokenUseCase.java` | application | `REFRESH_FAMILY_REVOKED`→**`TOKEN_REFRESH_REUSE`** (line 116), `TOKEN_REFRESH_SUCCESS`, `TOKEN_REFRESH_FAILURE` |
| `application/RegisterUserUseCase.java` | application | `REGISTRATION_SUCCESS`→**`REGISTER`** (line 112), `REGISTRATION_DUPLICATE_EMAIL` (keep) |
| `application/VerifyEmailUseCase.java` | application | `VERIFICATION_SUCCESS`→**`VERIFY`** (line 107), `VERIFICATION_FAILED` (keep) |
| `application/ForgotPasswordUseCase.java` | application | `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_THROTTLED` |
| `application/ResetPasswordUseCase.java` | application | `PASSWORD_CHANGED`, `PASSWORD_RESET_FAILED` |
| `application/ResendVerificationUseCase.java` | application | `RESEND_REQUESTED`, `RESEND_THROTTLED` (not in AC1's 9 but must move to the enum for consistency) |

### Migration
None for the rename itself (column is free-text `VARCHAR(64)`; new rows simply carry new strings). **Historical rows keep old literals** (Gap 6 in requirements — no backfill is in scope). Any consumer must tolerate both `ACCOUNT_LOCKED` and `LOCKOUT` for historical continuity; document explicitly in design.

### Tests affected
- **`SecureEventServiceTest`** — asserts `"ACCOUNT_LOCKED"` at lines 93, 126, 184, 257. **Break on rename** → update to `LOCKOUT` (and `ACCOUNT_LOCKED_WRITE_FAILED` retained).
- **`AuthAuditIT`** — asserts `"REFRESH_FAMILY_REVOKED"` (line 194) and `"ACCOUNT_LOCKED"` (lines 316-321). **Break on rename** → update to `TOKEN_REFRESH_REUSE` / `LOCKOUT`.
- **`AuthEventsAppendOnlyIT`** — uses ad-hoc literals purely as trigger fodder; **not affected** by the taxonomy rename.
- New: **`AuthEventTypeTest`** (domain) — enum-completeness / name-stability test.
- Use-case unit tests (`LoginUseCaseTest`, `RefreshTokenUseCaseTest`, `RegisterUserUseCaseTest`, `VerifyEmailUseCaseTest`, `ForgotPasswordUseCaseTest`, `ResetPasswordUseCaseTest`, `ResendVerificationUseCaseTest`) — any asserting on `getEventType()` strings must be swept.

### Risk / sizing — **M, Low risk.** Mechanical but touches 9 production files + ~6 test files. No real external consumer (EPIC-007 not started), so the rename is genuinely free per OQ-1. Main hazard is missing a test literal and failing CI, not production breakage.

---

## 3. WS-3 — In-Process Bounded Retry Buffer + Ops Alert (highest risk)

**This is the highest-complexity, highest-risk work stream in the story.** Per OQ-3 it is genuinely net-new infrastructure: nothing comparable exists in the codebase.

### Files created (indicative — names are Gate-2's to finalize)
| File | Layer | Responsibility (boundary only) |
|------|-------|-------------------------------|
| Retry-buffer component | **infrastructure** | Bounded in-memory queue of failed `AuthEvent`s; scheduled backoff retry; depth/exhaustion signalling. Lives in `identity.infrastructure.persistence` (or a new `...infrastructure.audit` sub-package) — an adapter concern, not domain. |
| Ops-alert hook (port + adapter) | **application port.out + infrastructure adapter** | Define a thin alerting port at the application layer; wire a concrete adapter (log/metric/webhook) in infrastructure. Concrete channel is TBD — design must define the **interface** regardless of which channel is wired. |
| Scheduler enablement config | **config** (JaCoCo-excluded) | `@EnableScheduling` not currently enabled for this purpose; needs adding (verify it isn't already pulled in elsewhere at design time). |

### Files modified
| File | Layer | Change |
|------|-------|--------|
| `infrastructure/persistence/JpaAuthEventAdapter.java` | infrastructure | Currently catches `DataAccessException`, logs WARN, swallows (lines 26-33). Extend: on failure, **enqueue to the buffer** instead of (or in addition to) the WARN. The OQ-4 5ms budget applies **only to this catch+enqueue path**, not the existing synchronous insert. |
| `application/port/out/AuthEventPort.java` | application | Contract likely unchanged (`record` stays "never throws"), but Javadoc ("log and continue") must be updated to "enqueue for retry on failure." |

### Dependency impact
- **Decision needed (ADR candidate):** build the bounded buffer on **JDK primitives** (`ArrayBlockingQueue` + a `@Scheduled` drainer + `Micrometer` gauge — already on the classpath) **vs.** adding **Resilience4j / Spring Retry**. Given the required primitives are already present, strong recommendation is **no new dependency**. ADR 0009 already established Redis is explicitly deferred; this buffer must not quietly reintroduce that conversation.

### Observability impact (mandatory)
- New metric(s): buffer depth gauge, retry-success counter, retry-exhausted counter → scraped via `/actuator/prometheus`.
- Alert thresholds (buffer-backing-up, retries-exhausted) — **no numeric SLO exists** (Gap 1 in requirements). Design must propose concrete thresholds; biggest open NFR unknown.

### Tests needed (all new)
- Unit: buffer enqueue-on-failure, bounded-capacity drop/overflow behavior, retry-drain success, retry-exhaustion → alert hook fired.
- Integration (`*IT`, Testcontainers MySQL): audit-store-down simulation → primary auth flow still returns success, event lands in buffer, drains on recovery. **No such "audit-store-down" IT exists today.**
- `JpaAuthEventAdapterTest` (exists) — extend for the new enqueue branch.

### Risk / sizing — **L, High risk.** Concurrency correctness (bounded queue under load), the documented residual data-loss-on-restart risk (explicitly accepted in OQ-3), scheduler lifecycle, and the absence of any numeric SLO all compound here. **Recommend this be sequenced last and the most heavily threat-modeled work stream at Gate 2.** Carries the explicit escape hatch from OQ-3 (synchronous-only via config) if it proves too costly.

---

## 4. WS-2 — Least-Privilege DB Role (INSERT + SELECT only)

Per OQ-2 this is **additive defense-in-depth alongside** the existing triggers (which stay). Infra / deployment-config task with **little or no Java**.

### Files / artifacts touched
| Artifact | Type | Change |
|----------|------|--------|
| `docker-compose.yml` (repo root) | infra | Today the backend connects as **`root`** (`DB_USERNAME: root`, lines 28-30). A new restricted MySQL user with `INSERT, SELECT` on `auth_events` must be provisioned. **Open question for design:** does the whole app move to one least-privilege user, or does only the `auth_events` write path use a **second `DataSource`/connection pool**? The latter is materially larger (multi-datasource config, transaction-manager routing) and interacts with the REQUIRES_NEW path. |
| Flyway migration **or** init SQL | infra/DB | `CREATE USER` / `GRANT` statements. **Caveat:** Flyway runs as the migration user; grant DDL is environment-specific (Testcontainers vs. dev vs. prod use different credentials). Versioned `V<N>` migration is fragile across environments — design should decide between migration, provisioning script, or container init SQL. |
| `scripts/` provisioning / deployment config | infra | Credential creation + rotation for the new user; CI Testcontainers setup must create it too or grant-level-denial tests won't run. |
| `application-*.yml` (per env) | config | Connection credentials. Hooks **deny reads/writes of `application-prod.*`** — prod credential wiring is out-of-band and must be handed to ops. |

### Tests
- New `*IT` (Testcontainers): assert the restricted user **cannot** `UPDATE`/`DELETE` `auth_events` even if triggers were absent (privilege-level proof, distinct from `AuthEventsAppendOnlyIT`'s trigger proof). Requires the test container to provision the restricted user.

### Risk / sizing — **M, Medium risk.** No business-logic risk, but touches credential management, connection-pool topology, and CI container provisioning — "materially larger than it sounds" (OQ-2's own words). Strong **ADR candidate**.

---

## 5. WS-4 — `tenant_id` Population

Column already exists (`auth_events.tenant_id`, `AuthEvent.java:30-31`) — **no DDL**. The gap is purely that nothing sets it.

### Files modified
| File | Layer | Change |
|------|-------|--------|
| `identity/domain/AuthEvent.java` | domain | Add a `withTenantId(UUID)` builder method (mirrors `withUserId`). |
| `application/service/LoginUseCase.java` | application | `tenantId` is already a method parameter — populate on all emitted events (success + post-auth failures). Pre-auth `LOGIN_FAILURE` (unknown email) stays NULL — no tenant resolvable. |
| `application/RegisterUserUseCase.java` | application | `tenantId` is a parameter — populate on `REGISTER` and `REGISTRATION_DUPLICATE_EMAIL`. |
| `application/ForgotPasswordUseCase.java` | application | `tenantId` is a parameter — populate on resolved-user events. |
| `application/ResetPasswordUseCase.java` | application | **`tenantId` is NOT available** — use case resolves `User` from token only. Tenant must be read off the loaded `User` (verify getter exists at design time). Pre-user-resolution failures stay NULL. |
| `application/VerifyEmailUseCase.java` | application | Same as reset — no tenant param; derive from loaded `User` where available; NULL on token-not-found path. |
| `application/service/RefreshTokenUseCase.java` | application | No tenant param; derive from loaded `User` where available; NULL on pre-lookup failures. |
| `application/service/LogoutUseCase.java` | application | No tenant param and no `User` load on the happy path (only `userId` resolved). Tenant is **not currently resolvable** without an extra lookup — design decision: accept NULL, or add a lookup. Flag. |
| `application/service/SecureEventService.java` | application | `LOCKOUT` event — `persistFailedAttempt` loads the `User`, so tenant **is** resolvable here; populate it. |

### Migration
None.

### Tests
- `AuthAuditIT` — add assertions that post-auth events carry the expected `tenantId` and pre-auth events carry NULL.
- Use-case unit tests — assert `withTenantId` set where resolvable.

### Risk / sizing — **S–M, Medium risk.** Mechanical per-flow, but the "where does tenant come from" answer differs per flow (param vs. loaded-user vs. unresolvable). The Logout NULL question is a genuine design unknown. Consequence of getting it wrong is high (requirements Risk Register flags this High likelihood, already-true-today).

---

## 6. WS-5 — Transaction-Durability Standardization (Logout, Register → REQUIRES_NEW)

Per OQ-6, move `LogoutUseCase` and `RegisterUserUseCase` audit writes onto `SecureEventService.recordEvent` (REQUIRES_NEW), matching Login/Refresh/Forgot/Reset.

### Files modified
| File | Layer | Change / hazard |
|------|-------|-----------------|
| `application/service/LogoutUseCase.java` | application | Currently injects `AuthEventPort` directly and records in the same `@Transactional`. Swap to `SecureEventService`. **Hazard:** the class Javadoc explicitly states revocation + audit commit *atomically*, "preventing a phantom LOGOUT event with no corresponding token revocation." Moving audit to REQUIRES_NEW **deliberately breaks that atomicity** — a phantom LOGOUT becomes possible if revocation later rolls back. Real semantic trade-off for design + threat model to adjudicate (OQ-6 says standardize; the existing Javadoc says the opposite was intentional). Constructor change (drops `AuthEventPort`, adds `SecureEventService`). |
| `application/RegisterUserUseCase.java` | application | Currently `authEventPort.record(...)` inline within the same TX as `userRegistrationPort.save(user)`. Swap to `SecureEventService`. **Hazard:** the `REGISTER` event currently commits atomically with the user row. Under REQUIRES_NEW, a registration that rolls back *after* the audit call could leave a `REGISTER` event for a user that doesn't exist. Design must decide event ordering relative to the save. Constructor change (adds `SecureEventService`). |
| `application/service/SecureEventService.java` | application | No new method needed — `recordEvent` already exists. |

### Interaction with WS-6 / WS-4
`LogoutUseCase.execute` takes `String clientIp`, not `RequestContext`. To also gain `traceId` + `userAgent` (today LOGOUT carries neither), the **controller→use-case signature must change** to pass a `RequestContext`. This couples WS-5, WS-6, and the metadata-enrichment gap for logout into one coordinated change in `LoginController.logout` + `LogoutUseCase.execute`.

### Tests affected
- **`LogoutUseCaseTest`** — constructed with `AuthEventPort` mock. **Breaks** — reconstruct with `SecureEventService` mock, re-verify the record interaction.
- **`RegisterUserUseCaseTest`** — constructor change → mock setup update.
- `SecureEventServiceTest` / `SecureEventServiceConcurrencyTest` — unchanged contract for `recordEvent`, but add coverage if logout/register paths introduce new event-shape assertions.
- `AuthAuditIT` logout/register assertions — still valid (event still recorded), but durability-under-rollback could get a new IT.

### Risk / sizing — **M, Medium risk.** Changes transaction semantics of two shipped flows and contradicts an existing intentional design note in `LogoutUseCase`. The atomicity-vs-durability trade-off is a real Gate-2 decision, not a mechanical swap.

---

## 7. WS-6 — `user_agent` Capture (512-cap, JSON-escaped)

Per OQ-7: capture `User-Agent`, cap at 512 chars, reuse `RequestContext`'s existing JSON-escape discipline.

### Files modified / created
| File | Layer | Change |
|------|-------|--------|
| `common/domain/RequestContext.java` | **common.domain** | Add a `userAgent` field (record becomes 3-arg). `toMetadataJson()` extends to emit `userAgent` using the existing `jsonEscape`. 512-char truncation applied here or at construction. The `UNKNOWN` sentinel and all `new RequestContext(...)` call sites change arity. |
| `interfaces/rest/LoginController.java` | interfaces | `requestContext(...)` reads `req.getHeader("User-Agent")`, truncates, passes through. |
| `interfaces/rest/RegistrationController.java` | interfaces | Same. |
| `interfaces/rest/PasswordResetController.java` | interfaces | Same. |
| `auth_events` table | DB | **New `user_agent` column** (additive). See §8. |
| `identity/domain/AuthEvent.java` | domain | Decision: store `user_agent` as a **first-class column** (`@Column(name="user_agent")` + `withUserAgent(...)`) **or** keep it inside `metadata` JSON only. Requirements §2 lists it as a schema-level field (AC2), so a column is indicated. Gate 2 confirms. |

### Call-site arity breakage (record change ripples)
Every `new RequestContext(...)` becomes 3-arg:
- Production: `LoginController:114`, `RegistrationController:111`, `PasswordResetController:90`, `RequestContext.UNKNOWN:10`.
- Tests: `ForgotPasswordUseCaseTest:46`, `ResetPasswordUseCaseTest:48`, `LoginUseCaseSecurityTest:73`, `LoginUseCaseTest:59` — all hard-code 2-arg `RequestContext` and **will not compile** until updated.

### Security note (feeds threat model)
`User-Agent` is fully attacker-controlled, unbounded free text. The 512-cap + `jsonEscape` mitigates row-bloat and JSON-injection into the native `JSON` column. Stored-XSS risk is deferred to EPIC-007's rendering layer but must be noted as a downstream obligation (escape-on-render). The existing `CorrelationIdFilter` charset restriction does **not** apply to User-Agent (different header), so escaping is the only control.

### Risk / sizing — **M, Low–Medium risk.** The record-arity change is the broadest ripple (every RequestContext call site + tests). The security handling is well-precedented by `traceId`/`ipAddress`.

---

## 8. Database / Migration Impact (consolidated)

| Change | Type | Owner WS |
|--------|------|----------|
| `auth_events` add `user_agent VARCHAR(512) NULL` | **Additive** (ADR 0003 compliant) | WS-6 |
| `tenant_id` population | No DDL (column exists) | WS-4 |
| Event-type rename | No DDL (free-text `VARCHAR(64)`, fits) | WS-1 |
| Append-only triggers | **Unchanged** — kept per OQ-2 | WS-2 |
| Least-privilege DB user `GRANT`s | DDL, but **environment-specific** — placement TBD (migration vs. provisioning script vs. container init) | WS-2 |

**Single additive migration** recommended for the `user_agent` column: provisionally **`V5__auth_events_add_user_agent.sql`** (confirm next free number against `main` at implementation — V4 is claimed by the in-flight US-007 branch but not yet on disk). All changes are **additive/expand-only**; **no expand/contract sequencing required**. `ddl-auto=validate` means the JPA `AuthEvent` field for `user_agent` must land in the same change as the migration or boot fails validation.

**`IdentitySchemaMigrationIT`** (exists) — will need an assertion for the new column if it validates schema shape.

---

## 9. Cross-Cutting Impact

### API impact
**None.** No REST contract changes. No new endpoints, no request/response DTO changes, no status-code changes. `auth_events` has no read API in this story (EPIC-007 is the consumer, out of scope). The only controller edits are internal (`RequestContext` construction, logout signature).

### Frontend impact
**None.** Confirmed by requirements (no UI surface; "Angular component changes: none"). No `nexus-frontend/` files touched.

### Security impact
- New attack-surface considerations centralize in the threat model: attacker-controlled `user_agent` (WS-6), least-privilege role + credential rotation (WS-2), and the accepted data-loss-on-restart residual risk of the buffer (WS-3).
- AC5 (no PII / no raw secrets) — add the missing **log-scrubbing test** for `auth_events` (Gap, Test Scenario 4). `AuthAuditIT.no_raw_refresh_token_in_logs` covers logs but not the `auth_events` payload specifically.

### Performance impact
- WS-3 catch+enqueue path is the only measured budget (5ms, OQ-4) — applies to the failure path only.
- Existing `auth_events` indexes (`user_id`, `tenant_id`, `event_type` each × `created_at`) are adequate; **no index changes**. `user_agent` is not indexed (free text, not a query key).
- No N+1 risk introduced. WS-5's REQUIRES_NEW adds a second connection per logout/register (same trade-off ADR 0009 already accepted for login; verify pool sizing >= 2× concurrent).

### Observability impact
- WS-3 new metrics (buffer depth / retry / exhaustion) + alert hook — the only substantial observability addition; **mandatory** and currently unspecified (Gaps 1, 2). Design must define metric names, thresholds, and the alert-hook interface.
- This story is the implementation of the already-documented `docs/observability-standards.md` audit-log shape, which already shows `userAgent` + `traceId` in `metadata` — i.e. WS-6 closes a pre-existing spec gap.

### Dependency impact
**Recommend zero new dependencies.** JDK `BlockingQueue` + Spring `@Scheduled` + Micrometer (all on the classpath) cover WS-3. No version bumps, no license review needed. Adding Resilience4j/Spring Retry would need explicit cost-benefit justification at Gate 2 and is not recommended for MVP scope.

### Backward compatibility
- Event-type rename leaves **historical rows with old literals** (no backfill — Gap 6, accepted). Consumers must tolerate both. No live consumer today.
- `RequestContext` arity change is **source-incompatible** but fully internal (no published API).
- No data-shape migration needed (all additive).

---

## 10. ADR Recommendations

| Candidate | Recommendation |
|-----------|----------------|
| **In-process bounded retry buffer (WS-3)** | **New ADR warranted.** Introduces a new reliability pattern, a deliberately-accepted data-loss-on-restart residual risk (OQ-3), and a "no durable outbox/broker for MVP" stance future stories will question. ADR should record: JDK-primitives-not-new-dep decision, bounded-capacity + drop policy, the restart-loss acceptance, the synchronous-only escape hatch, and SLO thresholds. Numbered **ADR 0011**. |
| **Least-privilege DB role for `auth_events` (WS-2)** | **New ADR warranted.** Changes the app's DB credential model (today: `root`), introduces possible multi-datasource topology, layered as defense-in-depth on top of the existing trigger design. Record: role grants, single-user-vs-second-datasource decision, environment provisioning approach, and rotation. Numbered **ADR 0012**. |
| Event taxonomy / enum rename (WS-1) | No ADR needed — refactor within established conventions; capture the name-mapping table in `03-design.md` instead. |
| TX standardization (WS-5) | No new ADR — **ADR 0009** already governs the REQUIRES_NEW-on-`SecureEventService` rule; this story applies it to two more flows. Reference ADR 0009; note the logout-atomicity trade-off in the design doc. |

ADRs 0001–0010 are in use; next free numbers are **0011, 0012**.

---

## 11. Blast-Radius File List (quick reference)

**Production — modify:** `AuthEvent.java`, `RequestContext.java`, `SecureEventService.java`, `JpaAuthEventAdapter.java`, `AuthEventPort.java` (Javadoc), `LoginUseCase.java`, `LogoutUseCase.java`, `RegisterUserUseCase.java`, `VerifyEmailUseCase.java`, `ForgotPasswordUseCase.java`, `ResetPasswordUseCase.java`, `RefreshTokenUseCase.java`, `ResendVerificationUseCase.java`, `LoginController.java`, `RegistrationController.java`, `PasswordResetController.java`, `docker-compose.yml`, per-env `application-*.yml`.

**Production — create:** `AuthEventType.java` (domain), retry-buffer component + alert port/adapter (infrastructure/application), scheduler config, `V5__auth_events_add_user_agent.sql`, DB-grant provisioning artifact.

**Tests — modify (compile/assert breaks):** `SecureEventServiceTest`, `AuthAuditIT`, `LogoutUseCaseTest`, `RegisterUserUseCaseTest`, `LoginUseCaseTest`, `LoginUseCaseSecurityTest`, `ForgotPasswordUseCaseTest`, `ResetPasswordUseCaseTest`, `IdentitySchemaMigrationIT`, plus any use-case test asserting event-type literals.

**Tests — create:** `AuthEventTypeTest`, retry-buffer unit + audit-store-down `*IT`, privilege-level append-only `*IT`, `auth_events` payload log-scrubbing test.

**Unaffected:** all `nexus-frontend/` (no UI), all REST DTOs/contracts, `auth_events` indexes, the append-only triggers.

---

## 12. Open Unknowns for Gate 2 (not scope questions — those are closed)

1. **Migration numbering** — confirm next free `V<N>` against `main` after US-007 merges (V4 claimed but not on disk).
2. **WS-2 topology** — single least-privilege app user vs. dedicated second `DataSource` for the `auth_events` write path; and where grant DDL lives across environments.
3. **WS-3 SLOs** — numeric buffer-depth/age alert thresholds and max-event-loss window (Gaps 1, 2; no values exist).
4. **WS-5 logout atomicity** — accept phantom-LOGOUT possibility under REQUIRES_NEW, or guard it; reconcile with the existing intentional atomicity note.
5. **WS-4 logout/verify/refresh tenant resolution** — accept NULL where no `User` is loaded, or add a lookup.
6. **WS-6 storage shape** — `user_agent` as first-class column (indicated by AC2) vs. metadata-JSON-only.
7. **Ops alert channel** — concrete channel TBD; design defines the hook interface regardless.

---

### File paths referenced (all absolute)
- Requirements: `C:\entomo\AI\nexus\docs\features\US-008\01-requirements.md`
- Format precedent: `C:\entomo\AI\nexus\docs\features\US-007\02-impact.md`
- Core sources verified: `identity\domain\AuthEvent.java`, `application\service\SecureEventService.java`, `application\port\out\AuthEventPort.java`, `infrastructure\persistence\JpaAuthEventAdapter.java`, `infrastructure\persistence\JpaAuthEventRepository.java`, `common\domain\RequestContext.java`, `common\web\CorrelationIdFilter.java`, the 7 use cases + `ResendVerificationUseCase.java`, `interfaces\rest\LoginController.java`, `resources\db\migration\V2__identity_schema.sql`, `docker-compose.yml`, `nexus-backend\pom.xml`, `docs\adr\0009-requires-new-transaction-for-lockout-counters.md`.
