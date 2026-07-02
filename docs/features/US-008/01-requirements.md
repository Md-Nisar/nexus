# US-008 — Requirements Analysis: Emit Audit Events for All Authentication Actions

_Output of `/analyze-story` (business-analyst) + `feature-discovery` skill. Feeds Gate 1._

---

## 1. Problem Statement

The security and compliance team needs every authentication-related action — login, logout, lockout, registration, verification, password reset, and token refresh/reuse — recorded immutably so incidents can be investigated and audit obligations satisfied. This story is the **producer** of the event stream; EPIC-007 (Audit Logs & Activity Feed) is the future **consumer**/viewer and is explicitly out of scope here.

**Bounded context:** `identity` (`com.example.nexus.identity`) — same context as US-001 through US-007.

**Critical scoping reality, confirmed by direct code reading:** this is **not a greenfield story**. The `auth_events` table, the append-only trigger enforcement, `SecureEventService`, `AuthEventPort`/`JpaAuthEventAdapter`, and event-emission call sites in every one of the six flows AC1 lists already exist, built incrementally across US-001/002/003/004/005/006/007. US-008's actual delta is narrower than the story text implies: it is a **gap-closure and standardization** story (naming, schema completeness, durability semantics, enforcement mechanism), not a "build audit logging from scratch" story.

**Non-goals (out of scope per story):**
- Audit viewing UI (EPIC-007)
- Retention automation
- SIEM export

---

## 2. Reuse-First Survey

### What already exists and can be reused directly

| Asset | Location | Reuse |
|-------|----------|-------|
| `auth_events` table | `V2__identity_schema.sql` (lines 76-90) | Core schema present: `id`, `user_id`, `tenant_id`, `event_type`, `outcome`, `ip_address`, `metadata` (JSON), `created_at` |
| Append-only triggers `trg_auth_events_no_update` / `trg_auth_events_no_delete` | Same migration | `BEFORE UPDATE`/`BEFORE DELETE` triggers `SIGNAL SQLSTATE '45000'` — verified by reading the migration. **This is trigger-based enforcement, not DB-privilege-based** (see OQ-2) |
| `AuthEvent` entity | `identity.domain.AuthEvent` | No `@Version`, no `updated_at`, builder-style `withX()` chaining — verified, matches append-only design intent |
| `AuthEventPort` / `JpaAuthEventAdapter` | `identity.application.port.out` / `identity.infrastructure.persistence` | Verified: `JpaAuthEventAdapter.record()` already wraps `authEventRepository.save(event)` in a `try/catch (DataAccessException)` that logs at WARN and **swallows** the exception — more significant finding than the prior discovery pass flagged (see AC4 analysis) |
| `SecureEventService` (`@Transactional(REQUIRES_NEW)`) | `identity.application.service` | `recordEvent()`, `revokeFamily()`, `persistFailedAttempt()`, `revokeAllUserSessions()`, `persistResetAttempts()` all verified present and durable against outer-tx rollback |
| `RequestContext` record `(ipAddress, traceId)` + `toMetadataJson()` | `common.domain.RequestContext` | Verified: produces `{"traceId":"...","ip":"..."}` JSON embedded into `auth_events.metadata`. **No `userAgent` field exists on this record at all** — not just missing a column, missing from the carrier object itself |
| `CorrelationIdFilter` | `common.web` | Sets MDC `traceId`; source of the value `RequestContext` carries |
| Event emission already wired into all 6 flows | `LoginUseCase`, `LogoutUseCase`, `RegisterUserUseCase`, `VerifyEmailUseCase`, `ForgotPasswordUseCase`/`ResetPasswordUseCase`, `RefreshTokenUseCase` | Verified by direct read of each file — every flow already calls `authEventPort.record(...)` or `secureEventService.recordEvent(...)` at every meaningful branch |
| `AuthEventsAppendOnlyIT`, `AuthAuditIT` | `nexus-backend/src/test/java/...` | Existing test coverage for trigger behavior and end-to-end event assertions — extend, don't replace |
| `LogMaskingUtil` (two copies — see Gaps) | `common.web.LogMaskingUtil`, `common.domain.LogMaskingUtil` | Existing email-masking utility for log lines (not currently applied to `auth_events`, since email is never stored there) |
| `docs/observability-standards.md` Audit Log section | `docs/observability-standards.md` (lines 188-208) | Documents the **target** JSON shape including `userAgent` and `traceId` in `metadata` — this is effectively the as-yet-unimplemented spec AC2 is asking for |

### What must be created

| Asset | Type | Reason |
|-------|------|--------|
| `AuthEventType` enum (or equivalent constants class) | Domain | Currently zero central definition — every call site uses an inline String literal; typos are possible and undetectable at compile time. AC1's named event types (`LOGIN_SUCCESS`, etc.) cannot be guaranteed consistent without this |
| `user_agent` capture path | `RequestContext` field + filter/interface-layer change | Not just a DB column — `RequestContext` itself has no field for it today; must be added at the point the context is constructed, then threaded through every use case |
| `user_agent` DB column (additive migration) | Flyway `V<N>__*.sql` | New column per ADR 0003 (additive-only); historical rows will lack it |
| `correlation_id` DB column (additive migration), or formal decision to leave it in `metadata` JSON | Flyway `V<N>__*.sql` | AC2 lists `correlation_id` as a schema-level field; today it is JSON-embedded only, not queryable/indexable as a first-class column |
| Resolution mechanism for AC3's "DB privilege level" vs. existing trigger enforcement | Infra/DB grants decision | See OQ-2 — may require a new restricted DB user/role with INSERT/SELECT-only grants, separate from the trigger |
| Retry/buffer mechanism for AC4 | New infra (scope TBD) | Verified: **no async infrastructure exists anywhere in `nexus-backend/src/main/java`** — no `@EnableAsync` bean, no custom `TaskExecutor`, no `@Retryable`/`RetryTemplate`, no outbox table, no message broker in `docker-compose`. The only `@Async` usage in the whole repo is the unrelated `MailEventListener` (bare `@Async`, no retry). AC4's "buffered and retried" is **net-new infrastructure**, not a wiring task |
| Log-scrubbing test (AC5 / Test Scenario 4) | Test | "Grep all logs/events for password/token strings" — no such test currently exists for `auth_events` specifically |
| Load test harness for 100 RPS / 10 min sustained login (Test Scenario 5) | Test/perf tooling | Not present in repo |

### What needs extension (not full rewrite)

| Asset | Extension |
|-------|-----------|
| `LoginUseCase` event literals | Already emits `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGIN_PENDING_ACCOUNT`, `ACCOUNT_UNLOCKED` — verified by direct read. AC1 only requires `LOGIN_SUCCESS`/`LOGIN_FAILURE`/`LOCKOUT`; the extra states are a superset, not a gap, but `LOCKOUT` itself is literally emitted as `"ACCOUNT_LOCKED"` from `SecureEventService.persistFailedAttempt` — naming mismatch vs. AC1's `LOCKOUT` |
| `LogoutUseCase` | Verified: calls `authEventPort.record()` **directly**, NOT through `SecureEventService` (i.e., NOT `REQUIRES_NEW`) — same transaction as the logout operation itself, and **does not call `ctx.toMetadataJson()` at all**, so `LOGOUT` events today carry no `traceId`/correlation data. Two issues: durability pattern inconsistency, and missing metadata enrichment |
| `RegisterUserUseCase` | Verified: `authEventPort.record()` called directly (not REQUIRES_NEW) for both `REGISTRATION_DUPLICATE_EMAIL` and `REGISTRATION_SUCCESS`, inside the same transaction as `userRegistrationPort.save(user)`. If that outer transaction rolls back after the audit call but before commit, the audit write rolls back too. Same durability gap class US-006 solved for lockout via REQUIRES_NEW; registration was never retrofitted |
| `RefreshTokenUseCase` reuse-detection event | Emits `"REFRESH_FAMILY_REVOKED"` (verified) — AC1 names this `TOKEN_REFRESH_REUSE`. Functionally this *is* the reuse-detection event but under a different label |
| All `event_type` String literals across 6 use cases | Replace with `AuthEventType` enum once created, for compile-time safety and to enable the AC1 rename decision (OQ-1) to be made in one place |
| `JpaAuthEventAdapter.record()` | Currently already swallows `DataAccessException` and logs WARN (verified) — this **partially satisfies** AC4's "audit write failure does not block auth" for the *synchronous write itself*, but does nothing for "buffered and retried" or for ops alerting; needs extension once retry/buffer design is settled |

---

## 3. Acceptance Criteria — Annotated

| # | Criterion | Status | Verification Note |
|---|-----------|--------|---------------------|
| AC1 | All 9 named events captured within 1s | **Partially satisfied, naming mismatch** | All 6 flows already emit events at the right moments. However the literal strings used today (`ACCOUNT_LOCKED`, `REFRESH_FAMILY_REVOKED`, plus extras like `LOGIN_PENDING_ACCOUNT`, `ACCOUNT_UNLOCKED`, `REGISTRATION_DUPLICATE_EMAIL`, `VERIFICATION_FAILED`/`VERIFICATION_SUCCESS`, `TOKEN_REFRESH_SUCCESS`/`TOKEN_REFRESH_FAILURE`, `PASSWORD_RESET_THROTTLED`/`PASSWORD_RESET_FAILED`) do not literally match AC1's 9 names. "Within 1s" is not measured by any existing test. **See OQ-1** |
| AC2 | Event schema complete: UTC timestamp, event_type, user_id (nullable), tenant_id, source IP, user agent, outcome, correlation_id | **Gap — 2 of 8 fields missing, 1 unpopulated** | `created_at`, `event_type`, `user_id`, `outcome`, `ip_address` exist as first-class columns. `tenant_id` column exists but is verified **never populated** by any call site — no `AuthEvent` builder method for it exists today. `user_agent` has no column and no carrier field on `RequestContext`. `correlation_id` exists only inside the free-form `metadata` JSON, not as a queryable column |
| AC3 | Append-only enforced at DB privilege level; UPDATE/DELETE denied, attempt fails in test | **Implemented via a different mechanism than specified** | Verified: enforcement today is `BEFORE UPDATE`/`BEFORE DELETE` triggers that `SIGNAL SQLSTATE '45000'`, exercised by `AuthEventsAppendOnlyIT`. Achieves the same *effect* (mutation denied) but not via "DB privilege level" / "restricted DB grants (INSERT/SELECT only)" as literally specified. **See OQ-2** |
| AC4 | Audit write failure does not block auth; failure alerted via ops channel; events buffered and retried | **Substantially unimplemented** | The *synchronous, in-transaction* failure-tolerance half is verified present (`JpaAuthEventAdapter` swallows `DataAccessException`). But: (a) no ops-channel alerting exists anywhere — a swallowed exception today only produces a WARN log line; (b) "buffered and retried" requires infrastructure that does not exist; (c) `LogoutUseCase` and `RegisterUserUseCase` audit writes are NOT in REQUIRES_NEW, so an outer-tx rollback would silently lose those audit rows with no failure even logged, contradicting AC4's intent. **See OQ-3** |
| AC5 | No PII beyond necessity; email not stored when user_id resolvable; no raw passwords/tokens in payload | **Largely already satisfied** | Verified: `AuthEvent` has no email field at all — only `userId` (UUID). No call site passes raw email or password/token into `metadata`. Closer to "confirm via test" than "build." A dedicated log-scrubbing test (Test Scenario 4) does not appear to exist yet for `auth_events` specifically |

**Net assessment:** AC1 and AC5 are mostly done (naming/verification gaps only). AC2 has two real schema gaps (`user_agent`, `tenant_id` population, `correlation_id` as a column). AC3 and AC4 are the two ACs with genuine, material open design questions that should not be resolved by an analyst — they need Gate 1 stakeholder decisions.

---

## 4. Data Flow (current state, as verified — not a proposed design)

```
Request arrives → CorrelationIdFilter sets MDC traceId (from X-Correlation-Id or generated)
  → Controller constructs RequestContext(ipAddress, traceId)   [no userAgent field today]
  → Use case (Login/Logout/Register/Verify/ForgotPassword/ResetPassword/RefreshToken)
      executes business logic
      → at each significant branch: constructs `new AuthEvent(id, "<LITERAL>", outcome)`
            .withUserId(...)   [nullable]
            .withIpAddress(ctx.ipAddress())
            .withMetadata(ctx.toMetadataJson())   [traceId + ip, NOT userAgent, NOT tenantId]
      → emission path is either:
           (a) secureEventService.recordEvent(event)  → REQUIRES_NEW tx → authEventPort.record()
               [Login, RefreshToken, ForgotPassword, ResetPassword]
           (b) authEventPort.record(event) directly, same outer tx
               [Logout, Register, VerifyEmail, ResendVerification]
      → JpaAuthEventAdapter.record(): authEventRepository.save(event);
            catch(DataAccessException) → log.warn(...), swallow, return normally
  → auth_events row committed (or, for path (b), rolled back together with the outer tx if it fails)
  → No alerting, no retry, no buffer on persistence failure today
```

---

## 5. Non-Functional Requirements

### Performance
- Story Technical Notes require "no auth-path latency impact > 5ms" from the async publisher. **Today's writes are synchronous, in-tx (REQUIRES_NEW or same-tx) DB inserts** — there is no async publisher to measure against. This requirement is currently not meaningful as stated; it presupposes an async design that doesn't exist yet. See OQ-4.
- Test Scenario 5 (100 RPS for 10 min, no event loss) has no existing load-test harness in the repo (Gap).
- `auth_events` indexes verified present: `(user_id, created_at)`, `(tenant_id, created_at)`, `(event_type, created_at)` — adequate for anticipated EPIC-007 read patterns, no index gap identified for current scope.

### Availability / Reliability
- AC4 implies an SLO-like expectation ("login still succeeds" under audit-store outage) but no formal SLO/SLA number is stated anywhere (e.g., max acceptable event-loss window, max retry backlog age before alert escalation). Gap.
- No defined behavior for what happens if the in-process buffer (once built) itself overflows or the app restarts mid-backlog. Gap.

### Security
- AC3's append-only requirement is currently enforced functionally (trigger-based) but not via least-privilege DB grants as literally specified — see AC3 analysis and OQ-2.
- AC5 (no PII beyond necessity) — verified largely satisfied today; needs an explicit automated test (log-scrubbing grep, Test Scenario 4) rather than relying on code review discipline going forward.
- `tenant_id` is currently never populated on any `AuthEvent` — this is a multi-tenancy isolation gap for the eventual EPIC-007 viewer (a tenant admin reading the audit stream could see cross-tenant events, or none at all, depending on how EPIC-007 filters). Flagged as a risk below.

### Observability
- `docs/observability-standards.md` already documents the target audit-log JSON shape including `userAgent` and `traceId` — this story is the implementation of that pre-existing spec, not a new spec. States "Audit log is append-only... Retention: minimum 1 year" — no retention enforcement exists yet (explicitly out of scope per story, consistent).
- Phase 9 of the observability standards' rollout checklist explicitly lists "audit events fired for all security-relevant actions" — this story is that checklist item.

### i18n / Accessibility
- Not applicable — no UI surface in this story (confirmed: "Angular component changes: none").

---

## 6. Open Questions

| # | Question | Stakeholder | Assumption if unanswered | Risk if assumption wrong |
|---|----------|-------------|---------------------------|----------------------------|
| OQ-1 | AC1 lists 9 event names (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOCKOUT`, `LOGOUT`, `REGISTER`, `VERIFY`, `PASSWORD_RESET_REQUESTED`, `PASSWORD_CHANGED`, `TOKEN_REFRESH_REUSE`) that do not literally match the ~13 event-type strings already in production code. **Should existing literals be renamed to match AC1 exactly, or should AC1's names be treated as a documentation-level taxonomy with an explicit alias/mapping table, leaving code as-is?** | PM, Architect | Assume AC1 names are the target canonical taxonomy and a rename is required, introduced via a new `AuthEventType` enum — but this is a breaking change to any existing consumer of the raw strings and must be confirmed (no real consumer exists today since EPIC-007 hasn't started) | If wrong: either EPIC-007 is built against names that later get renamed out from under it, or the rename is skipped and AC1 is permanently "satisfied" only by an informal mapping nobody enforces |
| OQ-2 | AC3 and the Technical Notes explicitly say "denied at DB privilege level" / "restricted DB grants (INSERT/SELECT only)." Today's enforcement is MySQL triggers, not a restricted DB user. **Is a new least-privilege DB role/user genuinely required, or do the existing triggers satisfy the intent and the story text should be read as descriptive rather than prescriptive?** Creating a new DB role touches connection-pool/credential management and deployment scripts — materially larger than it sounds. | Architect, Security | Assume triggers satisfy AC3's *functional* intent and a privilege-level restriction is a defense-in-depth enhancement to be explicitly scoped in/out at Gate 1, not silently added or silently skipped | If compliance specifically requires privilege-level enforcement for audit purposes, trigger-only enforcement may fail an audit even though it is functionally equivalent |
| OQ-3 | AC4 requires async/buffered/retried audit writes with ops alerting on failure, and the story's own Risks section flags "Compliance requires synchronous audit writes" as a risk needing confirmation **before Sprint 2**. No async infrastructure exists in the codebase today. **Is building genuinely new in-process buffering/retry infrastructure acceptable scope for this story's MVP, or does AC4 require the compliance sign-off called out in the story's Background section before any implementation work starts — and if compliance mandates synchronous writes, does today's synchronous swallow-and-log behavior already satisfy "does not block auth" without needing a buffer at all?** | Compliance, Architect | Assume compliance sign-off is a hard gate that must complete before implementation scope is finalized for AC4 — this requirements document does not assume an answer | If skipped: building bespoke retry infrastructure that compliance later rejects in favor of mandated synchronous writes is wasted work; conversely, shipping synchronous-only when async was actually required leaves the "audit store down blocks login" failure mode unaddressed |
| OQ-4 | Technical Notes require "no auth-path latency impact > 5ms" attributed to "async event publisher with retry buffer" — but today's writes are synchronous, so there is no async publisher whose overhead the 5ms budget could be measured against. **Once OQ-3 is resolved, does the 5ms budget apply to (a) the synchronous DB insert itself if writes stay synchronous, (b) only the in-process hand-off latency if an async buffer is built, or (c) is this NFR inherited from a generic template and not actually validated against this story's real design space?** | Architect, PM | Assume the 5ms figure needs to be re-derived once OQ-3's sync-vs-async decision is made, rather than treated as a fixed target today | If the figure is kept as-is without re-deriving it, a load test (Test Scenario 5) could pass or fail for reasons unrelated to the actual bottleneck |
| OQ-5 | `tenant_id` column exists but is verified never populated by any of the six use cases today. Is populating it in scope for this story (it's part of AC2's schema list), and if so, where does the value come from for pre-auth events (e.g. `LOGIN_FAILURE` for an unknown email, where no tenant has been resolved)? | PM, Architect | Assume populating `tenant_id` where resolvable (post-auth events) is in scope under AC2; pre-auth/unknown-tenant events remain `NULL`, consistent with `user_id`'s existing nullable pattern | If EPIC-007's UI assumes `tenant_id` is always populated for filtering/isolation, NULL rows could be invisible or mis-attributed in a multi-tenant view |
| OQ-6 | `LogoutUseCase` and `RegisterUserUseCase` write audit events in the *same* transaction as the primary operation (not REQUIRES_NEW), unlike Login/RefreshToken/PasswordReset which use `SecureEventService`. Is this inconsistency intentional, or an oversight that should be fixed as part of this story's "all auth events" mandate? | Architect | Assume it is an oversight and should be standardized to REQUIRES_NEW for consistency with AC4's durability intent, but flagging rather than fixing silently since it changes transaction semantics for two existing, shipped flows | If left as-is, a rollback in `RegisterUserUseCase` after the audit call silently drops the audit row with no alert — directly undermining AC4's intent for those two flows |
| OQ-7 | `user_agent` requires both a new `RequestContext` field and a new DB column. Should `User-Agent` be captured and stored verbatim, or does it need truncation/sanitization (it is fully attacker-controlled, unbounded-length, free-text input)? | Security | Assume truncation to a bounded length (e.g. 512 chars) and the same JSON-escaping discipline already applied to `traceId`/`ipAddress` — exact bound needs confirmation | If unbounded, a malicious or malformed `User-Agent` header could bloat `auth_events` rows or, if ever rendered unescaped in a future EPIC-007 UI, create a stored-XSS vector |

---

## 7. Risk Register

| Risk | Severity | Likelihood | Mitigation |
|------|----------|-----------|-------------|
| AC4's "buffered and retried" requires genuinely new infrastructure that does not exist anywhere in the codebase, with explicit compliance sign-off required before Sprint 2 per the story itself — building ahead of that sign-off risks wasted work or a control that doesn't satisfy compliance | **High** | Medium | Resolve OQ-3 before any implementation; do not start AC4 build until compliance confirms sync-vs-async requirement; consider scoping AC4 down to "synchronous swallow + WARN log + ops alert hook" for MVP if compliance permits, deferring true buffering to a follow-up story |
| `auth_events.tenant_id` is never populated today across all six flows; if EPIC-007's audit viewer assumes tenant isolation via this column, every historical and current event is effectively unfiltered/unisolated by tenant | **High** | High (already true today, not hypothetical) | Resolve OQ-5; if in scope, populate `tenant_id` wherever resolvable as part of this story rather than deferring to EPIC-007 |
| AC3's "DB privilege level" / "restricted DB grants" requirement is unimplemented as literally specified; only trigger-based enforcement exists. An external compliance audit checking specifically for DB-grant-level enforcement may fail despite passing this story's own test scenarios | **Medium** | Medium | Resolve OQ-2 explicitly at Gate 1; if privilege-level enforcement is mandated, scope the new DB role/credential-rotation work explicitly |
| `LogoutUseCase` and `RegisterUserUseCase` audit writes are not durable against outer-transaction rollback, inconsistent with the REQUIRES_NEW pattern used elsewhere and with AC4's "audit write never silently fails" intent | **Medium** | Low-Medium | Resolve OQ-6; standardize all six flows on the same durability pattern (REQUIRES_NEW via `SecureEventService`) |
| AC1's event-name mismatch, if resolved by renaming literals, is a breaking change for any future EPIC-007 consumer built against current names in the interim | **Medium** | Low (EPIC-007 not yet started) | Resolve OQ-1 before EPIC-007 begins discovery; introduce `AuthEventType` enum now regardless of naming decision |
| `user_agent` is fully attacker-controlled, unbounded free text; if stored without length bounds or escaping discipline, risks row bloat or a future stored-injection vector when EPIC-007 renders it | **Low** | Low | Resolve OQ-7; apply the same JSON-escaping already present in `RequestContext.toMetadataJson()` and a documented length cap |
| No SLO is defined for acceptable event-loss duration/volume during an audit-store outage, nor for buffer-overflow/restart behavior once AC4's buffering is built | **Medium** | Medium | Define explicit numeric SLOs as part of resolving OQ-3, not left implicit |
| "No auth-path latency impact > 5ms" cannot currently be measured meaningfully against a synchronous write path; using it as a literal pass/fail gate without re-deriving it post-OQ-3 may give a false pass or fail | **Low** | Medium | Resolve OQ-4; re-baseline the 5ms figure once the sync-vs-async design is settled at Gate 2 |

---

## 8. Gaps (missing from source material entirely)

1. **No numeric SLO** for audit-store-outage tolerance (e.g., how long can audit writes be unavailable before this becomes a P1 incident; backlog-size alert thresholds per `docs/observability-standards.md`'s alert-severity convention).
2. **No definition of "ops alerting channel"** beyond the phrase itself — no Slack channel, PagerDuty service, or alert name is specified.
3. **No explicit list of which of the 9 AC1 event types map to which of the ~13+ already-implemented literal strings** — this mapping does not exist anywhere and had to be reconstructed during this verification pass.
4. **No retention or storage-growth projection** for `auth_events` — explicitly out of scope ("Retention automation"), but the absence of even a rough volume estimate makes Test Scenario 5's "no event loss" claim hard to validate operationally.
5. **No mention of how `auth_events` rows correlate with general application logs** during an incident investigation — e.g., is `traceId` in `auth_events.metadata` expected to be cross-referenced with centralized log aggregation? Not specified.
6. **No specification of backfill/migration for historical events** — events recorded by US-001 through US-007 prior to this story's gap-closure work will retain old literal names, no `tenant_id`, no `user_agent`. If OQ-1/OQ-5/OQ-7 result in changes, historical rows are permanently inconsistent with new rows; no decision is recorded on whether that's acceptable.
7. **No specification of who can read `auth_events`** — the "restricted DB grants (INSERT/SELECT only)" phrase implies a reader role exists or will exist; that role and its access-control model isn't described.

---

## 9. Stakeholder Map

| Stakeholder | Interest |
|-------------|----------|
| Security & Compliance team (story's named persona) | Primary consumer of the eventual audit trail; needs schema completeness (AC2), tamper-evidence (AC3), and no data loss (AC4) to trust the stream for investigations |
| PM | Owns AC1 naming decision (OQ-1), tenant_id scope (OQ-5), and the Sprint 2 compliance-confirmation deadline called out in the story's own Background section |
| Architect | Owns durability-pattern consistency (OQ-6), the sync-vs-async infrastructure decision (OQ-3/OQ-4), and DB-privilege-vs-trigger tradeoff (OQ-2) |
| Security | Owns the DB-privilege-level requirement (OQ-2), `user_agent` handling/bounds (OQ-7), and sign-off on log-scrubbing test adequacy (AC5/Test Scenario 4) |
| Compliance/Legal | Explicitly named in the story as the required approver for AC4's async/best-effort semantics before Sprint 2 — not optional per the story's own text |
| EPIC-007 team (future) | Downstream consumer of whatever event-type taxonomy and schema this story finalizes — strong interest in OQ-1 and OQ-5 being resolved before they start |
| Ops/SRE (alerting channel owner) | Needs the "ops alerting channel" concretely named and integrated (Gap 2) before AC4's alerting clause can be implemented or tested |
| QA | Owns execution of the 5 Test Scenarios, several of which (load test, log-scrub grep, audit-store-down integration test) require new test infrastructure not yet present |

---

## 10. Definition of Ready

- [x] Bounded context identified: `identity`
- [x] Existing schema and code verified directly against source — `AuthEvent.java`, `SecureEventService.java`, `V2__identity_schema.sql`, `AuthEventPort.java`, `JpaAuthEventAdapter.java`, `RequestContext.java`, and all six use-case emission sites read in full
- [x] Reuse-first survey complete — story is confirmed to be predominantly gap-closure, not greenfield
- [x] Annotated AC table identifies AC1/AC5 as largely satisfied, AC2 as a concrete schema gap, AC3/AC4 as open design questions requiring stakeholder decisions before estimation
- [x] **OQ-1 through OQ-7 resolved at Gate 1 (2026-07-01, product owner delegated the call)** — see §11 below
- [ ] Compliance sign-off on AC4 semantics — superseded by the Gate 1 MVP-scoping decision in §11 (OQ-3); revisit if compliance later mandates durable buffering
- [ ] "Ops alerting channel" (Gap 2) — concrete channel/integration TBD at design phase; design must define the alert hook interface regardless of which channel is wired up later

---

## 11. Gate 1 Decisions (resolved 2026-07-01)

| # | Decision |
|---|----------|
| OQ-1 | **Rename, don't alias.** Introduce an `AuthEventType` enum now. Rename the literals that map 1:1 to AC1's canonical names: `ACCOUNT_LOCKED`→`LOCKOUT`, `REFRESH_FAMILY_REVOKED`→`TOKEN_REFRESH_REUSE`, `REGISTRATION_SUCCESS`→`REGISTER`, `VERIFICATION_SUCCESS`→`VERIFY`. Keep the remaining granular states (`LOGIN_PENDING_ACCOUNT`, `ACCOUNT_UNLOCKED`, `REGISTRATION_DUPLICATE_EMAIL`, `VERIFICATION_FAILED`, `TOKEN_REFRESH_SUCCESS`/`FAILURE`, `PASSWORD_RESET_THROTTLED`/`FAILED`, `ACCOUNT_LOCKED_WRITE_FAILED`) as additional enum values beyond AC1's 9. Rationale: no real consumer exists yet (EPIC-007 hasn't started), so renaming now is free; a permanent alias table would just be technical debt. |
| OQ-2 | **Both, not either/or.** Keep the existing `BEFORE UPDATE`/`BEFORE DELETE` triggers (already passes the literal test) and add a new least-privilege runtime DB role/user (INSERT+SELECT only) for the application's connection to `auth_events`, as defense-in-depth. Scope as a design-phase infra task (connection pool / deployment config), not a code-only change. |
| OQ-3 | **MVP scope, no external blocker.** Keep the proven synchronous write as the primary path (already shipped, low risk). On failure, enqueue to a small in-process bounded retry buffer with scheduled backoff; alert ops if the buffer backs up or retries are exhausted. Explicitly accept and document the residual risk: the in-memory buffer does not survive a pod restart/crash — no durable outbox/broker for MVP. The story's own named fallback (synchronous-only via config) remains the escape hatch if this is later judged insufficient. This decision is made by engineering judgment in lieu of an external compliance sign-off that isn't available in this workflow; flag for retroactive compliance review post-ship if the org has a formal process for that. |
| OQ-4 | Resolved by OQ-3: the 5ms latency budget applies only to the failure-path overhead (catch + enqueue), not the already-shipped synchronous-insert baseline, since the primary path is unchanged. |
| OQ-5 | **In scope.** Populate `tenant_id` wherever resolvable (post-auth-resolution events); stays `NULL` for pre-auth/unknown-tenant events, mirroring the existing `user_id` nullable pattern. |
| OQ-6 | **Standardize.** Move `LogoutUseCase` and `RegisterUserUseCase` onto `SecureEventService` (REQUIRES_NEW), matching the other four flows, for durability consistency. |
| OQ-7 | Cap `user_agent` at 512 chars; apply the same JSON-escaping discipline already used for `traceId`/`ipAddress` in `RequestContext`. |

These decisions are binding inputs to impact analysis (Phase 2) and design (Gate 2); Gate 2 design and threat-modeling may still surface refinements but should not need to revisit the *scope* questions above.
