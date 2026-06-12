# EPIC-001: Identity & Access — Enterprise Authentication Foundation

```
EPIC ID: EPIC-001
EPIC TITLE: Identity & Access — Enterprise Authentication Foundation
Description: Delivers tenant-aware user identity, credential-based authentication
(JWT access + rotating refresh tokens), email verification, password reset,
brute-force protection, and audit event emission. Establishes the frozen auth
contract all future epics consume.
Business Goal: Unblock all downstream feature epics with a secure, standardized
auth layer; zero high/critical findings in pre-GA security review.
Success Metric: RBAC epic builds on the token contract with zero contract changes;
99.9% auth availability; 100% auth events audited.
Priority: P0
Story Points (total): 33
Dependencies: Blocks ALL feature epics. Blocked by: transactional email provider
selection. External: email service, secrets vault.
```

---

## US-001 — Establish tenant-aware identity data model and migrations

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a platform development team,
I want a tenant-scoped user identity schema with versioned migrations,
So that all auth and future features share one consistent, multi-tenant-safe identity store.

### Background / Context
First feature on a greenfield platform; every epic depends on this schema. Multi-tenancy and future-IdP support (identity_provider column, token_version) are embedded now to avoid disruptive migrations under load later. Schema is reviewed via ADR before merge because downstream epics will adopt it immediately.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Users table created via migration | Flyway migration creates `users` with UUID PK, tenant_id, email, password_hash, status enum (PENDING/ACTIVE/LOCKED/DISABLED), identity_provider (default LOCAL), consent_accepted_at, created/updated timestamps | P0 | Email stored as citext |
| 2 | Email uniqueness is per-tenant | Unique index on (tenant_id, lower(email)); duplicate insert in same tenant fails with constraint violation; same email in a different tenant succeeds | P0 | Cross-tenant isolation |
| 3 | PII encrypted at rest | Column-level or TDE encryption verified on email and name fields; approach documented in ADR | P0 | Platform non-negotiable |
| 4 | Supporting tables created | `refresh_tokens`, `auth_tokens`, `auth_events` created with indexes on hashed token columns and (user_id, created_at) | P0 | Audit table append-only |
| 5 | Migration repeatable in CI | Clean DB → migrate → rollback test passes in pipeline on every build | P1 | |

### Technical Notes (ARC)
- API endpoints affected: none
- Database changes: 4 new tables (`users`, `refresh_tokens`, `auth_tokens`, `auth_events`) + indexes; Flyway migrations
- Spring Security considerations: none yet; entities prepared for Argon2 hash storage
- Angular component changes: none
- Performance considerations: UUIDv7 recommended for index locality; index on (tenant_id, email)
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Migrate clean DB | Integration | All tables/indexes exist; migration checksum stable |
| 2 | Duplicate email same tenant | Integration | Constraint violation |
| 3 | Same email in two tenants | Integration | Both rows persist |
| 4 | Read raw storage for PII column | Security | Ciphertext, not plaintext |
| 5 | Insert 1M user rows, query by (tenant, email) | Performance | < 10ms index lookup |

### Dependencies
- Blocked by: none (foundational)
- Blocks: US-002 through US-008 and all future epics
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Schema churn after downstream adoption | Med | High | ADR + architecture review before merge |

### Out of Scope
- Role/permission tables (RBAC epic)
- Org/tenant tables (Epic 3 — tenant_id is a column, not yet an FK)

---

## US-002 — Enable self-service registration with email verification

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a B2C end consumer,
I want to create an account with my email and a strong password and verify my email,
So that I can securely access the platform.

### Background / Context
First user-facing flow on the platform. Verification prevents account abuse and is required before login completes. Consent capture at signup supports the GDPR posture. Email delivery is abstracted behind a MailSender interface because the provider is not yet selected.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Valid registration creates PENDING account | POST /api/v1/auth/register with valid payload returns 201 within 500ms; user row status=PENDING; verification email dispatched | P0 | |
| 2 | Password policy enforced server-side | Passwords < 12 chars or in breached-password denylist rejected with 400 + error code AUTH_PWD_001 and field-level message | P0 | Client strength meter is advisory only |
| 3 | Verification token single-use, expires | Token valid 24h; consuming it sets status=ACTIVE and email_verified_at; second use returns 410 + AUTH_VRF_002 | P0 | Token stored hashed |
| 4 | No account enumeration on duplicate email | Registering an existing email returns the same 201-style response and sends an "account exists" notice email instead | P0 | Uniform timing ±50ms |
| 5 | Resend is throttled | Max 1 resend per 60s per account, 5 per 24h; excess returns 429 + Retry-After header | P1 | |
| 6 | Consent recorded | consent_accepted_at persisted; registration without consent checkbox returns 400 | P0 | |
| 7 | Form meets WCAG 2.1 AA | Keyboard-complete; labels associated; errors via aria-describedby; strength meter conveys level via text + icon, not color alone | P0 | Axe scan: zero critical issues |

### Technical Notes (ARC)
- API endpoints affected: POST /api/v1/auth/register, POST /api/v1/auth/verify-email, POST /api/v1/auth/resend-verification
- Database changes: writes to `users`, `auth_tokens`
- Spring Security considerations: Argon2id password encoder; endpoints publicly accessible (permitAll)
- Angular component changes: RegistrationFormComponent, VerificationLandingComponent
- Performance considerations: email dispatch async; registration p95 < 500ms
- Feature flag required: Yes (auth rollout flag)

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: register → verify → ACTIVE | E2E | Account active, success toast shown |
| 2 | Edge case: expired token | Integration | 410 + resend path works |
| 3 | Failure case: email provider down | Integration | Account stays PENDING; later resend succeeds |
| 4 | Security: duplicate-email timing uniformity; XSS/SQLi payloads in fields | Security | Uniform response timing; payloads rejected/escaped |
| 5 | Load: 50 RPS registrations sustained | Performance | p95 < 500ms |

### Dependencies
- Blocked by: US-001; transactional email provider selection
- Blocks: US-003
- External: email service (dev fallback: MailHog)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Email deliverability issues | Med | High | SPF/DKIM setup; provider with sandbox mode |

### Out of Scope
- B2B invite flow (Epic 3)
- Social login
- Admin-created users

---

## US-003 — Authenticate users via login issuing JWT access and refresh tokens

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a registered user,
I want to log in with my email and password and receive a session,
So that I can access protected platform features.

### Background / Context
Core authentication path and the highest-traffic endpoint on the platform. Establishes the frozen token contract (claims schema) consumed by every future feature; the contract freezes at end of Sprint 2 and is protected by a schema contract test in CI.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Valid credentials yield token pair | POST /api/v1/auth/login returns 200 with RS256 access token (TTL 15 min) and refresh token (TTL 14 days, httpOnly Secure SameSite cookie for web clients) within 300ms p95 | P0 | |
| 2 | Token claims match frozen contract | Access token contains sub, tenant_id, email_verified, roles[], iat, exp, jti, token_version; validated against published JSON schema in contract test | P0 | Contract freeze gate |
| 3 | Invalid credentials indistinguishable | Wrong password and unknown email both return 401 + AUTH_001 + "Invalid email or password"; response time delta < 50ms | P0 | Anti-enumeration |
| 4 | Unverified accounts cannot log in | PENDING account login returns 403 + AUTH_002 with resend-verification action in response body | P0 | |
| 5 | JWKS published | GET /.well-known/jwks.json returns active public key set; key rotation adds new kid without invalidating in-flight tokens | P0 | |
| 6 | Protected routes enforce JWT | Any /api/v1/** request (except auth endpoints) without valid token returns 401; tampered/expired token returns 401 | P0 | Spring Security filter chain |

### Technical Notes (ARC)
- API endpoints affected: POST /api/v1/auth/login, GET /.well-known/jwks.json, GET /api/v1/users/me
- Database changes: refresh_tokens insert per login (family_id)
- Spring Security considerations: custom filter chain, Argon2 encoder, RS256 keys from secrets vault
- Angular component changes: LoginComponent, AuthService, HTTP interceptor attaching bearer token
- Performance considerations: Argon2 parameters load-tested; per-IP rate limit 10 attempts/min (Redis)
- Feature flag required: Yes

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: login → GET /users/me | E2E | Identity echoed; correct claims |
| 2 | Edge case: same email in two tenants | Integration | Each logs into correct tenant context |
| 3 | Failure case: PENDING account login | Integration | 403 + resend action |
| 4 | Security: alg=none, modified tenant_id, expired token, wrong-key signature | Security | All rejected with 401 |
| 5 | Load: 100 RPS sustained 10 min | Performance | p95 < 300ms |

### Dependencies
- Blocked by: US-001, US-002
- Blocks: US-004, US-005, US-006, US-008 and all future epics
- External: secrets vault for signing keys

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Claim contract changes after downstream adoption | Med | High | Contract freeze end of Sprint 2 + schema contract test in CI; version via token_version |
| Argon2 params too costly at scale | Med | Med | Load test in Sprint 2; parameters configurable |

### Out of Scope
- MFA challenge step
- SSO redirect flows
- "Remember me" duration options

---

## US-004 — Refresh sessions silently with rotating refresh tokens

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As an authenticated user,
I want my session renewed automatically before expiry,
So that I stay logged in securely without re-entering credentials.

### Background / Context
Short-lived access tokens limit theft impact, but require silent renewal for acceptable UX (design system: login screen only when refresh fails). Rotation with reuse detection is the primary defense against refresh-token theft.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Refresh rotates the token | POST /api/v1/auth/refresh with valid refresh token returns new access + new refresh token; old refresh marked revoked in the same transaction | P0 | |
| 2 | Reuse triggers family revocation | Presenting an already-rotated token revokes the entire token family and returns 401 + AUTH_RT_001; user must re-login | P0 | Theft detection |
| 3 | Concurrent refresh race handled | Two simultaneous refreshes from one client (e.g., two tabs) do not falsely revoke the family; grace window ≤ 10s documented | P0 | |
| 4 | Silent renewal in frontend | Angular interceptor refreshes when access token has < 2 min TTL; login screen shown only when refresh fails | P0 | Per design system |

### Technical Notes (ARC)
- API endpoints affected: POST /api/v1/auth/refresh
- Database changes: refresh_tokens rotation (family_id, revoked_at)
- Spring Security considerations: refresh endpoint excluded from JWT filter; opaque token lookup by hash
- Angular component changes: HTTP interceptor + token refresh scheduler in AuthService
- Performance considerations: refresh p95 < 150ms; indexed token-hash lookup
- Feature flag required: No (rides auth flag)

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: idle 20 min, then act | E2E | Action succeeds, no login prompt |
| 2 | Edge case: two-tab concurrent refresh | Integration | Both sessions survive |
| 3 | Failure case: refresh with revoked family | Unit | 401 |
| 4 | Security: replay rotated token | Security | Family revoked; all sessions 401 |
| 5 | Load: 200 RPS refresh | Performance | p95 < 150ms |

### Dependencies
- Blocked by: US-003
- Blocks: US-005
- External: none

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Race-condition false logouts | Med | Med | Grace window + dedicated integration test |

### Out of Scope
- Device/session management UI ("active sessions" list)

---

## US-005 — Enable logout with refresh token revocation

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As an authenticated user,
I want to log out,
So that my session cannot be reused on this device.

### Background / Context
Completes the session lifecycle. Revoking the refresh family means a stolen device cannot mint new sessions; residual access-token validity is bounded by the 15-minute TTL unless a jti denylist is adopted (ARC decision recorded via ADR).

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Logout revokes refresh family | POST /api/v1/auth/logout revokes the refresh token family within 1s; subsequent refresh returns 401 | P0 | |
| 2 | Client state cleared | Access token, cookie, and cached identity removed; user redirected to login with confirmation toast | P0 | |
| 3 | Access token cut-off bounded | Revoked-session access tokens rejected no later than access-token expiry (15 min); jti denylist decision documented in ADR | P1 | ARC: denylist vs. TTL-only |
| 4 | Logout is idempotent | Repeat logout returns 204; no error surfaced to user | P1 | |

### Technical Notes (ARC)
- API endpoints affected: POST /api/v1/auth/logout
- Database changes: refresh_tokens family revocation
- Spring Security considerations: optional Redis jti denylist (ADR)
- Angular component changes: AuthService teardown, route guard redirect
- Performance considerations: revocation in single indexed update
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: logout → back button → protected route | E2E | Redirect to login |
| 2 | Edge case: double logout | Unit | 204, idempotent |
| 3 | Failure case: refresh after logout | Integration | 401 |
| 4 | Security: stolen access token after logout | Security | Rejected within 15-min ceiling (or instantly if denylist adopted) |
| 5 | Load: logout at 50 RPS | Performance | No errors; < 200ms p95 |

### Dependencies
- Blocked by: US-003, US-004
- Blocks: none
- External: Redis (only if denylist adopted)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| 15-min residual token window unacceptable to compliance | Low | Med | ADR decision point; denylist available as fast-follow |

### Out of Scope
- "Log out all devices" (requires session management UI)

---

## US-006 — Enforce password policy and brute-force lockout

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a security & compliance stakeholder,
I want password strength enforced and repeated failed logins throttled,
So that credential-stuffing and brute-force attacks are mitigated.

### Background / Context
OWASP-aligned hardening of the login path. Account lockout plus IP rate limiting covers both targeted and distributed attacks. The reset-password flow (US-007) is the escape path if an attacker weaponizes lockout against a victim account.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Account lockout after failures | 5 consecutive failed logins within 15 min sets status=LOCKED for 15 min; login during lockout returns 423 + AUTH_LCK_001 | P0 | Counter resets on success |
| 2 | Lockout UX is safe | UI shows "Too many attempts. Try again later or reset your password." — no remaining-attempts count exposed | P0 | |
| 3 | IP-level rate limiting | > 10 login attempts/min/IP returns 429 + Retry-After; limit configurable | P0 | Redis token bucket |
| 4 | Breached-password check | Registration/reset passwords checked against denylist (top-100k list or k-anonymity API); match returns 400 + AUTH_PWD_002 | P1 | Offline list acceptable for MVP |
| 5 | Lockout auto-expires | After 15 min, login with correct credentials succeeds without admin action | P0 | |

### Technical Notes (ARC)
- API endpoints affected: modifies POST /api/v1/auth/login behavior; no new endpoints
- Database changes: failed-attempt tracking (column on users or derived from auth_events)
- Spring Security considerations: lockout check in authentication provider; uniform error timing
- Angular component changes: lockout error state in LoginComponent
- Performance considerations: lockout check adds < 20ms to login; Redis IP buckets
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: 5 failures → locked → wait 15 min → success | Integration | Lockout expires automatically |
| 2 | Edge case: 4 failures + 1 success | Unit | Counter resets |
| 3 | Security: distributed attempts across many IPs vs. one account | Security | Account lockout still triggers |
| 4 | Security: lockout response timing vs. normal 401 | Security | Uniform timing |
| 5 | Load: 500 RPS attack traffic | Performance | Rate limiter holds; legitimate users unaffected |

### Dependencies
- Blocked by: US-003
- Blocks: none (US-007 provides the lockout escape path)
- External: Redis

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Attacker uses lockout to DoS a victim account | Med | Med | Password-reset escape path + support runbook |

### Out of Scope
- CAPTCHA
- Device fingerprinting
- Adaptive/risk-based authentication

---

## US-007 — Enable self-service password reset via email

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a registered user who forgot my password,
I want to reset it via a secure email link,
So that I can regain access without contacting support.

### Background / Context
Self-service recovery reduces support load and is the escape path for locked accounts (US-006 risk). Anti-enumeration responses and full-session revocation on reset are security requirements, not options.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | Uniform response regardless of account existence | POST /api/v1/auth/password/forgot always returns 202 with "If an account exists…" message; timing delta < 50ms | P0 | Anti-enumeration |
| 2 | Reset token single-use, 1h expiry | Valid token sets new password and is consumed; reused/expired token returns 410 + AUTH_RST_002 with "request a new link" CTA | P0 | Stored hashed; entropy ≥ 128 bits |
| 3 | Reset revokes all sessions | Successful reset revokes all refresh token families for the user within 1s | P0 | |
| 4 | Reset unlocks locked accounts | LOCKED account returns to ACTIVE on successful reset | P0 | Pairs with US-006 |
| 5 | Request throttling | Max 3 reset requests per account per hour; excess silently accepted (202) but not sent, and audited | P1 | |
| 6 | New password passes full policy | Same validation as registration incl. denylist; cannot equal current password | P0 | |

### Technical Notes (ARC)
- API endpoints affected: POST /api/v1/auth/password/forgot, POST /api/v1/auth/password/reset
- Database changes: auth_tokens (type=RESET), refresh_tokens mass-revoke
- Spring Security considerations: endpoints permitAll; token comparison constant-time
- Angular component changes: ForgotPasswordComponent, ResetPasswordComponent with strength meter
- Performance considerations: email dispatch async; queue backlog alerting
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: forgot → email → reset → login with new password | E2E | Full recovery flow works |
| 2 | Edge case: reused reset link | Integration | 410 + "request new link" CTA |
| 3 | Failure case: old sessions after reset | Integration | All prior sessions return 401 |
| 4 | Security: enumeration timing test; token entropy verification | Security | Uniform timing; ≥ 128 bits entropy |
| 5 | Load: 20 RPS forgot-password | Performance | Email queue backlog < 30s |

### Dependencies
- Blocked by: US-001, US-002, US-003; transactional email provider
- Blocks: none
- External: email service

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Email delivery delay degrades recovery UX | Med | Med | Provider SLA; resend option; queue monitoring |

### Out of Scope
- Security questions
- SMS-based reset
- Admin-forced reset

---

## US-008 — Emit audit events for all authentication actions

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-001: Identity & Access — Enterprise Authentication Foundation | _(PM assigns)_ | _(Tech lead assigns)_ |

### User Story
As a security & compliance team member,
I want every authentication event recorded immutably,
So that we can investigate incidents and satisfy audit requirements.

### Background / Context
Platform principle: all state changes must be logged, audit-ready from day one. This story produces the event stream; the Audit Log UI (Epic 7 / EPIC-007) consumes it later. Async/best-effort write semantics (AC 4) require compliance confirmation before Sprint 2.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|--------------------|----------|-------|
| 1 | All auth events captured | LOGIN_SUCCESS, LOGIN_FAILURE, LOCKOUT, LOGOUT, REGISTER, VERIFY, PASSWORD_RESET_REQUESTED, PASSWORD_CHANGED, TOKEN_REFRESH_REUSE each write an auth_events row within 1s of the action | P0 | |
| 2 | Event schema complete | Each event: UTC timestamp, event_type, user_id (nullable for unknown email), tenant_id, source IP, user agent, outcome, correlation_id | P0 | Passwords/tokens never logged |
| 3 | Append-only enforced | UPDATE/DELETE on auth_events denied at DB privilege level; attempt fails in test | P0 | |
| 4 | Audit write failure does not block auth | If audit write fails, login still succeeds; failure alerted via ops channel; events buffered and retried | P1 | Confirm with compliance |
| 5 | No PII beyond necessity | Email not stored in event payload when user_id is resolvable; raw passwords/tokens never present (log-scrubbing test) | P0 | |

### Technical Notes (ARC)
- API endpoints affected: none public (Audit Log UI is EPIC-007)
- Database changes: auth_events append-only table; restricted DB grants (INSERT/SELECT only)
- Spring Security considerations: events published from auth filter/provider layer
- Angular component changes: none
- Performance considerations: async event publisher with retry buffer; no auth-path latency impact > 5ms
- Feature flag required: No

### Test Scenarios (QA)

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Happy path: full user journey | E2E | Complete, correctly ordered event trail |
| 2 | Edge case: audit store down during login | Integration | Login succeeds; events replayed on recovery |
| 3 | Failure case: UPDATE/DELETE attempt on auth_events | Security | Denied at DB privilege level |
| 4 | Security: grep all logs/events for password/token strings | Security | Zero hits |
| 5 | Load: 100 RPS login for 10 min | Performance | No event loss |

### Dependencies
- Blocked by: US-001
- Blocks: EPIC-007 (Audit Logs & Activity Feed) consumes this stream
- External: ops alerting channel

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Compliance requires synchronous audit writes | Low | Med | Confirm policy before Sprint 2; sync mode available as config |

### Out of Scope
- Audit viewing UI
- Retention automation
- SIEM export

---

## Recommended Sprint Order

| Sprint | Stories | Points | Notes |
|--------|---------|--------|-------|
| Sprint 1 | US-001, US-002, US-003 | 15 | Schema, registration, login; prep contract freeze |
| Sprint 2 | US-004, US-005, US-008 | 9 | Sessions + audit; token contract freeze; load test |
| Sprint 3 (or Sprint 2 if Option A) | US-006, US-007 | 8 | Lockout + password reset; security review prep |

## Open Decisions (required before Sprint 1)

1. **Scope (ARC vs PM conflict):** Option A — full 33 pts in Sprints 1–2 (schedule risk) vs. Option B — defer US-006 and US-007 to Sprint 3 (~24 pts in Sprints 1–2, safer).
2. **Transactional email provider:** hard blocker for US-002 and US-007.
3. **Audit write consistency:** async/best-effort (US-008, AC 4) acceptable to compliance, or synchronous required?
