# US-006 Threat Model

> Scope: brute-force lockout + IP rate-limit reshape + `AUTH_PWD_002` split on the **Identity** login/register path.
> Cross-referenced against: `03-design.md` (Section 12 Open Design Decisions), `LoginUseCase.java`, `LoginRateLimitFilter.java`, `InMemoryRateLimitStore.java`, `User.java`, `PasswordPolicyService.java`, `SecureEventService.java`.

## 1. Trust Boundaries and Components

| Zone | Component | Role after US-006 | Boundary crossed |
|------|-----------|-------------------|------------------|
| **Untrusted (Internet)** | HTTP client / attacker | Sends `POST /auth/login`, `/auth/register`, `/auth/refresh` | email, password, body, transport headers (incl. `X-Forwarded-For`) |
| **Boundary 1 — Servlet pre-MVC** | `LoginRateLimitFilter` | IP bucket (10/60s) + USER-HMAC bucket (5/900s); body size cap (8 KB); reads `getRemoteAddr()` | request body bytes, derived `clientIp`, `emailHmac` |
| **Boundary 1 — in-memory state** | `InMemoryRateLimitStore` | Per-JVM sliding-window counters; eviction thread | bucket key (`IP:`/`USER:`/`REFRESH_IP:`), timestamps |
| **Trusted — MVC** | `LoginController` | Binds DTO, injects server-side `tenantId`, builds `RequestContext` | validated email/password, `tenantId`, `ctx` |
| **Trusted — application (outer TX)** | `LoginUseCase` (`@Transactional`) | Argon2-always, auto-expiry eval, lockout pre-check (423), credential branch, status gate, token issue | `User` aggregate, `LoginResult` |
| **Trusted — application (inner TX)** | `SecureEventService` (`REQUIRES_NEW`) | `persistFailedAttempt`, `persistResetAttempts`, audit `recordEvent` | `userId`, `now`, `AuthEvent` |
| **Trusted — crypto** | `PasswordVerifierPort` (Argon2) | Constant-cost verify on real or dummy hash | password, hash |
| **Trusted — domain** | `User` aggregate | `recordFailedAttempt`, `lockAccount`, `resetFailedAttempts`, `unlockIfExpired`; `@Version` | counter, `lockedUntil`, `status` |
| **Trusted — persistence** | MySQL `users` / `auth_events` | Durable lockout counter, lock instant, audit trail; optimistic-lock `version` | row state |
| **Boundary 2 — response** | `GlobalExceptionHandler` | Maps `AccountLockedException` → 423 + `Retry-After`; filter writes 429 directly | RFC 7807 problem doc, `Retry-After`, `retryAfterSeconds` |
| **Untrusted — browser** | `LoginFormComponent` | Maps `AUTH_LCK_001` to generic message | error code (count/Retry-After deliberately not shown) |

Key boundary observations:
- The **only** authoritative IP-derived value is `getRemoteAddr()` (filter line 84; documented as T-1.3). No `X-Forwarded-For` parsing exists — important for T-LCK-9.
- DB lockout is **globally authoritative**; the IP bucket is **per-JVM** (store-type=memory), so it does not survive multi-replica deployments.
- The lockout counter write crosses an **inner TX boundary** (`REQUIRES_NEW`) precisely because the outer login TX rolls back on the failed path. This is the crux of T-LCK-6 and T-LCK-7.

---

## 2. STRIDE Analysis

| ID | Component | STRIDE | Threat | Existing mitigation | Required mitigation | Residual risk |
|----|-----------|--------|--------|---------------------|---------------------|---------------|
| T-LCK-1 | Filter IP bucket + DB lockout | DoS / Spoofing | Credential stuffing from a single IP | IP bucket 10/60s (filter); DB lockout 5/900s per user; USER-HMAC bucket 5/900s | None beyond design | **Low** — single IP capped at 10/min and account locks at 5 |
| T-LCK-2 | DB lockout (global) | DoS / Spoofing | Distributed stuffing: many IPs, one account (rotating botnet) | DB lockout is per-user and global → 5 wrong attempts lock regardless of source IP | None — DB lockout is the designed control here | **Low for compromise**, converts into T-LCK-3 |
| T-LCK-3 | DB lockout | DoS | Lockout-as-DoS: attacker locks any account with 5 wrong passwords | Dual-layer IP throttle slows mass-locking; US-007 reset escape; support runbook (design 12.3) | Confirm IP bucket meaningfully rate-limits per attacker (DF-1); add `ACCOUNT_LOCKED` rate alerting (M-7) | **Medium (accepted, 12.3)** |
| T-LCK-4 | `GlobalExceptionHandler` 423 | Information disclosure | Account-existence enumeration via `AUTH_LCK_001` | Argon2-always preserves latency; non-existent accounts can never reach 423 | Accepted per OWASP (design 12.2); counter only for `found` users confirmed | **Low (accepted, 12.2)** |
| T-LCK-5 | `LoginUseCase` Step 2/4 | Information disclosure (timing) | Timing oracle: distinguish locked vs active-wrong-password by latency | Argon2 (Step 2) runs before Step 4 lock branch | Add timing test asserting locked-path ≈ active-wrong-password latency (M-1) | **Low** — provided Argon2-always invariant is test-enforced |
| T-LCK-6 | `LoginUseCase` outer TX / `SecureEventService` inner TX | Tampering / Repudiation | Counter rollback: outer TX rollback discards increment; lockout never fires | Counter write in `persistFailedAttempt` (`REQUIRES_NEW`) commits independently | Add test proving counter is persisted after `AuthenticationException` rolls back outer TX (M-2); see DF-2 for inner-TX-failure case | **Medium** — correct by design but fragile to future refactors |
| T-LCK-7 | `User.@Version` / `persistFailedAttempt` | Tampering (race) | Optimistic-lock race: N concurrent failures read same count, all increment to same value, threshold skipped | `@Version` on `User`; read-increment-save inside one `REQUIRES_NEW` TX; design swallows `OptimisticLockingFailureException` as benign | Add concurrency test bounding max effective attempts before lock (M-3); consider atomic `UPDATE count=count+1` (DF-3) | **Medium** — bounded extra attempts but ceiling is undefined |
| T-LCK-8 | `LoginUseCase` Step 3/8b; refresh token | Spoofing / Replay | Existing refresh-token families usable on a locked account via `/refresh` | `unlockIfExpired` only commits on success path — unlock requires correct credentials | Document whether `lockAccount` should revoke active refresh families (M-9 / DF-4) | **Medium** — locked account can still mint access tokens via `/refresh` |
| T-LCK-9 | `LoginRateLimitFilter` | Spoofing | IP spoofing via `X-Forwarded-For` to rotate IP bucket key | Filter uses `getRemoteAddr()` only, never XFF (T-1.3) — XFF injection cannot move bucket key | **DF-1:** behind a proxy, `getRemoteAddr()` is the proxy IP → all users share one bucket (false-DoS) or bucket is bypassed per replica (M-4) | **High in proxied deployment** — deployment topology must be defined |
| T-LCK-10 | `GlobalExceptionHandler` / filter | Tampering / DoS | Client ignores `Retry-After` and keeps flooding | Server enforces limits independently of header; locked account returns 423 at Argon2 cost | Accepted (DF-5). `retryAfterSeconds` discloses exact unlock instant — minor, accepted | **Low** |
| T-LCK-11 | `PasswordPolicyService` | Insecure design | `AUTH_PWD_002` denylist bypass: `Password123!` (13 chars, not verbatim in list) passes exact-match | Exact-string denylist + 12-char minimum | Document exact-match limitation (DF-6); optionally normalize (case-fold + leet-collapse) before lookup (M-5) | **Medium** — denylist stops verbatim passwords only |
| T-LCK-12 | `SecureEventService.persistFailedAttempt` | DoS / Repudiation | Inner `REQUIRES_NEW` TX fails (deadlock, pool exhaustion) — not `OptimisticLockingFailureException`; behavior undefined | Design catches only optimistic-lock failures | **DF-2:** specify catch policy — fail-safe to AUTH_001 for user, never 500, raise observable signal (M-8) | **Medium** — could leak 500 on auth path or silently disable lockout under DB stress |
| T-LCK-13 | `InMemoryRateLimitStore` eviction | DoS (memory) | Distributed single-visit flood grows the map between eviction sweeps | Eviction thread prunes per `ip-window-seconds` (now 60s, tighter than old 300s) | Confirm `@Value` repoint to `ip-window-seconds` is applied | **Low** |
| T-LCK-14 | Audit events / logs | Information disclosure / Log injection | PII or attacker-controlled CRLF in `ACCOUNT_LOCKED`/`LOGIN_FAILURE` logs | Design §9 logs `userId`+`tenantId` only; IP masked in MDC; no email logged | Verify no attacker-controlled string reaches new log lines unescaped (M-6) | **Low** |

---

## 3. Design Review Flags

### DF-1 — IP bucket is per-JVM and IP source is `getRemoteAddr()` only ⚠️ CHANGE REQUIRED

- **Design says:** per-instance IP bucket is a "known limitation"; client IP is always `getRemoteAddr()`, never XFF.
- **Threat (T-LCK-2/3/9):** In any deployment behind a load balancer or ingress, `getRemoteAddr()` is the *proxy* address. Either all users share one bucket (false-429 DoS for all users) or per-JVM counters make the cap trivially bypassable across replicas. A botnet can then lock accounts with the IP layer adding no meaningful friction.
- **Recommendation: Change required.** Define the production topology and a *trusted-proxy* forwarded-header strategy (e.g. `ForwardedHeaderFilter` with an allowlist of proxy IPs) before claiming the IP bucket as a credential-stuffing control. If MVP truly runs single-instance with direct client connections (no proxy), document that constraint explicitly as a precondition.

### DF-2 — Only `OptimisticLockingFailureException` is handled in `persistFailedAttempt` ⚠️ CHANGE REQUIRED

- **Design says:** swallow optimistic-lock failures as benign; must never surface as 500.
- **Threat (T-LCK-12):** Any *other* inner-TX failure (deadlock, connection loss, pool timeout) has undefined behavior — could bubble as a 500 on the unauthenticated login path (info disclosure, OWASP A09) or, if broadly caught, silently disable lockout under DB stress.
- **Recommendation: Change required.** Specify the catch policy for non-optimistic exceptions: log at WARN with `userId` only, allow the caller to still throw AUTH_001 (fail-safe for the user), and emit an `ACCOUNT_LOCKED_WRITE_FAILED` audit/metric so a sustained outage that disables lockout is observable.

### DF-3 — Read-modify-write counter under optimistic lock (§4, 12.4) — Acceptance with bound

- **Design says:** re-read inside `REQUIRES_NEW`, increment, save; swallow collisions as lost increments.
- **Threat (T-LCK-7):** concurrent failures lose increments, letting an attacker exceed 5 effective tries.
- **Options:** (a) accept and document the bounded extra-attempt window with a concurrency test proving a hard upper bound; (b) switch to an atomic `UPDATE users SET failed_attempt_count = failed_attempt_count + 1 ...` so every attempt counts deterministically. Option (b) eliminates the residual risk.

### DF-4 — Lockout gates `/login` only; refresh families NOT revoked — **Decision: ACCEPTED**

**Decision recorded (US-006 implementation):** Account lockout (brute-force response) does NOT
revoke active refresh-token families. Rationale:
- US-006 locks accounts in response to failed password attempts — the attacker does NOT yet
  have valid credentials, so they cannot hold a valid refresh token for this account.
- Revoking refresh families would disrupt legitimate sessions on legitimate devices that
  happened to be running while an attacker was attempting brute-force from elsewhere.
- If the threat model changes (e.g., suspected credential compromise), US-007 password reset
  WILL revoke all refresh families (a harder control for a confirmed-compromise scenario).
- This decision is revisited in US-007 design.

**Residual risk:** A known-compromised account that is LOCKED by admin action (not brute-force)
may still have active refresh sessions. This is a separate threat from brute-force lockout;
admin lockout path (if added) should invoke revokeFamily.

### DF-5 — `retryAfterSeconds` discloses the exact `lockedUntil` instant — Accepted (low)

- Exposes the precise unlock time. Standard HTTP `Retry-After` semantics; minor attacker value. Accept as-is.

### DF-6 — `AUTH_PWD_002` is an exact-match denylist split, not a strength improvement — Acceptance with note

- `Set.contains` is verbatim; trivial mutations bypass it. Accept the split as a P1 contract change but document the exact-match limitation in `PasswordPolicyService` Javadoc. Optional: normalize (case-fold + leet-collapse) before lookup.

---

## 4. Accepted Risks

| ID | Accepted risk | Rationale |
|----|---------------|-----------|
| T-LCK-4 | `AUTH_LCK_001` confirms an account exists for the email | OWASP lockout guidance; usability outweighs marginal enumeration that only occurs after 5 failed attempts; US-007 reset is the compensating control (design 12.2). |
| T-LCK-3 | Attacker can deliberately lock a victim's account | Inherent to account-lockout design; mitigated by US-007 self-service reset, dual-layer throttle, and a support runbook. **Conditioned on DF-1 being resolved.** |
| T-LCK-5 | Argon2 cost is paid on every login including locked accounts | Required to close the timing oracle; added latency is the intended cost (design 12.1, Q1=a). |
| T-LCK-10 / DF-5 | Exact remaining lock time disclosed via `Retry-After`/`retryAfterSeconds` | Standard HTTP semantics; needed by legitimate clients; minimal attacker value. |
| T-LCK-13 | Per-JVM IP bucket and best-effort memory eviction | MVP choice; Redis swap is the future path (design 12.6, requirements Assumption 5). |
| — | No CAPTCHA, device fingerprinting, or distributed bucket | Explicitly out of scope (design 12.6). |

---

## 5. Mitigations That Become Implementation Tasks

| Task | Threat(s) | Description |
|------|-----------|-------------|
| M-1 | T-LCK-5 | Add a timing test asserting the locked-account (423) path latency is statistically indistinguishable from the active-wrong-password (401) path, proving Argon2 runs before Step 4. |
| M-2 | T-LCK-6 | Add a test proving `failed_attempt_count` is durably committed via `persistFailedAttempt` (REQUIRES_NEW) even after the outer `@Transactional` login rolls back on `AuthenticationException`. |
| M-3 | T-LCK-7 / DF-3 | Add a concurrency test firing N parallel failed logins for one account and assert the account locks within a documented upper bound; if the bound is unacceptable, implement an atomic `UPDATE ... count = count + 1`. |
| M-4 | T-LCK-9 / DF-1 | Decide and document the deployment topology and a trusted-proxy forwarded-header strategy (or single-instance precondition) so the IP bucket key reflects the real client IP. |
| M-5 | T-LCK-11 / DF-6 | Document the exact-match limitation of the `AUTH_PWD_002` denylist in `PasswordPolicyService` Javadoc; optionally normalize (case-fold + leet-collapse) before denylist lookup. |
| M-6 | T-LCK-14 | Verify no attacker-controlled string (email, raw headers) reaches any new log line on the lockout paths; add a CRLF/log-injection assertion for `ACCOUNT_LOCKED`/`ACCOUNT_UNLOCKED`. |
| M-7 | T-LCK-3 | Emit a rate-observable `ACCOUNT_LOCKED` signal (metric or alert threshold on `auth_events`) so mass-lockout campaigns are detectable. |
| M-8 | T-LCK-12 / DF-2 | Implement the explicit catch policy for non-optimistic exceptions inside `persistFailedAttempt`: fail-safe to AUTH_001, never 500, and raise an `ACCOUNT_LOCKED_WRITE_FAILED` audit/metric when the inner write fails. |
| M-9 | T-LCK-8 / DF-4 | Document whether `lockAccount` should revoke active refresh-token families; if lockout is intended as a compromise-response control, wire `revokeFamily`; otherwise record the explicit decision that lockout gates `/login` only. |
