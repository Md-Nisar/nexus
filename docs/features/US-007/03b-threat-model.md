# US-007 — Threat Model (STRIDE)

_Output of `/design` security-reviewer pass. Each threat → mitigation → task. Feeds Gate 2._

**Scope:** `POST /api/v1/auth/password/forgot`, `POST /api/v1/auth/password/reset`, `PasswordResetEmailEvent` dispatch, `auth_tokens (type=RESET)` lifecycle.

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-S1 | Attacker forges a reset token without receiving the email | Guess or brute-force token | `TokenGenerator` produces 32 bytes via `SecureRandom` = 256-bit entropy (≥ 128-bit AC-2). SHA-256 stored; lookup is exact hash match on indexed column — no enumerable sequential IDs. | Verify in test: token entropy, DB hash-only storage |
| T-S2 | Attacker reuses a previously valid token (replay) | Capture email link and replay | Token consumed on first use (`markConsumed` + optimistic lock flush). `consumed_at != null` → 410. The `UNIQUE (token_hash)` constraint and flush-before-commit prevent double-consume under concurrent requests. | Reuse test (IT): concurrent POST /reset with same token → second gets 410 |

---

### T — Tampering

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-T1 | Attacker modifies token in transit (email link URL) | MITM or URL manipulation | Token is 256-bit random hex — modified value simply won't match any stored hash → 410. TLS in transit. | — |
| T-T2 | Race condition: two concurrent reset requests for same token | Two tabs click link simultaneously | Optimistic lock on `auth_tokens.version` + `flush()` after `markConsumed`. First commit wins; second gets `OptimisticLockingFailureException` → mapped to 410 | Concurrent-reset IT test |
| T-T3 | Attacker injects malicious password to bypass policy | Supply crafted newPassword | `PasswordPolicyService.validate()` (length + denylist) runs before Argon2 hash. Jakarta `@Size(max=256)` on DTO prevents unbounded input. | Password policy unit tests |

---

### R — Repudiation

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-R1 | User denies requesting a reset | Dispute of action | `PASSWORD_RESET_REQUESTED` audit event records `userId`, `ip_address`, timestamp. `PASSWORD_CHANGED` records the completion. Append-only `auth_events` table (trigger-enforced). | Verify audit events in IT test |
| T-R2 | Token value appears in logs (creates repudiable evidence) | Log grep | Raw token must never be logged (SEC-3). `PasswordResetEmailEvent.toString()` masks token: `rawToken=<redacted>`. `MailEventListener` logs only `maskEmail(toEmail)`. | Log-scrub test: grep test output for raw token pattern |

---

### I — Information Disclosure

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-I1 | Account enumeration via `/forgot` response differentiation | Different response for known vs. unknown email | `/forgot` always returns `202` with identical body. Async email dispatch removes SMTP latency from the request path. HMAC lookup is the only per-email operation — constant-time at DB index level. | Timing test: known vs. unknown email delta < 50ms |
| T-I2 | Account enumeration via response timing (found vs. not-found path) | Measure response time differential | `emailBlindIndexService.blindIndex()` runs unconditionally (both paths). Async dispatch ensures SMTP wait does not inflate the "found" path. Measured delta expected < 10ms (HMAC only). | IT timing assertion |
| T-I3 | Token value leaked in server logs | Log injection or log access | `rawToken` never passed to any logger. `LogMaskingUtil.maskEmail` used on all email references. `PasswordResetEmailEvent.toString()` redacts rawToken. | Static analysis / log-scrub test |
| T-I4 | Error message reveals whether account exists | `/forgot` returning different errors for valid vs. invalid email format | 400 fires only on structural validation (blank field, invalid format) — not on "email not found". Both known and unknown valid emails return 202. | Contract test: valid unknown email → 202, invalid email format → 400 |
| T-I5 | Residual 15-min JWT validity after reset | Attacker holds a stolen access token | **Accepted residual risk (Gate 1 decision).** `token_version` incremented on reset. Access tokens remain valid up to 15 min (TTL). `revokeAllUserSessions` closes the refresh-token vector immediately. | Document in tech notes; no implementation task |

---

### D — Denial of Service

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-D1 | Email flood: attacker triggers reset emails for a victim | Repeatedly POST /forgot with victim email | AC-5: max 3 reset emails/account/hour. Excess silently accepted (202) but email suppressed + `PASSWORD_RESET_THROTTLED` audit event. | Throttle IT test: 4th request → 202 but no email; audit event present |
| T-D2 | IP-based DoS on `/forgot` endpoint | High-rate anonymous requests | Existing `LoginRateLimitFilter` does not cover `/password/forgot`. The endpoint is computationally cheap (HMAC lookup + no Argon2). Acceptable for MVP; document for ops. | No task at MVP; note in ops runbook |
| T-D3 | Email queue backlog under load | 20 RPS of reset requests | Email dispatch is async (`@Async` + `@TransactionalEventListener`). Spring async executor queue depth is bounded by `spring.task.execution.pool.queue-capacity`. Alert on queue depth (existing observability). | Performance: 20 RPS test → queue backlog < 30s |
| T-D4 | Lock-out amplification: attacker repeatedly resets a victim's password | Rapid reset → victim's session revoked repeatedly | AC-5 throttle (3/hr) limits resets. Each reset requires email-link click — attacker cannot complete reset without email access. | No additional task |

---

### E — Elevation of Privilege

| ID | Threat | Attack Vector | Mitigation | Task |
|----|--------|---------------|------------|------|
| T-E1 | Attacker completes reset without owning the email address | Intercept or predict the reset token | Token is 256-bit random, hash-stored, single-use. Email delivery channel is the authorization gate — attacker must have inbox access. | Token entropy unit test |
| T-E2 | Attacker uses reset to unlock a victim's locked account, then re-locks via brute-force | Circular lockout/reset cycle | Reset unlocking (AC-4) is intentional behavior (escape path). Lockout re-trigger requires 5 fresh wrong attempts after reset — this is the correct design. | No additional task |
| T-E3 | Attacker uses reset endpoint to set a known-weak password and then logs in as victim | Bypass denylist with exotic input | `PasswordPolicyService.validate()` runs before the hash step. Same denylist as registration. Argon2 hash stored immediately. | Denylist + same-password policy tests |
| T-E4 | CSRF: attacker triggers reset on behalf of authenticated user | Forged cross-origin POST | Stateless API; no session cookies on reset endpoint; CSRF not applicable. `SameSite=Strict` on refresh-token cookie does not affect this endpoint. | — |

---

## Threat → Task Mapping (Security Tasks Required)

| Threat ID | Task | Priority |
|-----------|------|----------|
| T-S1, T-E1 | Unit test: verify token is 64-char hex, stored as SHA-256 hash, not raw | P0 |
| T-S2, T-T2 | IT test: concurrent POST /reset with same token — second must return 410 | P0 |
| T-I1, T-I2 | IT test: timing assertion (known vs. unknown email delta < 50ms on `/forgot`) | P0 |
| T-I4 | IT test: valid unknown email → 202; blank/malformed email → 400 | P0 |
| T-R2, T-I3 | Log-scrub test: grep test output / logs for raw token pattern (64-char hex) | P0 |
| T-D1 | IT test: 4th reset request in same hour → 202, no email sent, `PASSWORD_RESET_THROTTLED` event recorded | P1 |
| T-T3, T-E3 | Unit test: new password = current password → `AUTH_RST_003`; denylist hit → `AUTH_PWD_002` | P0 |
| T-R1 | IT test: success path emits `PASSWORD_RESET_REQUESTED` + `PASSWORD_CHANGED` audit events | P0 |

---

## Accepted Risks (No Mitigating Task)

| ID | Risk | Rationale |
|----|------|-----------|
| T-I5 | 15-min residual JWT validity after reset | Gate 1 decision; bounded by access token TTL; refresh token revocation closes primary re-auth vector |
| T-D2 | No IP-level rate limit on `/forgot` | Endpoint is cheap (HMAC only); MVP scope; ops note |
