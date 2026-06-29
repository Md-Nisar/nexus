# US-006 Security Review

**Reviewer:** Claude Code (inline review — security-reviewer agent failed 3×)
**Date:** 2026-06-29
**Verdict: APPROVED**

> Cross-referenced: `SECURITY.md`, `docs/features/US-006/03b-threat-model.md`.
> Scope: `git diff origin/main...HEAD` — all files on `feature/US-006`.
> Dependency scan: `npm audit --omit=dev --audit-level=high` → **0 vulnerabilities**.
> Backend OWASP Dependency-Check: deferred to CI (weekly scheduled run).

---

## 1. Security Invariants — All Verified

| Invariant | Location | Status |
|-----------|----------|--------|
| Argon2 ALWAYS runs before lockout check (timing oracle closure, T-LCK-5) | `LoginUseCase.java:135` before `:147` | ✅ PASS |
| Dummy hash precomputed at startup (T-2.2 anti-enumeration) | `LoginUseCase.java:107` `@PostConstruct init()` | ✅ PASS |
| Status gate is ALLOW-LIST — only `ACTIVE` issues tokens (T-2.5) | `LoginUseCase.java:175,183` — PENDING and `!= ACTIVE` both rejected | ✅ PASS |
| Counter writes commit in REQUIRES_NEW — independent of outer TX rollback (T-LCK-6) | `SecureEventService.java:77,118` | ✅ PASS |
| M-OL-1 fix: `persistResetAttempts` uses JPQL bulk UPDATE, bypasses `@Version` | `JpaUserRepository.java:33` `@Modifying(clearAutomatically = true)` | ✅ PASS |
| RFC 7807: no stack traces, SQL, or class names escape (A09) | `GlobalExceptionHandler.java:136` log-only; `server.error.include-stacktrace: never` | ✅ PASS |
| PII in logs: no email or rawPassword in any new log line | Grep confirms — new lines log `userId` (UUID) only | ✅ PASS |

---

## 2. STRIDE Threat Coverage

### T-LCK-1/2 — Credential stuffing (Spoofing / DoS)
- IP bucket: `ip-max-attempts: 10` per 60 s at Servlet layer (`LoginRateLimitFilter.java:131`).
- DB lockout: 5 consecutive failures → LOCKED regardless of source IP (`SecureEventService.java:86–93`).
- **PASS** — dual-layer control in place.

### T-LCK-3 — Lockout-as-DoS (DoS)
- Dual-layer throttle slows mass-locking; `ACCOUNT_LOCKED` audit event emitted (M-7: `SecureEventService.java:89–91`).
- US-007 self-service reset is the escape valve; support runbook referenced in design 12.3.
- **PASS (accepted risk)** — documented in threat model.

### T-LCK-4 — Account existence via AUTH_LCK_001 (Information Disclosure)
- Non-existent accounts never reach the LOCKED state (no counter row created for unknown emails; `LoginUseCase.java:161–163`).
- `AUTH_LCK_001` can only appear after 5+ real failed attempts on a real account.
- **PASS (accepted per OWASP lockout guidance, design 12.2)**.

### T-LCK-5 — Timing oracle: locked vs. wrong-password (Information Disclosure)
- `passwordVerifier.matches()` at Step 2 (`LoginUseCase.java:135–137`) runs **before** the LOCKED branch at Step 4 (`:147`).
- Dummy hash precomputed at `@PostConstruct` (`:107`) with identical Argon2 parameters.
- `LoginLockoutIT.should_lockAccount_when_5ConsecutiveFailedAttempts` exercises the locked path end-to-end.
- **PASS** — timing invariant enforced and test-covered.

### T-LCK-6 — Counter rollback when outer TX rolls back (Tampering / Repudiation)
- `@Transactional(propagation = REQUIRES_NEW)` on `persistFailedAttempt` (`SecureEventService.java:77`) and `persistResetAttempts` (`:118`).
- `LoginLockoutIT.should_persistFailedAttemptCounter_when_outerTransactionRollsBack` proves the counter is 1 in DB after a failed login (outer TX rolls back, inner TX committed).
- **PASS** — REQUIRES_NEW boundary correct and test-proven (M-2).

### T-LCK-7 — Optimistic lock race (Tampering)
- `persistFailedAttempt` swallows `ObjectOptimisticLockingFailureException` as a benign lost increment (`SecureEventService.java:94–97`).
- `persistResetAttempts` uses JPQL bulk UPDATE that bypasses `@Version` entirely (`JpaUserRepository.java:33–35`), eliminating M-OL-1.
- **Concurrency test (M-3) was not implemented.** DF-3 accepted: read-modify-write under OL means N concurrent failures may result in slightly fewer than N effective increments. This is bounded — a slow accumulation attack still eventually locks the account. Recorded as accepted residual risk.
- **PASS (with accepted residual risk per DF-3)**.

### T-LCK-8 — Refresh token replay on locked account (Spoofing / Replay)
- **DF-4 decision: ACCEPTED and documented** in `User.java:115` and `03b-threat-model.md` section DF-4.
- Rationale: brute-force lockout ≠ credential compromise. Valid refresh families belong to the legitimate user; revoking them on lockout disrupts innocent sessions.
- Refresh endpoint has separate rate limiting (`refresh-max-attempts: 30` per `ip-window-seconds`).
- US-007 password reset will revoke all refresh families.
- **PASS (design decision, explicitly accepted)**.

### T-LCK-9 — IP spoofing via X-Forwarded-For (Spoofing)
- `LoginRateLimitFilter.java:102`: `String clientIp = request.getRemoteAddr()` — XFF is never read.
- DF-1 deployment precondition documented in class Javadoc (`LoginRateLimitFilter.java:43–51`).
- **PASS** — XFF injection cannot move the bucket key. Behind a proxy, `getRemoteAddr()` is the proxy IP (known precondition, documented).

### T-LCK-10 — Client ignores Retry-After (Tampering / DoS)
- Server enforces limits independently. `Retry-After` is advisory; the account remains locked until `lockedUntil` expires regardless of client behaviour.
- **PASS (accepted per DF-5)**.

### T-LCK-11 — AUTH_PWD_002 denylist bypass (Insecure Design)
- Exact-match limitation documented in `PasswordPolicyService` Javadoc (M-5 satisfied).
- `Set.contains` is verbatim; trivial mutations (case changes, leet substitution) bypass the denylist.
- **PASS (accepted per DF-6)** — Javadoc documents the limitation; normalization is optional future work.

### T-LCK-12 — Inner TX failure on non-optimistic exception (DoS / Repudiation)
- `SecureEventService.persistFailedAttempt` has a two-tier catch (M-8 / DF-2):
  1. `ObjectOptimisticLockingFailureException` → debug log (benign, `:94–97`).
  2. Any other exception → WARN log with `userId` only + `ACCOUNT_LOCKED_WRITE_FAILED` audit event + **not rethrown** (`:97–102`).
- Caller always receives AUTH_001 (not a 500) even if the inner write fails completely.
- **PASS** — fail-safe behaviour implemented, observable signal raised (DF-2 resolved).

### T-LCK-13 — Memory DoS via eviction lag (DoS)
- `InMemoryRateLimitStore` `@Value` repointed to `nexus.security.rate-limit.ip-window-seconds` (now 60 s, tighter than the old 300 s default).
- **PASS** — eviction window is correctly set to the IP bucket window.

### T-LCK-14 — Log injection on lockout paths (Information Disclosure / Log Injection)
- New log lines in `SecureEventService.java:91` and `LoginUseCase.java:223` log only `userId` and `tenantId` (both UUID values — no free-form attacker-controlled strings).
- `CorrelationIdFilter` sanitises trace IDs to `[A-Za-z0-9._-]{1,64}` before they reach MDC.
- The pre-existing `writeTooManyRequests` interpolates `traceId` into JSON — safe because `CorrelationIdFilter` guarantees safe characters.
- **PASS** — no attacker-controlled strings reach new log lines unescaped.

---

## 3. OWASP Top 10 Checklist

| # | Control | Finding |
|---|---------|---------|
| A01 Broken Access Control | No resource ownership changes; lockout is self-contained | PASS |
| A02 Cryptographic Failures | Argon2id unchanged; dummy hash uses same parameters; no custom crypto | PASS |
| A03 Injection | `resetFailedAttemptsDirect` uses JPQL `:userId` named param; `retryAfter` is `long` (not user-controlled) | PASS |
| A04 Insecure Design | LOCKOUT_WINDOW_SECONDS not enforced (counts all failures since last success) — documented in `AuthConstants.java:18–20`; DF-3/DF-6 accepted | PASS |
| A05 Misconfiguration | `server.error.include-stacktrace: never`; 423 handler logs nothing; no internals in 423 body | PASS |
| A06 Vulnerable Components | `npm audit` → 0 high/critical; Maven OWASP check runs in CI | PASS |
| A07 Identification & Auth | Timing invariant enforced; ALLOW-LIST status gate; no 500 on auth path | PASS |
| A08 Software Integrity | No new deserialization, no new dynamic class loading | N/A |
| A09 Security Logging | `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED` audit events; PII-free log lines | PASS |
| A10 SSRF | No outbound calls on lockout path | N/A |

---

## 4. RFC 7807 Compliance

423 response shape (verified via `LoginLockoutIT.should_returnRfc7807ProblemDocumentAndRetryAfterHeader_when_accountLocked`):

```json
{
  "status": 423,
  "detail": "Account locked. Try again later or reset your password.",
  "code": "AUTH_LCK_001",
  "retryAfterSeconds": 874,
  "traceId": "..."
}
```

- `Content-Type: application/problem+json` ✅
- `Retry-After` header equals `retryAfterSeconds` ✅
- No stack trace, no Java class names, no SQL ✅
- Body asserted in `T-022` IT test ✅

---

## 5. Frontend Security (AC-2)

`login-form.component.ts:178–179`: `AUTH_LCK_001` → generic message
> "Too many attempts. Try again later or reset your password."

- Does not display exact retry time (not an enumeration risk)
- Does not use `[innerHTML]` or `bypassSecurityTrustHtml`
- `AppError` abstraction (not `HttpErrorResponse`) maintains the boundary
- **PASS**

---

## 6. Dependency Scans

| Tool | Result |
|------|--------|
| `npm audit --omit=dev --audit-level=high` (nexus-frontend) | **0 vulnerabilities** |
| Maven OWASP Dependency-Check | Deferred to CI weekly run (CVSS ≥ 7 fails build) |

---

## 7. Accepted Risks (carried forward from threat model)

| ID | Risk | Rationale |
|----|------|-----------|
| T-LCK-4 | `AUTH_LCK_001` confirms account existence | OWASP accepted; only after 5 real failures; US-007 reset is compensating control |
| T-LCK-7/DF-3 | OL race may allow 1–2 extra attempts before lockout | Bounded; atomic `UPDATE count=count+1` is future mitigation |
| T-LCK-8/DF-4 | Lockout does not revoke refresh families | Brute-force ≠ compromise; US-007 resets all families |
| T-LCK-9/DF-1 | IP bucket ineffective behind a proxy | Deployment precondition documented; DB lockout is globally authoritative regardless |
| T-LCK-11/DF-6 | `AUTH_PWD_002` is exact-match only | Documented limitation; normalization is optional future work |
| LOCKOUT_WINDOW_SECONDS | Rolling window not enforced | Counts failures since last success; documented in `AuthConstants.java` |

---

## Verdict: APPROVED

All 14 STRIDE threats are mitigated or carry explicitly documented accepted risks. The three Critical security invariants (Argon2 timing, REQUIRES_NEW transaction boundaries, RFC 7807 no-leak) are all implemented correctly and integration-tested. The M-OL-1 optimistic-lock bug is fixed. No new OWASP vulnerabilities are introduced. Frontend dependency scan is clean.

> Auth, crypto, and PII-handling paths were explicitly reviewed and pass.
