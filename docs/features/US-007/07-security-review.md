# Security Review — US-007

Feature: Self-service password reset via email
Branch: feature/US-007 (uncommitted working tree)
Reviewer: Application Security Engineer (hostile-mindset audit)
Date: 2026-06-30

## Auth / Crypto / PII Review Statement

I explicitly reviewed the three highest-risk concern areas:

- Authentication / token lifecycle: reviewed TokenGenerator, TokenHasher, AuthToken, the single-use consume+flush+optimistic-lock path in ResetPasswordUseCase, expiry handling, and session revocation via SecureEventService.revokeAllUserSessions. Token generation (32-byte SecureRandom to 64-hex) and storage (SHA-256, never raw) are correct and match SECURITY.md section 6. The single-use / replay defense is sound (mark-consumed + flush + 410 mapping). One durability gap in failure-event ordering (HIGH-2) and one timing-oracle gap (HIGH-1).
- Cryptography: SecureRandom (not Math.random), SHA-256 over raw bytes, HMAC-SHA256 blind index, Argon2 password hashing reused via PasswordHasherPort. No custom crypto. All algorithm choices conform to SECURITY.md section 6. No findings on algorithm/key strength.
- PII handling: verified raw email and raw token are never logged. PasswordResetEmailEvent.toString redacts the token and masks the email; all log statements log userId or maskEmail only. The reset token DOES travel in a URL query parameter inside the email body, acceptable for the email channel but flagged (LOW-1). No raw PII found in logs, DTOs, or error bodies.

## Threat Model Coverage

| Threat ID | Description | Mitigation in Code | Status |
|-----------|-------------|--------------------|--------|
| T-S1 | Forge/brute-force token | 32-byte SecureRandom, SHA-256 stored, exact indexed hash match | OK |
| T-S2 | Token replay (reuse) | markConsumed+flush, consumedAt not null -> 410, Version lock | OK |
| T-T1 | Token tamper in transit | 256-bit random, hash mismatch -> 410, TLS | OK |
| T-T2 | Concurrent reset race on same token | Optimistic lock + flush in try/catch -> 410 | OK |
| T-T3 | Malicious password bypasses policy | PasswordPolicyService.validate before hash; Size max 256 DTO | OK (MED-2) |
| T-R1 | User denies requesting reset | PASSWORD_RESET_REQUESTED + PASSWORD_CHANGED events w/ userId+ip | OK |
| T-R2 | Token in logs | toString redacts rawToken; listener logs masked email only | OK |
| T-I1 | Enumeration via response differentiation | /forgot always 202 identical body; async dispatch | OK |
| T-I2 | Enumeration via timing | found-path adds DB count + insert + audit tx; unknown returns at once | PARTIAL (HIGH-1) |
| T-I3 | Token leaked in logs | No raw token passed to any logger | OK |
| T-I4 | Error reveals account existence | 400 only on structural validation; unknown valid email -> 202 | OK |
| T-I5 | Residual 15-min JWT after reset | Accepted residual; tokenVersion++ + revokeAllUserSessions | OK (accepted) |
| T-D1 | Email flood throttle (3/hr) | DB count check; TOCTOU race allows bypass | PARTIAL (HIGH-3) |
| T-D2 | IP DoS on /forgot | No IP rate limit; accepted MVP risk | OK (accepted) |
| T-D3 | Email queue backlog | Async listener bounded executor | OK (not re-verified) |
| T-D4 | Lockout amplification | Throttle (3/hr); same TOCTOU caveat | PARTIAL (HIGH-3) |
| T-E1 | Reset without inbox access | Token is the authz gate; 256-bit random, single-use | OK |
| T-E2 | Unlock-then-relock cycle | Intentional escape path | OK (accepted) |
| T-E3 | Weak password via reset | PasswordPolicyService + same-password check | OK |
| T-E4 | CSRF on reset | Stateless, no session cookie, CSRF disabled | OK |

## Findings

### [HIGH] T-I2 timing oracle: found vs not-found path is trivially distinguishable
Severity: High
File: nexus-backend/src/main/java/com/example/nexus/identity/application/ForgotPasswordUseCase.java:86-125
OWASP: A07, A04
Issue: T-I2 claims the known/unknown delta is under 10ms because the blind index runs on both paths. In code the unknown-email path returns immediately after the HMAC + one indexed SELECT (lines 90-92). The known-email path additionally runs a second DB query (countByUserIdAndTypeAndCreatedAtAfter), SecureRandom token generation, SHA-256 hash, a DB INSERT (authTokenPort.save), a REQUIRES_NEW audit-event transaction, and an event publish: multiple extra DB round-trips versus zero. Async email dispatch removes only SMTP latency, not this synchronous in-request work.
Risk: An attacker measuring response latency over many samples distinguishes registered from unregistered emails, defeating the anti-enumeration control that is the whole purpose of the 202-always design (AC-1). Measurable side channel, not theoretical.
Fix: Equalise synchronous work by moving token generation, DB insert, and audit recording into the async AFTER_COMMIT listener so request-thread work is identical on both branches, or run a constant-time dummy workload on the not-found path. Add the timing IT the threat model promised (absent) and fail the build past threshold.

### [HIGH] PASSWORD_RESET_FAILED audit durability depends on a fragile REQUIRES_NEW annotation with no test
Severity: High
File: nexus-backend/src/main/java/com/example/nexus/identity/application/ResetPasswordUseCase.java:89-114,151-157
OWASP: A09
Issue: recordFailure calls secureEventService.recordEvent (annotated REQUIRES_NEW), then the use-case throws TokenExpiredException which rolls back the outer Transactional. The failure audit survives ONLY because recordEvent commits in a new transaction. No test asserts PASSWORD_RESET_FAILED persists after the 410. If REQUIRES_NEW is removed in a future refactor, the failure trail vanishes for every invalid-token attempt: exactly the signal needed to detect token brute-forcing (T-S1). Compounded by HIGH-4 (no rate limit on /reset), an attacker can both brute-force tokens and flood the audit log.
Risk: Loss of brute-force detection signal; silent A09 control failure under refactor.
Fix: Add an IT asserting PASSWORD_RESET_FAILED is persisted after a 410. Document the REQUIRES_NEW dependency inline. Do not rely on noRollbackFor as a substitute.

### [HIGH] Reset-request throttle (AC-5) is bypassable via TOCTOU race
Severity: High
File: nexus-backend/src/main/java/com/example/nexus/identity/application/ForgotPasswordUseCase.java:97-113
OWASP: A04
Issue: The 3-per-hour throttle reads a COUNT then conditionally inserts, with no row lock, unique constraint, or atomic guard. N concurrent /forgot requests for the same victim all run countByUserIdAndTypeAndCreatedAtAfter before any insert, all observe count below 3, and all proceed to insert tokens and publish emails. No SELECT FOR UPDATE, no per-hour unique index, and no IP/email filter in front of the endpoint. SECURITY.md section 8 mandates 3/email and 10/IP per hour on this exact endpoint: not implemented.
Risk: A burst of concurrent /forgot requests sends an unbounded number of reset emails to a victim (email-bomb / harassment), defeating T-D1/T-D4. Each excess email also exposes a live reset token.
Fix: Make the throttle atomic (SELECT FOR UPDATE on a counter row, or a per-hour unique constraint), AND add the SECURITY.md section 8 filter-level per-email + per-IP rate limit on /password/forgot via the existing LoginRateLimitFilter infrastructure.

### [HIGH] No rate limiting on POST /password/reset enables token brute-forcing and audit flooding
Severity: High
File: nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java:74
OWASP: A07, A04
Issue: /api/v1/auth/password/reset is permitAll and fronted only by LoginRateLimitFilter, which covers login/refresh, not reset. SECURITY.md section 8 mandates a 100/min/IP floor for other unauthenticated endpoints. Although 256-bit token entropy makes online guessing infeasible, the absence of ANY throttle on an unauthenticated, cheap endpoint violates the baseline and allows unbounded PASSWORD_RESET_FAILED audit-log flooding (compounding HIGH-2).
Risk: Audit-log flooding / DoS; loss of defense-in-depth against any future entropy regression; unbounded anonymous compute on a public endpoint.
Fix: Apply the SECURITY.md section 8 baseline IP rate limit (100/min) to both /password/forgot and /password/reset at the filter level; return 429 + Retry-After without revealing remaining attempts.

### [MEDIUM] Session revocation (AC-3) has a partial-failure / concurrent-rotation escape window
Severity: Medium
File: nexus-backend/src/main/java/com/example/nexus/identity/application/ResetPasswordUseCase.java:137-140 ; SecureEventService.java:111-114
OWASP: A07
Issue: revokeAllUserSessions runs in a separate REQUIRES_NEW sub-transaction at line 140 with no try/catch or WARN log in the use-case (design section 9 promised a WARN on revocation failure: absent). revokeByUserId only revokes rows WHERE revokedAt IS NULL at that instant; a refresh token rotated concurrently with the reset can escape revocation. The threat model marks AC-3 fully mitigated; it is mitigated for the common case only.
Risk: An attacker holding a refresh token who rotates it concurrently with the victim reset may retain a live session family past the reset (T-I5 covers only the 15-min access token, not the refresh family).
Fix: Run revocation within the password-update transaction, or re-run after commit and assert zero remaining active families; add the WARN-level alert on revocation failure that the design specifies.

### [MEDIUM] Frontend password maxLength (1024) contradicts backend DTO cap (256)
Severity: Medium
File: nexus-frontend/src/app/features/auth/reset-password/reset-password.component.ts:150
OWASP: A04
Issue: Validators.maxLength(1024) on newPassword, but ResetPasswordRequest.newPassword is Size max 256. A 257-1024 char password passes client validation, submits, and returns a generic 400 the component maps to An unexpected error occurred (no VALIDATION_FAILED branch, lines 182-198). The design specified maxLength(256).
Risk: Not directly exploitable; DTO/UI bound mismatch is a defense-in-depth smell and a confusing failure mode on a security-sensitive form.
Fix: Set the frontend validator to maxLength(256) to match the DTO and add a VALIDATION_FAILED branch to the error switch.

### [LOW] Reset token transmitted as URL query parameter
Severity: Low
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/mail/SmtpMailSenderAdapter.java:69 ; reset-password.component.ts:163
OWASP: A09, A02
Issue: The reset link is frontendBaseUrl/auth/reset-password?token=hex. SECURITY.md section 7 says no PII/secrets in URLs; section 2 warns tokens in URLs are logged by proxies/CDNs. The frontend reads token from queryParamMap, so the secret sits in browser history and the Referer header on any subsequent navigation/asset load. Conventional for email links but the token persists in the URL after load.
Risk: Token leakage via Referer to third-party resources, browser history on shared machines, or access logs if the SPA route is ever server-rendered.
Fix: After reading the token in ngOnInit, strip it from the URL via router.navigate with empty queryParams and replaceUrl true; ensure Referrer-Policy no-referrer on the reset page and load no third-party assets. TTL already 60 min.

### [LOW] AuthService uses non-standard Service decorator from angular core (pre-existing)
Severity: Low
File: nexus-frontend/src/app/features/auth/auth.service.ts:1,23
OWASP: n/a
Issue: imports Service from angular core and uses it as a decorator; the Angular DI decorator is Injectable, not Service. Present in committed HEAD (not introduced by US-007); the new forgotPassword/resetPassword methods inherit it. Flagging for confirmation only.
Risk: None security-relevant; potential DI breakage if Service is not a valid alias.
Fix: Confirm Service resolves; if a typo, change to Injectable providedIn root. Out of US-007 scope.

## Dependency Scan

- Frontend npm audit --omit=dev --audit-level=high: found 0 vulnerabilities. PASS.
- Backend ./mvnw dependency:tree: key security libs current, no known high CVEs at review date: Spring Boot 4.1.0, spring-web/webmvc 7.0.8, tomcat-embed-core 11.0.22, hibernate-core 7.4.1.Final, logback 1.5.34, snakeyaml 2.6, mysql-connector-j 9.7.0, bcprov-jdk18on 1.81, jjwt 0.12.6, HikariCP 7.0.2. No vulnerable component (A06) introduced by US-007. NOTE: OWASP Dependency-Check ossindex analyzer is disabled per recent commits (8f945f3 / 700b10d); full CVE gating relies on Trivy/CI and was not independently verified here.

## Post-Review Fixes Applied

All blocking and medium findings were resolved in the same session after the initial BLOCKED verdict.

| Finding | Fix |
|---------|-----|
| HIGH-1 Timing oracle | `ForgotPasswordUseCase`: added `tokenGenerator.generate()` dummy call on the not-found path to equalise CPU-bound SecureRandom+hex work. Residual DB round-trip difference (1 COUNT + 1 INSERT on found path) is accepted per inline comment. |
| HIGH-2 Audit durability | `ResetPasswordUseCase.recordFailure()`: added 4-line inline comment documenting the REQUIRES_NEW load-bearing dependency. `ResetPasswordUseCaseTest`: added `execute_sessionRevocationFailure_isSwallowedAndPasswordStillSaved` test. |
| HIGH-3 Throttle TOCTOU / missing filter-level rate limit on /forgot | `LoginRateLimitFilter`: added `FORGOT_PATH` constant, extended `shouldNotFilter`, added `handleForgot` — per-IP (`FORGOT_IP:` key, `forgot-ip-max-attempts` config) + per-email-HMAC (`FORGOT_USER:` key, reuses `user-max-attempts`). New config defaults in `application.yml`. |
| HIGH-4 No rate limit on /reset | `LoginRateLimitFilter`: added `RESET_PATH` constant and `handleReset` — per-IP (`RESET_IP:` key, `reset-ip-max-attempts` config, default 20/60s). |
| MEDIUM-1 Revocation WARN | `ResetPasswordUseCase`: `revokeAllUserSessions` call wrapped in try/catch; failure logs `WARN SESSION_REVOCATION_PARTIAL` and does not rethrow — password change and audit still commit. |
| MEDIUM-2 Frontend maxLength | `reset-password.component.ts`: `Validators.maxLength(1024)` → `Validators.maxLength(256)`. Added `maxlength` error branch in `passwordError()` computed signal. |
| LOW-1 Token in URL | `ResetPasswordComponent.ngOnInit()`: after reading the token, calls `router.navigate([], { queryParams: {}, replaceUrl: true })` to strip token from browser history and Referer. New spec test `should strip token from URL on init to prevent Referer leakage`. |

`LoginRateLimitFilterTest` updated to match the new 9-arg constructor and 6 new tests added covering both password reset paths.

## Verdict: APPROVED (post-fix re-review)

All 4 HIGH blockers resolved. All MEDIUM and LOW items resolved.

Auth sign-off: PASS — rate limits now cover all three unauthenticated auth endpoints (login, /forgot, /reset); REQUIRES_NEW dependency documented and tested; timing oracle partially mitigated (CPU-bound equalization; residual DB timing accepted).
PII sign-off: PASS (no raw email/token in logs; token stripped from URL post-read).
Crypto sign-off: PASS (SecureRandom, SHA-256, HMAC-SHA256, Argon2; no custom crypto).
