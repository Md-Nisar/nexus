# Code Review — US-002: Self-Service Registration with Email Verification

Reviewed against: `CLAUDE.md`, `ARCHITECTURE.md`, `SECURITY.md`, `docs/coding-standards.md`, `docs/features/US-002/03-design.md`, `docs/features/US-002/03b-threat-model.md`.

---

## BLOCKER

**[BLOCKER] VerificationEmailEvent record exposes rawToken via auto-generated toString()**
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/event/VerificationEmailEvent.java`

Problem: `VerificationEmailEvent` is a Java `record` with no custom `toString()`. Java auto-generates `toString()` returning all component values, including `rawToken`. If Spring's application event infrastructure, AOP, or any debug/tracing framework logs this event object, the raw verification token is exposed in full — a direct violation of SEC-3 (T-I4: "Never log rawToken").

Fix: Add an explicit `toString()` to the record that redacts rawToken:
```java
public record VerificationEmailEvent(String toEmail, String rawToken, UUID userId) {
    @Override
    public String toString() {
        return "VerificationEmailEvent[toEmail=" + LogMaskingUtil.maskEmail(toEmail)
            + ", rawToken=<redacted>, userId=" + userId + "]";
    }
}
```

---

## HIGH

**[HIGH] RESEND_THROTTLED audit event is never recorded — violates threat model T-R4**
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/ResendVerificationUseCase.java`

Problem: `enforceRateLimit()` throws `RateLimitException` immediately without calling `authEventPort.record()`. The threat model explicitly names `RESEND_THROTTLED` as a required audit event. The `auth_events` table will have no record of throttle abuse, making it impossible to detect resend-flooding attacks in retrospect.

Fix: Record the audit event before throwing `RateLimitException` in both branches of `enforceRateLimit()`.

---

**[HIGH] Audit event type and outcome strings deviate from the approved design**
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/RegisterUserUseCase.java`

Problem:
- `"REGISTRATION_DUPLICATE"` with outcome `"SUCCESS"` → should be `"REGISTRATION_DUPLICATE_EMAIL"` with outcome `"BLOCKED"`
- `"RESEND_SUCCESS"` in `ResendVerificationUseCase` → should be `"RESEND_REQUESTED"`

These string values are stable identifiers for audit queries, dashboards, and alerting rules. They must match the design spec (§11) exactly.

---

**[HIGH] Audit records carry no IP address or traceId metadata — violates T-R1, T-R2, T-R3**
File: `RegisterUserUseCase.java`, `VerifyEmailUseCase.java`, `ResendVerificationUseCase.java`

Problem: `AuthEvent` has `ipAddress` and `metadata` fields. The design (§11) requires `{ "traceId": "...", "ip": "...", "userAgent": "..." }` in `metadata`. None of the three use-cases populate either field. Without IP and traceId, the `auth_events` table cannot be used to investigate suspected account-takeover or replay incidents.

Fix: Pass a `RequestContext` value object from the controller boundary into the use-cases and populate `ipAddress` and metadata on each audit event.

---

**[HIGH] `application` layer imports `common.web` — layering violation**
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/RegisterUserUseCase.java`

Problem: `RegisterUserUseCase` imports `com.example.nexus.common.web.LogMaskingUtil`. Application-layer services must not import from any web or interface layer. ArchUnit's current rules don't catch `common.web` imports from `application`, so this slips through.

Fix: Move `LogMaskingUtil` from `common.web` to `common.domain` or `common.util` — it has no web dependencies. Update ArchUnit to also block `..common.web..` imports from `..application..`.

---

## MEDIUM

**[MEDIUM] `Instant.now()` called directly in use-cases — not testable**
File: `RegisterUserUseCase.java:88`, `VerifyEmailUseCase.java:52`, `ResendVerificationUseCase.java:78,89`

Problem: `docs/coding-standards.md` (Forbidden Patterns) prohibits `System.currentTimeMillis()` for this reason; `Instant.now()` has the same testability problem. Time-boundary tests (e.g. expiry at exactly `expiresAt`) are fragile without a `Clock` abstraction.

Fix: Inject `Clock clock` (Spring bean) into the three use-cases and call `Instant.now(clock)`. Tests pass `Clock.fixed(...)`.

---

**[MEDIUM] Duplicate-path audit event loses the existing user's ID**
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/RegisterUserUseCase.java`

Problem: On duplicate email detection, `authEventPort.record(...)` is called without `.withUserId(existingUserId)`. The resulting audit event has a null `userId`.

Fix: Capture the found user's ID from the port lookup result and include it with `.withUserId(existingUserId)`.

---

**[MEDIUM] `RegistrationControllerIT` timing test is fragile on loaded CI runners**
File: `nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/RegistrationControllerIT.java`

Problem: The anti-enumeration timing test runs 50 back-to-back HTTP requests and compares mean latencies. A single GC pause of 50ms in one path would cause a flaky failure. Warmup of 3 iterations is too low for JIT stabilization on Argon2.

Fix: Tag with `@Tag("timing")` so it can be excluded from standard CI and run in a dedicated perf gate. Increase warmup iterations.

---

**[MEDIUM] Test helper `createPendingUser()` sets `consentAcceptedAt = null` — illegal domain state**
File: `RegistrationControllerIT.java`, `VerificationTokenIT.java`, `ResendVerificationIT.java`

Problem: Users created in tests with `consentAcceptedAt = null` couldn't legally have been registered via the actual flow. Tests should model valid domain states.

Fix: Pass `Instant.now()` as `consentAcceptedAt` in test helper methods.

---

**[MEDIUM] E2E test comment incorrectly describes the scenario**
File: `nexus-frontend/e2e/auth/registration.spec.ts:99`

Problem: Comment says "63 f-chars — invalid format" but the code uses `'f'.repeat(64)` which is 64 valid hex characters. The 410 comes from a DB miss, not format validation.

Fix:
```typescript
// 64 f-chars — valid hex format but no matching token in DB → backend returns 410 AUTH_VRF_002
```

---

## LOW / NIT

**[LOW] `PasswordPolicyService.validate()` deviates from design spec `assertValid()`**
The approved design (§5.6) names the method `assertValid(rawPassword)`. Minor naming discrepancy; document or align before generating Swagger client docs.

---

**[LOW] `RegistrationControllerTest` has a stale cross-reference to "T-021"**
Comment references "T-021" — no such class exists. The IT tests are in `RegistrationControllerIT`. Update the comment.

---

**[LOW] `@EnableAsync` on `PasswordEncoderConfig` is semantically misleading**
`@EnableAsync` is a platform-wide concern. A dedicated `config/AsyncConfig.java` would match the platform's `config/` package convention and be less surprising.

---

**[LOW] CORS config doesn't expose `Retry-After` header to browser clients**
File: `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`

The `GlobalExceptionHandler` sets `Retry-After` on 429 responses, but CORS doesn't expose it. Browser `fetch`/XHR cannot read unexposed headers.

Fix:
```java
cfg.setExposedHeaders(List.of("Retry-After", "X-Correlation-Id"));
```

---

**[LOW] Bouncycastle `1.78` — verify no CVEs by release time**
Run `mvn verify -Psecurity` to confirm the OWASP dependency-check is clean. Update to `1.79+` if patches are available.

---

## Praise

- **`VerifyEmailUseCase` concurrent-consumption handling is excellent.** The `authTokenPort.flush()` call before commit makes the `OptimisticLockingFailureException` deterministic and catchable. The `VerificationTokenIT.verify_concurrentConsumption_exactlyOneSucceeds` test validates this correctly with two real threads against MySQL.
- **Anti-enumeration timing strategy is cleanly implemented.** Hashing before the duplicate check (SEC-5) with explanatory comment is exactly right.
- **`TestcontainersConfiguration.stubMailSenderPort()` as `@Primary`** is an elegant solution to the Spring Boot 4 property-precedence / conditional-bean ordering problem.
- **`LogMaskingUtil` is simple, correct, and well-tested** — all edge cases (null, no `@`, zero-length local part) are covered.
- **`PasswordPolicyConfig.load()` is package-private**, enabling direct testing without a Spring context.

---

## Summary

| Severity  | Count |
|-----------|-------|
| BLOCKER   | 1     |
| HIGH      | 4     |
| MEDIUM    | 5     |
| LOW / NIT | 5     |
| **Total** | **15** |

**Verdict: CHANGES REQUESTED**

The implementation is structurally sound with strong understanding of the hexagonal architecture, anti-enumeration requirements, and `@TransactionalEventListener(AFTER_COMMIT)` dispatch. The following must be fixed before merge:

1. **BLOCKER:** `VerificationEmailEvent` auto-`toString()` leaks `rawToken` — add a custom redacting `toString()`.
2. **HIGH:** `RESEND_THROTTLED` audit event never recorded when rate-limit is hit.
3. **HIGH:** Audit event type/outcome strings don't match the approved design spec.
4. **HIGH:** Audit records missing `ipAddress` and `traceId` metadata (T-R1/T-R2/T-R3).
5. **HIGH:** `application` layer imports `common.web` — architecture violation.

All remaining findings are medium/low quality improvements that may be addressed in a follow-up.
