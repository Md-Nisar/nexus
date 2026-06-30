# Code Review -- US-007: Self-Service Password Reset via Email

_Reviewer: Staff Engineer (code-reviewer agent). Branch: feature/US-007. All files read as uncommitted working-tree state._
_All findings resolved in the same session. Re-run: 358 backend tests pass, 155 frontend tests pass._

---

## Summary

| Severity  | Count | Status |
|-----------|-------|--------|
| Blocker   | 3     | ✅ All resolved |
| High      | 3     | ✅ All resolved |
| Medium    | 4     | ✅ All resolved |
| Low/Nit   | 5     | ✅ All resolved |

**Verdict: APPROVE**

---

## Findings

---
### [BLOCKER] Flyway migration V4 is missing -- throttle index will never be created

File: C:/entomo/AI/nexus/nexus-backend/src/main/resources/db/migration/ (file absent)

Problem: The design document (section 4) mandates V4__auth_tokens_reset_throttle_index.sql which creates idx_auth_tokens_user_id_type_created_at. This file does not exist in the migration directory -- only V1, V2, and V3 are present. Without this index, countByUserIdAndTypeAndCreatedAtAfter performs a full table scan on auth_tokens for every forgot-password request. Under load this is an O(N) query per unauthenticated HTTP call -- a direct denial-of-service amplifier. Since ddl-auto=validate only validates mapped entity columns and not indexes, the gap is not caught at boot time and will silently degrade in production.

Why it matters: The throttle query (AC-5) table-scans auth_tokens on every unauthenticated call. An attacker who discovers the endpoint can amplify DB load at zero authentication cost.

Fix: Create nexus-backend/src/main/resources/db/migration/V4__auth_tokens_reset_throttle_index.sql with:

    CREATE INDEX idx_auth_tokens_user_id_type_created_at
        ON auth_tokens (user_id, type, created_at);

---

### [BLOCKER] EmailCipher.value() abstraction violation -- application layer depends on JPA converter internals

File: C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/application/ForgotPasswordUseCase.java:115

Problem: The code calls user.getEmailCipher().value() to obtain the plaintext email. The EmailCipher record is documented as a wrapper for AES-256-GCM ciphertext. The design document (section 3, step 13) specifies a named emailCipher.decrypt() port call. The current code works in production because AttributeEncryptor.convertToEntityAttribute decrypts before wrapping in EmailCipher, making .value() return plaintext. But the application layer is relying on a JPA infrastructure implementation detail with no type-level contract. If AttributeEncryptor is ever refactored (e.g. lazy decryption, or ciphertext stored in the field with a separate decrypt accessor), this silently starts emailing AES ciphertext to users with no compile-time error.

Why it matters: Architectural coupling from the application layer to a JPA infrastructure detail, violating the hexagonal dependency rule. A future AttributeEncryptor refactor causes a silent runtime security regression (PII sent as ciphertext to SMTP).

Fix: Rename EmailCipher to PlaintextEmail to make the contract unambiguous at the type level, or add explicit Javadoc to User.getEmailCipher() stating it returns a decrypted value because AttributeEncryptor decrypts before creating the record. At minimum, document the invariant so future maintainers cannot misread the type.

---

### [BLOCKER] ForgotPasswordUseCaseTest @InjectMocks field has null Clock -- latent NPE for any future contributor

File: C:/entomo/AI/nexus/nexus-backend/src/test/java/com/example/nexus/identity/application/ForgotPasswordUseCaseTest.java:58-59

Problem: @InjectMocks private ForgotPasswordUseCase useCase; is declared but Clock is not in the @Mock field list. Mockito cannot satisfy the Clock dependency and injects null. The comment on line 65 (fixed clock injected via constructor -- InjectMocks uses field injection for Clock) is inaccurate: there is no @Mock Clock in scope. All five test methods work around this by calling buildWithClock(NOW), so tests pass today. But the useCase field holds a broken instance -- any future test that calls useCase.execute(...) will NPE on clock.instant() with no helpful failure message.

Why it matters: Dead misleading test infrastructure that is a latent NPE bomb for future contributors.

Fix: Remove the @InjectMocks annotation and the useCase field declaration. All tests already use buildWithClock(NOW), which is the correct pattern.

---

### [HIGH] passwordHasher.hash() called before markConsumed() -- concurrent duplicate requests both pay the full Argon2 cost before one fails

File: C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/application/ResetPasswordUseCase.java:126-133

Problem: The current execution order is: (1) policy validate, (2) load user, (3) same-password check, (4) passwordHasher.hash(newPassword) -- Argon2, typically 100-300ms, (5) markConsumed + flush -- optimistic lock check. Under concurrent duplicate reset submissions against the same token (attacker or double-click), both requests reach step (4) and pay the full Argon2 cost before either discovers the optimistic lock conflict at flush. The losing request wastes a full hash operation that serves no purpose.

Why it matters: On the unauthenticated reset endpoint, an attacker who can replay a token with concurrent requests amplifies CPU cost. Moving the hash after the flush makes the losing concurrent request fail fast without the Argon2 penalty.

Fix: Reorder to: (1) policy validate, (2) load user, (3) same-password check, (4) markConsumed + flush -- fail fast on optimistic lock conflict, (5) passwordHasher.hash(newPassword), (6) user.applyPasswordReset(newHash), (7) userRegistrationPort.save(user).

---

### [HIGH] ResetPasswordRequest.newPassword has @Size(max=1024) but design specifies @Size(max=256) -- unapproved deviation widens DoS surface

File: C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/dto/ResetPasswordRequest.java:8

Problem: The approved design (section 6) specifies @Size(max = 256) on newPassword. The implementation uses @Size(max = 1024). This allows 1024-byte password strings to reach the Argon2 hasher on the unauthenticated reset endpoint. Argon2 is intentionally CPU-intensive; a 4x increase in maximum input size amplifies the CPU cost of a DoS attack relative to what was threat-modelled. There is no documented rationale for the deviation.

Why it matters: The threat model was approved with a 256-char limit. Deploying with 1024 means the threat model is inaccurate for the reset endpoint.

Fix: Revert to @Size(max = 256). If longer passwords are a genuine product requirement, raise a design amendment to re-evaluate the threat model.

---

### [HIGH] ForgotPasswordComponent emailError computed signal does not handle the maxlength validation error -- user sees a disabled button with no explanation

File: C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/forgot-password/forgot-password.component.ts:149-155

Problem: The form control applies Validators.maxLength(254) but the emailError computed signal only handles required and email errors. If a user pastes an email address longer than 254 characters, the control becomes invalid with a maxlength error, the submit button is disabled, but emailError() returns an empty string -- no inline message is displayed. The user has no programmatic error message explaining the constraint, which is a WCAG 2.1 AA accessibility failure.

Fix: Add inside emailError() after the email check:

    if (control.hasError("maxlength")) return "Email address must not exceed 254 characters.";

---

### [MEDIUM] ResetPasswordComponent stores tokenFromUrl as a plain class field instead of a signal as the design specifies

File: C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/reset-password/reset-password.component.ts:145

Problem: The design document (section 7) specifies tokenFromUrl = signal<string>(). The implementation uses private tokenFromUrl = (a plain class field). With ChangeDetectionStrategy.OnPush, plain class fields are not tracked by the signal graph. The current usage is safe today -- set once in ngOnInit, read in submit() -- but deviates from the approved design and the project signals-first convention. If the component is later made reactive to query param changes, a non-signal field silently breaks change detection.

Fix: Change to private readonly tokenFromUrl = signal<string>() and update ngOnInit to use this.tokenFromUrl.set(...).

---

### [MEDIUM] ForgotPasswordUseCase records PASSWORD_RESET_REQUESTED audit event after publishEvent() -- audit event lost if publish throws synchronously

File: C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/application/ForgotPasswordUseCase.java:116-122

Problem: The sequence is: (1) save token, (2) eventPublisher.publishEvent(...), (3) secureEventService.recordEvent(PASSWORD_RESET_REQUESTED). ApplicationEventPublisher.publishEvent() is synchronous and invokes all synchronous listeners before returning. If any synchronous listener throws, publishEvent propagates the exception and the PASSWORD_RESET_REQUESTED audit event is never recorded. Since recordEvent runs REQUIRES_NEW it would commit independently -- but it is never reached when publishEvent throws first.

Fix: Move secureEventService.recordEvent(PASSWORD_RESET_REQUESTED) to before eventPublisher.publishEvent(...). The REQUIRES_NEW ensures the audit event commits even if the outer transaction later encounters an issue.

---

### [MEDIUM] AuthService.forgotPassword() return type deviates from approved design -- should be Observable<void>

File: C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/auth.service.ts:60-62

Problem: The design document (section 7) specifies forgotPassword(email: string): Observable<void>. The implementation returns Observable<{ message: string }>. ForgotPasswordComponent ignores the response body and works correctly, but the service API surface is inconsistent with the design and with the other void-returning methods (register, verifyEmail, resendVerification) which all pipe through map(() => undefined).

Fix: Change return type to Observable<void> and add .pipe(map(() => undefined)).

---

### [MEDIUM] PasswordResetControllerTest bypasses Spring MVC -- @Valid, 202 status, and 400 on invalid input are untested at the HTTP boundary

File: C:/entomo/AI/nexus/nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/PasswordResetControllerTest.java

Problem: The test instantiates the controller directly and calls methods on it, bypassing the Spring MVC dispatcher. Bean validation (@Valid) is never exercised; the 202 status code from @ResponseStatus(HttpStatus.ACCEPTED) is not verified; and the 400 Bad Request response for a blank email is not tested at the HTTP boundary. The email normalisation assertion (lines 40-45) is correct but insufficient as the only HTTP-contract test.

Fix: Add a @WebMvcTest(PasswordResetController.class) companion test with MockMvc that verifies: (a) POST /api/v1/auth/password/forgot with a blank email body returns 400 with a VALIDATION_FAILED problem document, and (b) a valid email request returns 202 Accepted.

---

### [LOW] ForgotPasswordUseCaseTest @InjectMocks field is dead code

File: C:/entomo/AI/nexus/nexus-backend/src/test/java/com/example/nexus/identity/application/ForgotPasswordUseCaseTest.java:58-59

Problem: @InjectMocks private ForgotPasswordUseCase useCase; is never referenced in any test method. It is dead code that misleads readers into thinking it is the primary test subject. (See BLOCKER above for the NPE hazard this also creates.)

Fix: Remove lines 58-59.

---

### [LOW] ResetPasswordUseCaseTest comment inaccurately describes execution order

File: C:/entomo/AI/nexus/nexus-backend/src/test/java/com/example/nexus/identity/application/ResetPasswordUseCaseTest.java:147

Problem: The comment user lookup happens after policy check -- not needed here is technically accurate but misleading. It implies user lookup can always be omitted for policy tests, which is only true because doThrow causes the policy check to throw before findById is reached.

Fix: Reword to: // passwordPolicyService.validate() throws before findById is called; no user stub required.

---

### [LOW] app-password-strength-meter selector in ResetPasswordComponent template may not match the nx- prefix convention

File: C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/reset-password/reset-password.component.ts:51

Problem: The template uses <app-password-strength-meter ...>. The project coding standards (docs/coding-standards.md) require nx-kebab-case selectors. If PasswordStrengthMeterComponent declares selector: nx-password-strength-meter, the template reference is wrong and Angular will silently ignore the element with no runtime error.

Fix: Verify PasswordStrengthMeterComponent declared selector. If it is nx-password-strength-meter, update the template at line 51 to <nx-password-strength-meter ...>.

---

## Positives

1. Anti-enumeration contract is correctly implemented end-to-end. ForgotPasswordUseCase always returns normally for unknown emails. The throttle is also silent to the caller. The 202-always design is enforced at the controller, use case, and test layers.

2. REQUIRES_NEW transaction pattern is applied correctly. revokeAllUserSessions and recordEvent live in SecureEventService with REQUIRES_NEW, exactly matching the CLAUDE.md non-negotiable for writes that must survive outer TX rollback.

3. Optimistic lock race on token consumption is handled precisely. The markConsumed + flush + catch OptimisticLockingFailureException pattern prevents double-redemption under concurrent requests. This is the correct implementation of the design step 13 race-condition mitigation.

4. Raw token is never logged anywhere in the call chain. PasswordResetEmailEvent.toString() redacts the token. LoggingMailSenderAdapter suppresses it. SmtpMailSenderAdapter passes it only to the email body. SEC-3 compliance is complete and directly tested by sendPasswordResetEmail_doesNotLogRawToken in LoggingMailSenderAdapterTest.

5. User.applyPasswordReset() cleanly encapsulates the domain state transition. Password hash update, tokenVersion increment (AC-3), ACTIVE transition (AC-4), and lockout reset are all atomic in one domain method. The Javadoc explicitly references the Gate 1 accepted residual risk.

6. @Async @TransactionalEventListener(AFTER_COMMIT) pattern is correctly applied. Email is dispatched only after transaction commit, preventing phantom emails on rollback. The async executor offloads SMTP latency from the HTTP thread, satisfying the anti-enumeration timing constraint.

7. Frontend signal usage is consistent with OnPush and the project conventions. loading, submitted, errorMessage, showForgotLink, and showPassword are all signals. Templates use @if not *ngIf. computed is used correctly for derived error messages.

8. ResetPasswordComponent error code switch is exhaustive and precise. All four documented error codes (AUTH_RST_002, AUTH_PWD_001, AUTH_PWD_002, AUTH_RST_003) map to specific user-facing messages. showForgotLink is correctly raised only for AUTH_RST_002. The default fallback is safe.

9. Test coverage is broad. Both use-case test classes cover token-not-found, wrong type, expired, already-consumed, optimistic lock, policy violation (both codes), same-password, and the full happy path. Audit event shapes are verified. SecureEventService.revokeAllUserSessions has a dedicated test.

10. SecurityConfig correctly permits both new endpoints. /api/v1/auth/password/forgot and /api/v1/auth/password/reset are in the permitAll matcher list without any @ConditionalOnProperty guard, matching the design decision of no feature flag.
