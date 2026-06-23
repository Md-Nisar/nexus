# Code Review -- US-003: JWT Login / Refresh / Logout

**Reviewer:** Staff Engineer (Claude Code claude-sonnet-4-6)
**Date:** 2026-06-23
**Branch:** feature/US-003
**Verdict:** CHANGES REQUESTED

---

## Executive Summary

The implementation is architecturally sound. The security invariants from the design are largely upheld: anti-enumeration dummy hash runs unconditionally, the status gate is a strict ACTIVE allow-list, theft detection revokes the family before throwing, client IP is read exclusively from getRemoteAddr(), the algorithm assertion after JJWT parse guards against confusion attacks, both AccessTokenResult and LoginResult have redacting toString() overrides, and the JWKS endpoint never emits private key fields. The test suite is thorough.

Two BLOCKER findings must be resolved before merge: (1) the RSA modulus encoding in the JWKS endpoint includes a sign-magnitude leading-zero byte that will cause token-verification failures for RFC-compliant clients such as WebCrypto; (2) AuthStore.isAuthenticated does not check token expiry, so an expired session is treated as authenticated. Two HIGH findings must also be fixed: login() and refresh() in AuthService are missing withCredentials: true, breaking the httpOnly cookie flow in cross-origin deployments; and the auth interceptor has no shared in-flight refresh observable, so concurrent 401 responses trigger multiple simultaneous refresh requests that backend theft detection will revoke as token reuse.

---

## Findings Table

| ID  | Severity | File:Line                              | Summary |
|-----|----------|----------------------------------------|---------|
| C1  | BLOCKER  | JwkSetAdapter.java:30                  | RSA modulus BigInteger.toByteArray() prepends a sign-magnitude leading zero -- JWKS n is malformed for ~50% of RSA-2048 keys |
| C2  | BLOCKER  | auth.store.ts:11                       | isAuthenticated never checks expiry -- expired access tokens appear authenticated |
| C3  | HIGH     | auth.service.ts:48,65                  | login() and refresh() missing withCredentials:true -- httpOnly cookie never stored or sent cross-origin |
| C4  | HIGH     | auth.interceptor.ts:22                 | No shared in-flight refresh observable -- concurrent 401s fire multiple POST /refresh calls, triggering theft-detection family revocation |
| C5  | MEDIUM   | JpaRefreshTokenRepository.java:23,29   | @Transactional on infrastructure repository violates the coding-standard rule that it belongs on application services only |
| C6  | MEDIUM   | JwtRs256Service.java:79                | clockSkewSeconds(30) extends effective token lifetime to 930 s, beyond the 900 s design contract |
| C7  | MEDIUM   | login-form.component.ts:104            | loading signal not reset on the happy path -- button stays in loading/disabled state if navigation fails |
| C8  | MEDIUM   | InMemoryRateLimitStore.java:92         | retryAfterSeconds always returns full window duration (300 s), not actual remaining window |
| C9  | LOW      | LoginController.java:111               | MDC.get uses magic string literal instead of CorrelationIdFilter.MDC_KEY constant |
| C10 | LOW      | auth.interceptor.ts:21                 | isAuthEndpoint uses substring includes() -- could match unintended future URL paths |

---

## Finding Details

### C1 — BLOCKER: RSA modulus encoding produces invalid JWKS `n` parameter
**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwkSetAdapter.java:30`

`BigInteger.toByteArray()` returns a two's-complement signed representation. When the most-significant bit of the modulus is 1 (true for ~50% of RSA-2048 keys), it prepends a `0x00` sign byte to keep the value positive, producing a 257-byte array instead of 256. RFC 7518 §6.3.1.1 requires `n` to be the unsigned big-endian byte representation with no leading zero padding. Any RFC-compliant consumer (WebCrypto, Go stdlib, Bouncy Castle) will reject a key whose modulus length is 257 bytes.

**Fix:** Strip the leading zero before encoding.
```java
byte[] nBytes = publicKey.getModulus().toByteArray();
if (nBytes.length > 0 && nBytes[0] == 0) {
    nBytes = Arrays.copyOfRange(nBytes, 1, nBytes.length);
}
String n = encoder.encodeToString(nBytes);
```

---

### C2 — BLOCKER: `isAuthenticated` does not check token expiry
**File:** `nexus-frontend/src/app/core/auth/auth.store.ts:11`

```typescript
readonly isAuthenticated = computed(() => this._session() !== null);
```

`AuthSession` carries `expiresIn` (seconds) but no `expiresAt` timestamp is stored when the session is set. After the 900-second access-token lifetime, `isAuthenticated` still returns `true` because the signal holds a non-null session object. `AuthGuard` uses this signal, so expired sessions pass the guard and reach protected routes. The interceptor will catch the resulting 401 and attempt a refresh, but the guard itself provides no expiry-aware protection.

**Fix:** Store `expiresAt = Date.now() + session.expiresIn * 1000` in `setSession` and check it in `isAuthenticated`:
```typescript
setSession(session: AuthSession): void {
  this._session.set({ ...session, expiresAt: Date.now() + session.expiresIn * 1000 });
}
readonly isAuthenticated = computed(() => {
  const s = this._session();
  return s !== null && Date.now() < s.expiresAt;
});
```

---

### C3 — HIGH: `login()`, `refresh()`, and `logout()` missing `withCredentials: true`
**File:** `nexus-frontend/src/app/features/auth/auth.service.ts:48,60,65`

The refresh-token cookie is `SameSite=Strict; HttpOnly`. Browser same-site/CORS policy requires `withCredentials: true` on XHR/fetch for the browser to (a) send existing cookies and (b) apply `Set-Cookie` headers from the response. Without this flag on cross-origin requests (frontend `:2000`, backend `:1000`), the cookie is silently dropped. The entire stateless-refresh flow is broken in all non-localhost deployments.

**Fix:** Add `{ withCredentials: true }` to `login()`, `refresh()`, and `logout()`:
```typescript
this.http.post<LoginApiResponse>(`${this.base}/login`, body, { withCredentials: true })
this.http.post<LoginApiResponse>(`${this.base}/refresh`, null, { withCredentials: true })
this.http.post<void>(`${this.base}/logout`, null, { withCredentials: true })
```

---

### C4 — HIGH: No shared in-flight refresh guard — concurrent 401s trigger theft detection
**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts:22`

When a page makes N parallel API calls and the access token has expired, all N calls return 401 simultaneously. Each independently enters the `catchError` branch and calls `authService.refresh()`. The first refresh succeeds and rotates the token. The second call presents the now-revoked token to `POST /refresh`, which triggers the theft-detection family revocation in `RefreshTokenUseCase`, revoking all tokens for the user and forcing a logout.

**Fix:** Deduplicate with a shared observable:
```typescript
let refreshInFlight: Observable<AuthSession> | null = null;

const doRefresh = (): Observable<AuthSession> => {
  if (!refreshInFlight) {
    refreshInFlight = authService.refresh().pipe(
      finalize(() => { refreshInFlight = null; }),
      shareReplay(1),
    );
  }
  return refreshInFlight;
};
// replace authService.refresh() with doRefresh()
```
`refreshInFlight` must live outside the interceptor function (module-level or in an `@Injectable` wrapper).

---

### C5 — MEDIUM: `@Transactional` on Spring Data JPA repository interface
**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaRefreshTokenRepository.java:23,29`

CLAUDE.md states `@Transactional` belongs on application services only. All callers (`SecureEventService`, `JpaRefreshTokenAdapter`) propagate an active `@Transactional(REQUIRED)` context, making the explicit `@Transactional` on the repository redundant and a convention violation.

**Fix:** Remove `@Transactional` from both `@Modifying` methods. The application-service transaction is always active at call time.

---

### C6 — MEDIUM: `clockSkewSeconds(30)` extends effective token lifetime to 930 s
**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:79`

JJWT's `clockSkewSeconds(30)` causes the parser to accept tokens expired up to 30 seconds ago. The design contract (`nexus.jwt.access-token-ttl-seconds: 900`) does not account for this extension. In a token-compromise scenario, the attacker has 30 extra seconds beyond what audit logs show.

**Fix:** Remove clock skew, or cap at ≤5 s and document with a named constant `AUTH_CLOCK_SKEW_SECONDS` in `AuthConstants`.

---

### C7 — MEDIUM: `loading` signal not reset on navigation success
**File:** `nexus-frontend/src/app/features/auth/login-form/login-form.component.ts:104`

`loading` is set to `true` before the API call and reset in the `error` handler, but the `next` handler only calls `this.router.navigate(['/dashboard'])` without resetting `loading`. If navigation fails (guard rejects, routing error), the component stays mounted with the submit button permanently disabled.

**Fix:** Reset before navigating:
```typescript
next: () => {
  this.loading.set(false);
  this.router.navigate(['/dashboard']);
},
```

---

### C8 — MEDIUM: `Retry-After` always reports full window duration, not actual remaining time
**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/InMemoryRateLimitStore.java` (via `RateLimitResult.reject(windowSeconds)`)

`tryConsume` calls `RateLimitResult.reject(windowSeconds)` with the full configured window. In a sliding window, the actual remaining wait is `oldestTimestamp + windowSeconds - now`. A client rate-limited after 299 s of activity will be told to wait 300 s when it only needs 1 s.

**Fix:** Calculate the actual remaining time inside `tryConsume` using `deque.peekFirst()` and pass it to `RateLimitResult.reject(remainingSeconds)`.

---

### C9 — LOW: Magic string `"traceId"` in `LoginController`
**File:** `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/LoginController.java:111`

```java
MDC.get("traceId")
```
`SecurityConfig`'s entry-point handlers correctly use `MDC.get(CorrelationIdFilter.MDC_KEY)`. A rename of the MDC key would silently break `LoginController` without a compile error.

**Fix:** `MDC.get(CorrelationIdFilter.MDC_KEY)`

---

### C10 — LOW: `isAuthEndpoint` uses `includes()` — over-broad URL match
**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts:21`

```typescript
req.url.includes('/auth/login') || req.url.includes('/auth/refresh')
```
Matches any URL containing the substring. A future path like `/api/v1/admin/auth/login-audit` would be incorrectly excluded from the 401-refresh loop.

**Fix:** Check against the pathname explicitly:
```typescript
const path = new URL(req.url, window.location.origin).pathname;
const isAuthEndpoint = ['/api/v1/auth/login', '/api/v1/auth/refresh'].includes(path);
```

---

## What Was Done Well

- **Security invariant ordering**: Anti-enumeration (Argon2 runs before the `found` check), status gate (strict `ACTIVE` allowlist), and theft detection (family revocation fires before `AuthenticationException` is thrown) are all correctly ordered per the threat model.
- **No private-key leakage**: `JwkSetAdapter` only emits `kty`, `use`, `alg`, `kid`, `n`, `e`.
- **Algorithm confusion defence**: `JwtRs256Service.verify()` asserts `alg == RS256` after parsing.
- **Client-IP hygiene**: All IP reads use `getRemoteAddr()` exclusively — no `X-Forwarded-For` usage anywhere.
- **Token redaction**: Both `AccessTokenResult` and `LoginResult` override `toString()` to emit `[REDACTED]`.
- **Cookie hardening**: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/v1/auth`, `Max-Age` derived from `AuthConstants`.
- **Body-size guard**: `LoginRateLimitFilter` limits body reads to `MAX_LOGIN_BODY_BYTES` (8 192), returning 413 on excess.
- **Architecture**: Hexagonal layering respected; `@Transactional` on application services; constructor injection throughout.
- **Test coverage**: 269 unit tests + 82 IT tests including rate-limit, rotation, audit, JWT security property, and `SecurityConfig` integration tests.
