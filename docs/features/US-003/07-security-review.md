# US-003 Security Code Audit -- Login / Refresh / Logout (JWT)

Phase 7 hostile-mindset code audit. Reviewer: Application Security Engineer.
Date: 2026-06-23. Branch: feature/US-003. Scope: backend identity module + Angular auth client.

Reviewer attestation: I reviewed the AUTHENTICATION code (JWT issuance/verification, refresh
rotation/theft detection, login credential check, session/token handling), the CRYPTOGRAPHIC
code (RS256 sign/verify, alg-confusion defence, Argon2id params, SHA-256 token hashing, HMAC
blind index, RSA key loading, SecureRandom usage), and the PII-handling code (claims contract,
log masking, audit-event fields, cookie handling). Findings are inline and summarised below.

Dependency scans:
- mvnw dependency:tree -Dincludes=io.jsonwebtoken => jjwt 0.12.6 (current; 0.11.x
  parseClaimsJws alg-confusion issues do not apply to 0.12 typed verifyWith/parser). No high CVE. (A06)
- npm audit --omit=dev --audit-level=high => found 0 vulnerabilities. (A06)

---

## Findings

### BLOCKER / CRITICAL
None.

### HIGH
None.

### MEDIUM

[MEDIUM] LoginController.java:100 / SecurityConfig.java:73 -- token-less /auth/logout does not revoke server-side tokens
- File: nexus-backend/.../interfaces/rest/LoginController.java:100-109; .../config/SecurityConfig.java:73
- Issue: /api/v1/auth/logout is permitAll; the handler derives userId from SecurityContext
  (LoginController:102-105). With a valid Bearer token, authenticated logout revokes all tokens.
  A client whose access token is lost/expired (the log-me-out-everywhere case) sends logout with
  no usable Bearer => userId null => LogoutUseCase.execute(null, ip) only clears the cookie and
  records LOGOUT with NO token revocation (LogoutUseCase:47).
- Risk: The advertised T-7.1 mitigation (logout revokes ALL refresh tokens) degrades to a
  cookie-clear exactly when global revocation matters most; server-side refresh tokens survive.
- Fix: Require auth on /auth/logout (remove from permitAll) OR on token-less logout hash the
  presented refresh cookie, resolve userId, and revoke that family. Add the T-7.1 revocation IT.

[MEDIUM] RefreshTokenUseCase.java:95 -- malformed refresh cookie yields 500 + ERROR stack trace, not 401
- File: nexus-backend/.../application/service/RefreshTokenUseCase.java:95
- Issue: execute() passes the attacker-controlled cookie into tokenHasher.hash(value);
  TokenHasher.hash (TokenHasher.java:29) calls HexFormat.parseHex, which throws
  IllegalArgumentException for any non-even-length / non-hex value. No guard, so it escapes
  AUTH_004 handling and hits GlobalExceptionHandler.handleUnexpected => 500 + ERROR stack trace.
- Risk: (1) Error-oracle: malformed=>500 vs unknown-but-valid=>401, a token-format distinguisher.
  (2) Unauthenticated log-spam (ERROR stack trace per junk cookie). /refresh 30/window blunts only.
- Fix: Catch IllegalArgumentException around the hash and throw AuthenticationException(AUTH_004)
  on the same path as token-not-found; preserve the uniform-401 contract; do not log at ERROR.

[MEDIUM] InMemoryRateLimitStore.java:103 -- eviction sweep not atomic vs tryConsume (benign, single-node)
- Issue: evictExpiredEntries iterates forEach + computeIfPresent per key; per-key compute is
  atomic so no counter is lost, but a key at its limit could lose its oldest timestamp a tick
  early under clock-edge races. Net: at most a 1-tick early reset, never a counter increase.
- Risk: Marginal boundary weakening, bounded by the accepted single-node limitation (T-6.1).
- Fix: Acceptable single-node; document. If tightened, evict only when peekLast older than cutoff.

### LOW / INFO

[LOW] SecurityConfig.java:131-143 -- CORS exposes Set-Cookie with allowCredentials=true
- Issue: allowCredentials(true) + exposedHeaders includes Set-Cookie. Safe ONLY because
  setAllowedOrigins is a single fixed origin (nexus.frontend.base-url), never a wildcard. No
  test pins that the origin cannot become permissive. Exposing Set-Cookie cross-origin is
  needless (HttpOnly defeats JS reads). (A05)
- Fix: Drop Set-Cookie from exposedHeaders; add a prod test that the resolved origin is a
  concrete https origin, not a wildcard. SameSite=Strict stays the load-bearing CSRF control (T-1.5).

[LOW] LoginRateLimitFilter.java:146 -- extractEmailHmac swallows all exceptions; per-username key may be skipped
- Issue: catch(Exception) means a body the filter mapper cannot parse skips the per-username key;
  only per-IP is consumed. Filter mapper and controller mapper differ in leniency.
- Risk: Defence-in-depth gap on the per-username cap; per-IP cap still applies. Slightly eases the
  already-accepted distributed-IP single-account attack (T-1.2).
- Fix: Parse email with controller-equivalent strictness, or consume a conservative per-IP key on
  unparseable bodies. Acceptable residual given T-1.2; note it.

[LOW] JwtAuthenticationFilter.java:69-70 -- claims into MDC (safe today; forward-looking)
- claims.sub()/tenantId() are signature-verified UUIDs (not PII, cannot carry CRLF without breaking
  the signature). No issue now; if a free-text claim is ever logged to MDC, log-injection (T-7.3)
  reopens. Fix: validate any future logged claim against the safe charset before MDC.

[LOW] AuthConstants.java:13 -- clock skew = 0 (ops dependency on NTP)
- AUTH_CLOCK_SKEW_SECONDS=0, stricter than the suggested <=30s. A verifier lagging the issuer by
  >=1s rejects a just-issued token. Operational risk (false 401 on drift), not a security weakness,
  acceptable only if NTP is enforced as the comment claims. Fix: keep 0 + enforce NTP, or set 5-10s.

[LOW] auth.interceptor.ts:44-47 -- reviewed, correct (no change)
- 401 retry clones the original request and overwrites Authorization with the refreshed token; the
  shared in-flight shareReplay(1) refresh prevents duplicate /refresh calls that would trip
  theft-detection family revocation. Correct.

[INFO] Refresh-token TTL is 14 days, not the 7 days stated in SECURITY.md
- AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS=14. Implementation, threat model (T-1.4
  Max-Age=1209600), and 03-design all use 14 days (threat model accepted). Documentation drift
  only; no security impact. Reconcile SECURITY.md or the constant; flag to architect.

---

## Positive controls verified (auth / crypto / PII -- explicitly reviewed)

- Anti-enumeration (T-2.2): Argon2 runs on a precomputed dummyHash when not-found BEFORE any branch
  (LoginUseCase:124-131); dummyHash built in @PostConstruct via the same PasswordHasherPort (line
  103) => runtime params => timing parity; unknown-email and wrong-password share AUTH_001. CONFIRMED.
- Status allowlist (T-2.5): PENDING=>403 only after password match; any non-ACTIVE=>401; ACTIVE is
  the only issuance path (LoginUseCase:142-159). CONFIRMED.
- Alg-confusion/none/foreign (T-3.1/3.2/3.3): verifyWith(publicKey) + explicit RS256 header check
  (JwtRs256Service:78-88); no jku/x5u/remote fetch; single local key. Tests assert AUTH_003 for
  alg=none, HS256-with-public-key, foreign RSA key, tampered tenant_id/roles. CONFIRMED.
- Theft detection ordering (T-4.1): revoked token => revokeFamily (REQUIRES_NEW, commits
  independently) BEFORE throw (RefreshTokenUseCase:106-112). CONFIRMED.
- Optimistic lock (T-4.2): @Version on RefreshToken:42-44; OptimisticLockingFailure=>AUTH_004
  (RefreshTokenUseCase:123-129). CONFIRMED.
- Token redaction (T-5.1/5.2): AccessTokenResult.toString=>jti+expiry only; LoginResult.toString
  omits rawRefreshToken. CONFIRMED.
- JWKS public-only (T-5.3): JwkSetAdapter emits exactly kty,use,alg,kid,n,e; no d/p/q/dp/dq/qi;
  test asserts d absent. CONFIRMED.
- Rate limit before Argon2 (T-6.1): LoginRateLimitFilter at servlet layer, ordered before
  JwtAuthenticationFilter and controller (SecurityConfig:65-66); body capped 8 KiB. CONFIRMED.
- Bounded memory (T-6.2): empty deques evicted in atomic compute (InMemoryRateLimitStore:94) +
  periodic sweeper. CONFIRMED.
- Logout revokes all tokens (T-7.1): revokeByUserId (JPQL WHERE revokedAt IS NULL) + LOGOUT audit,
  single @Transactional. CONFIRMED for authenticated path; see MEDIUM for token-less degradation.
- Crypto: Argon2id 19456 KiB/iter 2/par 1 (application.yml:79-83, matches SECURITY.md); SecureRandom
  nextBytes(32) tokens (never Math.random); SHA-256 stored hashes; HMAC-SHA256 blind index
  (NFC+lowercase); RSA rejects <2048-bit, prod fail-fast on missing key (RsaKeyConfig:67-69,107-110);
  AES-256-GCM via Encryptors.delux; no PEM/secret in source; dev placeholders blocked outside dev/smoke. REVIEWED.
- PII: no email/name in JWT claims (JwtClaims) or MeResponse (UUIDs/roles/flags only); audit logs
  UUID userId + getRemoteAddr() IP; RequestContext.toMetadataJson JSON-escapes; only UUID debug logs.
  No raw email/password/token reaches a logger. REVIEWED.
- Actuator (T-5.2): IdentityActuatorSanitizer masks nexus.jwt.private* and nexus.identity.* secrets;
  RsaKeyConfig.toString emits only kid; env/configprops not in web exposure list. CONFIRMED.

---

## 1. Threat-model coverage

| Threat | Invariant | Status | Evidence |
|--------|-----------|--------|----------|
| T-1.3 | Client IP getRemoteAddr() only, never XFF | CONFIRMED | LoginRateLimitFilter:84; LoginController:92,106,112 |
| T-2.1 | DTO size limits before Argon2; raw token never in body | CONFIRMED | LoginRequest @Size(254/256); 8 KiB cap; LoginResponse has no token |
| T-2.2 | Argon2 dummy hash before branch on found | CONFIRMED | LoginUseCase:124-131; runtime params |
| T-2.5 | ACTIVE allowlist; non-ACTIVE never issues | CONFIRMED | LoginUseCase:142-159 |
| T-3.1 | Cookie HttpOnly;Secure;SameSite=Strict;Path=/api/v1/auth;Max-Age=1209600 | CONFIRMED | LoginController:115-119 |
| T-3.2 | Post-parse alg==RS256 assertion | CONFIRMED | JwtRs256Service:84-88 + tests |
| T-4.1 | Family revocation before throw | CONFIRMED | RefreshTokenUseCase:106-112 |
| T-4.2 | @Version optimistic lock | CONFIRMED | RefreshToken:42-44; catch:123-129 |
| T-5.1 | AccessTokenResult.toString redacts token | CONFIRMED | AccessTokenResult:10-13 |
| T-5.2 | LoginResult.rawRefreshToken absent from toString | CONFIRMED | LoginResult:11-14 |
| T-5.3 | JWKS no d/p/q/dp/dq/qi | CONFIRMED | JwkSetAdapter:44-52; test asserts d absent |
| T-6.1 | Rate limit before password verification | CONFIRMED | SecurityConfig filter order |
| T-6.2 | Store bounded (evicts empty deques) | CONFIRMED | InMemoryRateLimitStore:94 + sweeper |
| T-7.1 | Logout revokes ALL user refresh tokens | PARTIAL | All revoked when userId known; degrades to cookie-clear for token-less logout (MEDIUM) |

## 2. OWASP Top 10 coverage

| ID | Category | Applies | Status | Notes |
|----|----------|---------|--------|-------|
| A01 | Broken Access Control | Yes | PASS | Default-deny; /users/me reads signed claims only (no IDOR); tenant_id from token; 1 MEDIUM on logout authz. |
| A02 | Cryptographic Failures | Yes | PASS | RS256, RSA>=2048, Argon2id, SecureRandom, SHA-256, AES-256-GCM, no secret in source, prod fail-fast. |
| A03 | Injection | Yes | PASS | JPQL named params; no string-concat SQL; JSON metadata escaped; no raw-input log concatenation. |
| A04 | Insecure Design | Yes | PASS | Rate limit, one-time rotation, family theft detection, body cap. Residuals T-1.2/T-3.9 documented. |
| A05 | Security Misconfiguration | Yes | PASS w/ LOW | HSTS; CSRF off (stateless+Bearer, SameSite=Strict); springdoc off in prod; env not exposed + sanitizer. LOW: CORS Set-Cookie/origin. |
| A06 | Vulnerable Components | Yes | PASS | jjwt 0.12.6 (no high CVE); npm audit 0 vulns. |
| A07 | Auth and Session Failures | Yes | PASS | Theft=>family revoke; one-time rotation; access token in memory only; expiry both sides; stateless. MEDIUM on token-less logout. |
| A08 | Software and Data Integrity | Yes | PASS | alg-confusion/none/foreign/tamper tests assert 401; deps pinned. |
| A09 | Logging and Monitoring | Yes | PASS | Append-only auth_events; LOGIN/REFRESH/FAMILY_REVOKED/LOGOUT recorded; no PII/secret in logs. MEDIUM: malformed-cookie 500 log-spam. |
| A10 | SSRF | Minimal | PASS | No outbound URL from user input; verify uses local key only (no jku/x5u). |

---

## Verdict

APPROVED with required follow-ups (no blocker).

All CRITICAL/HIGH threat-model invariants are CONFIRMED in code, and the highest-value items
(alg-confusion, anti-enumeration, theft detection, JWKS privacy, key handling) are backed by real
tests. Cryptography, authentication, and PII handling were explicitly reviewed and are sound. No
exploitable-now (Blocker) or insider/effort (High) issue was found.

Three MEDIUM items must be addressed (one degrades an advertised mitigation):
1. Token-less /auth/logout does not revoke server-side refresh tokens -- close the T-7.1 gap and add the IT.
2. Malformed refresh cookie => 500 + ERROR stack trace -- catch parseHex and return AUTH_004 (401) on the uniform path.
3. Rate-limit sweep boundary -- accept-and-document for single node.

LOW/INFO (CORS Set-Cookie/origin, filter email-parse leniency, clock-skew=0 NTP dependency,
SECURITY.md 7d-vs-14d TTL drift) should be triaged but are not merge-blocking.

Follow-ups are owned by the engineer agent; this review modifies no code.
