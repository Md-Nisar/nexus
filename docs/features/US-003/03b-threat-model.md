# US-003 Threat Model — Authenticate users via login issuing JWT access and refresh tokens

Status: DRAFT — awaiting Gate 2 approval
Author: Security Reviewer Agent
Date: 2026-06-21
Inputs reviewed: `docs/features/US-003/03-design.md`, `docs/features/US-003/01-requirements.md`, `SECURITY.md`, `nexus-backend/.../config/SecurityConfig.java`, `nexus-backend/.../common/web/GlobalExceptionHandler.java`, `nexus-backend/.../common/web/CorrelationIdFilter.java`, `RegistrationController.java`

Explicit reviewer attestation: I reviewed the authentication design (JWT issuance/verification, refresh rotation), the cryptographic design (RS256, Argon2id, SHA-256 token hashing, RsaKeyConfig key handling, randomness sources), and the PII-handling design (email blind index, log masking, claims contract). Findings on each are inline below and called out in §3/§4.

---

## 1. Scope and Trust Boundaries

In scope: the login, refresh, logout, JWKS, and `/users/me` flows of US-003 in `com.example.nexus.identity`, the `SecurityConfig` overhaul, the new `JwtAuthenticationFilter` and `LoginRateLimitFilter`, RSA key handling, and the Angular auth client.

Trust boundaries modelled (attacker controls everything on the untrusted side of each):

| TB | Boundary | Untrusted side | What crosses it |
|----|----------|----------------|-----------------|
| TB1 | Browser ↔ Backend API | Browser / network client | login creds, bearer tokens, refresh cookie, `X-Forwarded-For`, `X-Correlation-Id`, `Origin` |
| TB2 | LoginController ↔ LoginUseCase | HTTP request body/headers | `LoginRequest{email,password}`, cookie value, client IP |
| TB3 | JwtAuthenticationFilter ↔ SecurityContext | Bearer token bytes | claims (`sub`, `tenant_id`, `roles`, `token_version`) that become the authenticated principal |
| TB4 | RefreshTokenUseCase ↔ refresh_tokens DB | refresh cookie value | token hash lookup, rotation, family revocation |
| TB5 | RsaKeyConfig ↔ Environment/Vault | deploy environment | RSA private/public PEM (signing key material) |
| TB6 | InMemoryRateLimitStore ↔ JVM process | per-node memory; multi-node deploy | rate-limit counters (no cross-node consistency) |

Architectural notes affecting the model:
- `SecurityConfig` is cross-context (shared `config` package). Any change there is platform-wide blast radius (TB3).
- Client IP today is derived from `req.getRemoteAddr()` (see `RegistrationController:111`); the design does not state how `clientIp` reaches `LoginUseCase`/`LoginRateLimitFilter`. This is load-bearing for TB1/TB6 (see T-1.3).
- `CorrelationIdFilter` already sanitises `X-Correlation-Id` to `[A-Za-z0-9._-]{1,64}` — log-injection on that header is mitigated; other newly-logged fields are not yet covered (see T-Repud / T-InfoDisc).

---

## 2. STRIDE Analysis

### 2.1 TB1 — Browser ↔ Backend API (login / refresh / logout / JWKS)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-1.1 | S | Credential stuffing against `/auth/login` | 5/5-min per IP + per username (§4.4); Argon2 cost | Confirm username key is the `emailHmac`, not raw email (design says `USER:{emailHmac}` — good). Add `auth.rate_limit.rejections` alerting threshold. | Medium |
| T-1.2 | S | Distributed credential stuffing with rotating IPs defeats per-IP limit | Per-username limit also applies (caps attempts on a single account) | Accept residual: a botnet spreading 1 attempt/account/IP is not fully stoppable in Sprint 2. Document as accepted; US-006 lockout + later WAF/CAPTCHA close it. | Medium (accepted) |
| T-1.3 | S | IP spoofing via `X-Forwarded-For` to evade per-IP rate limit / poison audit IP | Design uses a single `clientIp` value; existing code uses `getRemoteAddr()` (not spoofable past the LB) | **Design must state the IP-resolution rule explicitly:** use `getRemoteAddr()`, OR parse `X-Forwarded-For` ONLY when behind a trusted proxy with a configured trusted-proxy allowlist (e.g. Spring `ForwardedHeaderFilter` + known proxy hops). Never blindly trust the leftmost XFF value. → **design change required** | Medium until specified |
| T-1.4 | T | Refresh cookie tampering / theft via XSS or non-TLS transmission | `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=1209600` (§4.5); access token in memory only | Confirm cookie attributes are emitted in all three responses (login/refresh/logout) and that `Secure` is not stripped in dev over plain HTTP (acceptable in dev only). Verify `Path` exactly `/api/v1/auth`. | Low |
| T-1.5 | T | CSRF on cookie-bearing `/auth/refresh` (CSRF disabled platform-wide) | `SameSite=Strict` on the refresh cookie blocks cross-site send; access endpoints use a non-cookie Bearer header | Confirm in a test that a cross-site POST to `/auth/refresh` does NOT carry the cookie. With `allowCredentials(true)` + a single fixed origin this holds, but document the dependency on `SameSite=Strict`. | Low |
| T-1.6 | I | JWKS endpoint leaks key material | JWKS publishes only public modulus/exponent (`n`,`e`) — by design public (§5.4) | Verify `JwkSetAdapter` never serialises the private key; assert in a unit test that the JSON contains no `d`/`p`/`q` fields. | Low |
| T-1.7 | D | Unauthenticated Argon2 cost amplification: flood `/auth/login` to burn CPU (each request ~100–500 ms Argon2) | Rate limit runs in `LoginRateLimitFilter` BEFORE the controller/use-case (§4.4) — Argon2 only runs after the limit check passes | Confirm filter ordering: rate-limit MUST precede any Argon2 work. Cap request body size on `/auth/login` (oversized password → DoS). Add a global per-IP "other unauthenticated" 100/min limit per SECURITY.md §8 — design only limits login, not `/refresh`, `/jwks`, `/users/me` pre-auth. → **design gap** | Medium |
| T-1.8 | D | `/auth/refresh` has NO rate limit this sprint (§5.2 "429 not applied to refresh") | One-time-use rotation limits value of a single token | **Flag:** unauthenticated `/refresh` flooding triggers a DB lookup + (on theft) a bulk family-revoke UPDATE per request — cheap-ish but unthrottled. Add at least a per-IP throttle on `/refresh`. → **design change required** | Medium |

### 2.2 TB2 — LoginController ↔ LoginUseCase (input validation boundary)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-2.1 | T | Oversized/malformed `email`/`password` (giant strings → memory/CPU DoS, Argon2 on huge input) | `@Valid LoginRequest` bean validation (§4.5) | DTO must enforce `@Email`, `@NotBlank`, and explicit `@Size(max=…)` on both fields (e.g. email ≤254, password ≤256). Bean validation is not a security boundary per SECURITY.md §4 — re-assert size in use-case before Argon2. | Low |
| T-2.2 | I | Email enumeration via timing (unknown email skips Argon2) | §4.3 step 3 runs Argon2 against `DUMMY_ARGON2_HASH` when `!found`; AC-3 delta < 50 ms | **Validate the dummy-hash design:** (a) `DUMMY_ARGON2_HASH` MUST be a precompiled constant hash with the SAME Argon2 params as production hashes (memory=19MiB, iter=2, par=1) — note SECURITY.md says test params are lowered; the dummy must match the *runtime profile's* params, else timing diverges. (b) Must not branch on `found` before the verify call. Add a timing security test (T-5.5). | Low if implemented exactly |
| T-2.3 | I | Email enumeration via distinct status codes (401 vs 403): a valid-but-PENDING account returns 403 AUTH_002, an unknown email returns 401 — reveals account existence | §4.3 step 5 gates PENDING only AFTER the credential check passes; design claims 403 is "exposed only to a caller who already proved the password" | **Verify the ordering invariant in code and test:** PENDING 403 must be reachable ONLY when the supplied password actually matches the PENDING user's hash. If a wrong password against a PENDING account returns 403 (instead of 401), it becomes an enumeration oracle. Pin this with a security test (unknown→401, wrong-pw-on-PENDING→401, correct-pw-on-PENDING→403). | Medium until test-pinned |
| T-2.4 | I | Stack trace / internal state leaks on login error | `GlobalExceptionHandler` returns RFC 7807 only, `include-stacktrace=never` | Add the missing `@ExceptionHandler(AuthenticationException.class)`→401 and `AccountNotVerifiedException`→403. Without it both fall through to the **422 DomainException catch-all** (confirmed: handler has no 401 path today) — wrong status AND leaks that the input was structurally valid. → **design change already flagged in §15.4; must be implemented** | Low once handler added |
| T-2.5 | E | PENDING (or otherwise non-ACTIVE) account obtains a token because status check is mis-ordered or omitted | §4.3 step 5 gates on status; only ACTIVE proceeds to issue (steps 6+) | Make the gate an allowlist (`status == ACTIVE` required to issue), not a denylist of `PENDING`. Other future statuses (LOCKED/DISABLED) must NOT fall through to token issuance. → **design wording change required** | Medium until allowlist |

### 2.3 TB3 — JwtAuthenticationFilter ↔ SecurityContext (token trust establishment)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-3.1 | S | Token forgery via `alg=none` | §4.4: parser pinned RS256; `alg=none` rejected at parse | Must reject at PARSE time, not "unsupported later". Test scenario 4 covers `alg=none`. Assert JJWT is configured so an unsigned token never reaches claim extraction. | Low |
| T-3.2 | S | Algorithm-confusion: attacker re-signs with HS256 using the **public** key as the HMAC secret | §4.4: `verifyWith(publicKey)` + explicit RS256 check | Critical: JJWT 0.12 `verifyWith(PublicKey)` binds asymmetric verification, but add an explicit header-`alg`==RS256 assertion AND ensure the public key can never be interpreted as a MAC key. Security test must include an HS256 token signed with the JWKS public key → expect 401. | Low if explicit alg check present |
| T-3.3 | S | Forged token signed with attacker's own key / wrong key | RS256 signature verified against configured public key | Verify `kid` is informational only and does NOT cause the verifier to fetch/trust an attacker-supplied key (no remote JWKS fetch in verify path — verify uses the locally-held public key). Confirm single-key, no `jku`/`x5u` header honoured. | Low |
| T-3.4 | T | Payload modification of `sub`/`tenant_id`/`roles`/`token_version` | RS256 signature covers the full payload; any edit breaks signature → 401 | Test scenario 4 (modified `tenant_id`). Add explicit assertions for tampered `roles` and `token_version`. | Low |
| T-3.5 | T | Clock-skew exploitation of `exp` (replay just past expiry) | `exp`=iat+900s from injected `Clock` | Set JJWT allowed clock skew to a small bounded value (e.g. ≤30s), not the library default if larger; verify expiry uses the same `Clock`. Document skew tolerance. | Low |
| T-3.6 | E | Privilege escalation by injecting `roles:["ADMIN"]` into a token | Roles hardcoded `["USER"]` at issuance; signature prevents client edits | Filter must derive authorities ONLY from the signed `roles` claim of a validly-signed token. Since the issuer hardcodes `["USER"]`, an ADMIN claim can only exist in a forged token (→401). Re-verify when admin roles are introduced (future story) that issuance is authoritative, not client-influenced. | Low |
| T-3.7 | E | Tenant isolation break: caller manipulates `tenant_id` to read another tenant's data | `tenant_id` sourced from `User.tenantId` at issuance, never from request (SECURITY.md §3); signature-protected | `/users/me` echoes claims only (no DB query this sprint), so no IDOR surface yet. **Required for downstream:** every future data-access path MUST filter by the JWT `tenant_id` from `SecurityContext`, never a request-supplied tenant. Establish this as a tested invariant now (claim is stashed as auth detail per §4.4). | Low this sprint; High platform-wide if not enforced later |
| T-3.8 | E | Default-deny bypass: a new public path added to permit-all accidentally exposes data | `anyRequest().authenticated()` preserved; `JwtAuthenticationFilter` no-ops without a token | Add an `*IT` that asserts `/api/v1/users/me` and an arbitrary unknown `/api/v1/**` path return 401 without a token (Test scenario 8). Keep the permit-all list minimal and reviewed. | Low |
| T-3.9 | S/E | `token_version` is embedded but NOT checked this sprint — a stolen access token stays valid for its full 15 min even after a forced-logout intent | Claim present for future use (§7); short 15-min TTL bounds exposure | Accept for Sprint 2 (revocation is US-005). Document that access tokens are irrevocable within their TTL window; ensure refresh rotation + family revoke is the only containment lever now. | Medium (accepted) |

### 2.4 TB4 — RefreshTokenUseCase ↔ refresh_tokens DB (rotation / theft detection)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-4.1 | S | Stolen refresh token reused after legit rotation | One-time use; presenting an already-revoked token ⇒ theft ⇒ `revokeFamily` (§4.3 step 3) | Test scenario 6. Ensure `REFRESH_FAMILY_REVOKED` audit + `refresh_theft_detected` WARN fire. | Low |
| T-4.2 | T | Concurrent rotation race (double-spend a token in parallel) | `@Version` optimistic lock on `RefreshToken` (§4.3) | Verify the use-case is `@Transactional` and a lost-update yields one winner + the loser treated as reuse (theft) or clean retry — pin with a concurrency IT. | Medium until tested |
| T-4.3 | I | Raw refresh token logged or echoed in JSON body | §4.3 step 9 / §12: raw token never logged, never in body, only Set-Cookie | Add a log-scan test / assertion that no logger receives the raw token or cookie value. Store only SHA-256 hash (§8). | Low |
| T-4.4 | S | Refresh-token family reuse across tenants (token bound to wrong user/tenant) | Token row carries `user_id`; new access token re-looked-up by `token.userId()` and re-checks `status==ACTIVE` (§4.3 step 7) | Confirm the re-lookup uses the token's `user_id` only and the issued JWT's `tenant_id` comes from that user — never carried over from a client value. Add cross-tenant rotation test (Test scenario 2 variant). | Low |
| T-4.5 | T | Hash-collision / lookup ambiguity on `token_hash` | SHA-256 + `uq_refresh_tokens_token_hash` UNIQUE | SHA-256 collision is infeasible; UNIQUE prevents duplicates. No action. | Low |
| T-4.6 | D | refresh_tokens table unbounded growth (no expiry sweep this sprint) — every login + rotation inserts a row, none reaped | Rotation revokes (sets `revoked_at`) but does not DELETE; V4 expiry index/sweep deferred (§8, §15.2) | **Flag:** table grows monotonically; over months this is a storage/perf DoS. Either (a) accept with a documented operational ticket + monitoring on table size, or (b) reinstate a minimal expiry-sweep. → **architect decision at Gate 2** | Medium (must be explicitly accepted) |

### 2.5 TB5 — RsaKeyConfig ↔ Environment/Vault (key material)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-5.1 | S/T | Prod boots with a weak/ephemeral/absent signing key → forgeable tokens | Prod fail-fast: blank `privateKeyPem` under `prod` ⇒ `IllegalStateException` at startup (§4.4); dev/test auto-gen RSA-2048 | Verify fail-fast is reachable for `prod` specifically (not just "key absent"). Assert RSA-2048 minimum on parse (reject <2048-bit keys even if PEM provided). PEM only from env/Vault, never source (SECURITY.md §1). | Low |
| T-5.2 | I | Private key PEM leaked via logs/error/actuator/heap dump | `@ConfigurationProperties` value; design says no logging of key | Ensure `RsaKeyConfig` `toString()` / actuator `/configprops` / `/env` do NOT expose `privateKeyPem` (Spring sanitises `*key*`/`*secret*` keys, but `privateKeyPem` should be added to `management.endpoint.configprops.show-values`/sanitize keywords). Never log the parsed key. → **config hardening item** | Low |
| T-5.3 | A02 | No key rotation mechanism this sprint | Single key + `kid` from day 1 so header shape is stable (§7) | Accept: rotation deferred but `kid` makes it non-breaking later. Document that a key compromise this sprint requires a full redeploy with a new key (no online rotation). | Medium (accepted) |
| T-5.4 | A02 | Dev/test ephemeral key accidentally used in a prod-like env | Prod profile fail-fast guards this | Ensure staging/preprod run with the `prod` profile (or an equally strict one) so ephemeral generation is impossible outside dev/test. Verify profile gating. | Low |

### 2.6 TB6 — InMemoryRateLimitStore ↔ JVM process (per-instance limiter)

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-6.1 | S/D | Multi-node deploy: per-JVM counters mean effective limit = 5 × N nodes; attacker spreads attempts across nodes behind the LB | Config seam for Redis-backed shared store exists (`store-type=redis`), zero-code migration (§4.2) | **Flag as a documented known limitation** in 03-design.md §10/§15: in-memory limiter is correct only for single-instance Sprint 2. Multi-node must switch to Redis BEFORE horizontal scaling. Add a design note + an ops guardrail (deploy with 1 replica until Redis lands). → **design note required** | Medium (accepted for single-node) |
| T-6.2 | D | `ConcurrentHashMap` unbounded growth: attacker sends logins with millions of distinct IPs/usernames → one Deque per key, never evicted → heap exhaustion | Sliding-window prunes timestamps WITHIN a key, but does not remove empty/expired KEYS | **Required:** bound the store — evict keys whose window is fully expired (e.g. opportunistic removal in `compute` when the Deque becomes empty, plus a periodic sweeper or a size cap / `Caffeine` with maximumSize+expireAfterWrite). Without eviction this is an unauthenticated memory-DoS. → **design change required** | Medium → Low once bounded |
| T-6.3 | T | Rate-limit counters lost on restart (attacker forces restart or waits) | In-memory by nature | Accept: limited value to attacker (still bounded by Argon2 cost + per-username cap). Document. | Low (accepted) |

### 2.7 Cross-cutting — Repudiation & Logging

| # | STRIDE | Threat scenario | Existing mitigation | Required mitigation | Residual risk |
|---|--------|-----------------|---------------------|---------------------|---------------|
| T-7.1 | R | User denies a login/logout/refresh they performed | Append-only `auth_events`: `LOGIN_SUCCESS/FAILURE/PENDING`, `TOKEN_REFRESH_SUCCESS/FAILURE`, `REFRESH_FAMILY_REVOKED` (§12) | SECURITY.md §10 requires logout to be audited — design audits login/refresh but **no `LOGOUT` event** is listed. Add a `LOGOUT` auth event. → **design change required** | Medium until logout audited |
| T-7.2 | R | Audit log tampered post-hoc | `auth_events` "append-only" by convention (§12) | Ensure the application has no UPDATE/DELETE path on `auth_events`; rely on DB grants/retention ≥1yr (SECURITY.md §10). No app code may mutate audit rows. | Low |
| T-7.3 | I | Log injection (CRLF) via attacker-controlled fields newly logged (masked `email`, `ip`, `reason`) | `X-Correlation-Id` sanitised by `CorrelationIdFilter`; structured key=value logging | The masked email and `ip` are now logged (§12). `email` is masked (`u***@…`) which removes most injection risk; `ip` from `getRemoteAddr()` is safe, but if XFF parsing is added (T-1.3) the `ip` becomes attacker-controlled and must be validated as an IP literal before logging. Use structured logging (no raw concatenation). | Low (Medium if XFF added without validation) |
| T-7.4 | I | PII in logs: raw email / password / token | §12 mandates masked email via `LogMaskingUtil`, no password, no token | Add a test asserting no `WARN/INFO` auth log line contains an `@`-with-full-localpart, a bcrypt/argon prefix, or a 64-hex token. Confirm `LogMaskingUtil` is applied at every auth log site. | Low |
| T-7.5 | I | JWT body carries PII (email) readable by anyone holding the token | Claims contract (§7) deliberately EXCLUDES email — carries only `sub`,`tenant_id`,`email_verified`,`roles`,`iat`,`exp`,`jti`,`token_version` | Good. Contract test (Test scenario 9) freezes this — assert no `email`/name claim is ever added. | Low |

---

## 3. Threats Requiring Design Changes (back to Architect)

These cannot be resolved by implementation alone — `03-design.md` must change or a decision must be recorded at Gate 2:

1. **T-1.3 — IP resolution rule is unspecified.** Add to §4.4/§12 an explicit, trusted-proxy-aware client-IP strategy: use `getRemoteAddr()` only (current platform pattern), OR `ForwardedHeaderFilter` with a configured trusted-proxy allowlist. Forbid blind trust of `X-Forwarded-For`. Without this, both the per-IP rate limit (T-1.3) and audit-IP integrity (T-7.3) are spoofable.

2. **T-6.2 — InMemoryRateLimitStore is unbounded.** The current §4.4 design prunes timestamps within a key but never evicts empty/expired keys. Add a bounding strategy: Caffeine `maximumSize` + `expireAfterWrite`, or empty-Deque eviction in the atomic `compute`, plus a sweeper. This is an unauthenticated memory-DoS as designed.

3. **T-6.1 — Per-instance limiter correctness.** Add an explicit known-limitation note to §10/§15: the in-memory limiter only enforces 5/5-min on a single replica; multi-node deployment multiplies the limit and requires the Redis store first. Pair with an ops guardrail (single replica until Redis).

4. **T-1.7 / T-1.8 — Throttling gaps on non-login unauthenticated paths.** SECURITY.md §8 mandates 100/min per-IP on "other unauthenticated" endpoints; design only throttles `/auth/login`. Decide and document throttling for `/auth/refresh`, `/.well-known/jwks.json`, and pre-auth hits on `/api/v1/**`. At minimum add a per-IP throttle on `/auth/refresh`.

5. **T-2.5 — Status gate should be allowlist, not denylist.** §4.3 step 5 only special-cases `PENDING`. Change wording so a token is issued ONLY when `status == ACTIVE`; any other status (future LOCKED/DISABLED) must not reach issuance.

6. **T-4.6 — refresh_tokens unbounded growth.** §8/§15.2 defers expiry sweep. Either record an explicit Gate-2 acceptance with a monitoring ticket, or reinstate a minimal cleanup. Architect must choose.

7. **T-7.1 — Logout is not audited.** Add a `LOGOUT` event type to the `auth_events`/`AuthEventPort` list in §12 (SECURITY.md §10 requires it).

8. **T-2.4 — Missing 401 exception handler (already flagged §15.4 of design).** Confirmed against the live `GlobalExceptionHandler`: there is no 401 path; `AuthenticationException`/`AccountNotVerifiedException` would hit the 422 `DomainException` catch-all. The new handlers are mandatory, not optional.

---

## 4. High-Residual-Risk Items

No item is rated **High** for the Sprint-2 single-node, flag-gated scope. The following are **Medium** items that MUST be explicitly accepted at Gate 2 or mitigated before implementation:

- **T-6.1 / T-6.2 / T-6.3** — In-memory rate limiter: per-instance only, unbounded memory (T-6.2 is the must-fix), lost on restart.
- **T-1.2** — Distributed credential stuffing across rotating IPs (mitigated only by per-username cap until US-006 lockout / WAF).
- **T-3.9** — Access tokens are irrevocable within their 15-min TTL (no `token_version` enforcement until US-005).
- **T-4.6** — refresh_tokens table grows without a reaper.
- **T-3.7 (platform-wide)** — Tenant isolation is correct in US-003 (`/users/me` echoes claims only), but becomes **High** platform-wide if any future data path trusts a request-supplied tenant instead of the JWT claim.

---

## 5. Security Test Requirements

| Threat | Required test | Type |
|--------|---------------|------|
| T-3.1 | `alg=none` token → 401 | Security/Unit |
| T-3.2 | HS256 token signed with the JWKS public key → 401 (alg-confusion) | Security/Unit |
| T-3.3 | Token signed with a foreign RSA key → 401; `jku`/`x5u`/foreign `kid` not honoured | Security/Unit |
| T-3.4 | Tampered `tenant_id`, `roles`, `token_version`, `sub` → 401 (each) | Security/Unit |
| T-3.5 | Expired token (just past `exp` + beyond skew) → 401; within-skew boundary documented | Unit |
| T-3.8 | No token on `/api/v1/users/me` and arbitrary `/api/v1/**` → 401 (default-deny) | IT |
| T-2.2 | Timing: unknown-email vs wrong-password delta < 50 ms over N samples | Security/Perf |
| T-2.3 | unknown→401, wrong-pw-on-PENDING→401, correct-pw-on-PENDING→403 (no enumeration oracle) | Security/IT |
| T-2.4 | `AuthenticationException`→401 and `AccountNotVerifiedException`→403 (not 422) | IT |
| T-2.1 | Oversized email/password rejected at validation, before Argon2 | Unit |
| T-2.5 | Non-ACTIVE/non-PENDING status never receives a token | Unit |
| T-1.1/T-1.3 | 6th login attempt within window → 429 + `Retry-After`; per-IP and per-username independently; spoofed XFF does not reset the per-IP counter | IT |
| T-1.4/T-1.5 | Refresh cookie carries `HttpOnly;Secure;SameSite=Strict;Path=/api/v1/auth`; cross-site POST to `/refresh` omits the cookie | IT |
| T-1.6 | JWKS JSON contains only `kty,use,alg,kid,n,e` — never `d/p/q` | Unit |
| T-4.1/T-4.2 | Rotate once → new pair; reuse revoked → family revoked + `REFRESH_FAMILY_REVOKED`; concurrent rotation → single winner | IT (incl. concurrency) |
| T-4.4 | Two tenants, same email → each refresh issues correct-tenant JWT; no cross-tenant carryover | IT |
| T-5.1/T-5.4 | Prod profile + blank key → startup fails; <2048-bit key rejected; ephemeral key impossible under prod profile | IT |
| T-5.2 | `privateKeyPem` not exposed via `/actuator/configprops`/`/env`, logs, or `toString()` | Unit/IT |
| T-6.2 | Flood with distinct keys → store size stays bounded (eviction works) | Unit |
| T-7.4 | No auth log line contains raw email/password/token | Unit (log capture) |
| T-7.1 | Logout emits a `LOGOUT` audit event | IT |
| T-7.5 / contract | Issued access token validates against the frozen JSON schema; no `email`/PII claim present | Contract (CI) |

---

## Dependency / Component Note

Per SECURITY.md §11 and design §11, `./mvnw -Psecurity dependency-check:check` (fail CVSS ≥7) must run on the JJWT 0.12.6 additions (`jjwt-api`/`impl`/`jackson`) and `npm audit --omit=dev --audit-level=high` on the Angular changes before merge — these are Phase-7 code-audit gates, out of scope for this threat model but called out so they are not skipped. RSA parsing uses JDK-native `KeyFactory` (no Bouncy Castle JOSE), reducing CVE surface — good (A06).
