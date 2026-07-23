# Security

Single source of truth for security on Nexus. Two parts: **what is implemented today** (the baseline) and **the standards any new code must meet** (especially the auth/crypto rules that apply the moment the first auth feature lands). The `security-reviewer` agent audits diffs against this document; `/security-review` runs it on demand.

## 1. Baseline — implemented today

| Control | Implementation |
|---------|----------------|
| Default-deny authorization | `SecurityConfig`: `anyRequest().authenticated()`; only `/actuator/health/**`, `/actuator/info`, and (non-prod) API docs are public |
| Stateless sessions | `SessionCreationPolicy.STATELESS`; no session cookie → CSRF disabled deliberately |
| No information leakage | `GlobalExceptionHandler` returns RFC 7807 documents only — no stack traces, SQL, or class names; `server.error.include-stacktrace=never` |
| Secrets out of source | All credentials are `${ENV_VAR}` placeholders; prod has **no defaults** and fails fast if unset. `.env*` gitignored; agent tooling denied read/write on `.env*` and `application-prod.*` (`.claude/settings.json`), plus the `secret-scan` hook |
| Input validation | Bean validation at the controller boundary (`spring-boot-starter-validation`); re-validated at the service layer for sensitive operations — bean validation is not a security boundary |
| Log-injection defense | `CorrelationIdFilter` accepts only `[A-Za-z0-9._-]{1,64}` correlation ids; anything else is replaced |
| Browser hardening | nginx sets `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` |
| Dependency hygiene | Weekly OWASP Dependency-Check (fail CVSS ≥ 7), `npm audit` (high+), Trivy filesystem scan |
| Prod API docs | springdoc fully disabled under the `prod` profile |

## 2. Authentication roadmap

HTTP Basic in `SecurityConfig` is a **placeholder**. Until the `auth` bounded context replaces it, any deployed environment must sit behind network-level access control. The auth feature must implement the standards below.

### JWT
- **Algorithm:** RS256 (asymmetric). Private key signs; public key verifies. Never HS256 in production.
- **Access token TTL:** 15 minutes. **Refresh token TTL:** 7 days, rotated on use (one-time).
- **Claims:** `sub` (userId), `iat`, `exp`, `jti` (for revocation), `tenantId`.
- **Frontend storage:** refresh token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie; access token in memory only — never `localStorage`.
- **Revocation:** store revoked `jti` (table or Redis); check on each request.
- **Transport:** `Authorization: Bearer <token>` — never tokens in URLs (logged by proxies/CDNs).

### Sessions & MFA
- Invalidate all sessions on password change/reset and on suspicious activity.
- Design auth flows MFA-ready: separate "credential check" from "issue token".

### Passwords
- **Hashing:** Argon2id (`Argon2PasswordEncoder`), memory=19 MiB, iterations=2, parallelism=1.
- Never MD5/SHA-1/SHA-256/bcrypt-alone. Min length 12, no max. Never log, even partially.

## 3. Authorization

- **Default deny** (implemented). Every endpoint opts in.
- **Method-level permission checks:** `@RequiresPermission("resource:action")` — see §3.1 below.
- **Object-level (IDOR):** every resource fetch verifies the caller owns/may access that specific object. Return **404, not 403**, for inaccessible resources to prevent enumeration.
- **Tenant id comes from the JWT** — never from request body or path. Admin endpoints require an explicit admin-role check, not just authentication.

### 3.1 Method-level permission checks — `@RequiresPermission`

`@RequiresPermission("resource:action")` is a `@PreAuthorize` meta-annotation (`com.example.nexus.common.security.RequiresPermission`) enforced by `TenantAwarePermissionEvaluator` via Spring's method-security AOP proxy. Apply it directly to the controller method that is the actual HTTP entry point:

```java
@RestController
class ExampleController {

    @GetMapping("/tenants/{id}/settings")
    @RequiresPermission("tenant:write")
    public ResponseEntity<Void> updateSettings(@PathVariable String id) {
        ...
    }
}
```

> **Warning — Spring AOP self-invocation bypasses this annotation.**
> `@RequiresPermission` (like every `@PreAuthorize`-based check) only runs when the call goes *through the Spring-generated proxy* — i.e. an external caller (another bean, the servlet dispatcher) invokes the method. A call from **another method in the same class** goes directly to `this`, skips the proxy entirely, and **the permission check silently does not run**. No error, no log, no exception — the code simply executes unguarded.
>
> ```java
> @RequiresPermission("tenant:write")
> public void updateSettings(...) { ... }
>
> public void internalHelper(...) {
>     updateSettings(...); // BYPASSES the check — same bean, no proxy involved
> }
> ```
>
> **Do this instead:**
> - Annotate the method that is actually the external entry point (the controller method, the port method called by another bean) — not an internal helper it delegates to.
> - If a guarded operation must also be reachable from another method in the same bean, extract it into a **separate bean** and call it through that bean's injected proxy.
>
> This is a general Spring AOP limitation, not specific to this annotation — but it is the highest-consequence pitfall with `@RequiresPermission` because the failure is a silent, permanent authorization bypass, not a compile error or a test failure you'd notice locally unless you specifically test the entry point you meant to guard.

> **Also: `@RequiresPermission` must be on a `public`, non-`final` method.** Spring AOP cannot proxy `final` or `private` methods — the same silent-bypass failure mode as self-invocation above, just from a different cause. If a guarded method is ever marked `final` or `private`, the check silently stops running.

**Single-permission scope.** `@RequiresPermission` takes exactly **one** permission string — there is no AND/OR composition (`value()` is a single `String`, not an array). If an operation genuinely needs more than one permission, drop to a raw `@PreAuthorize` SpEL expression on that method instead of trying to stack `@RequiresPermission`.

**The `RBAC_001` response shape.** A denial from `@RequiresPermission` (authenticated caller, missing permission) returns:

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "detail": "You do not have permission to perform this action",
  "code": "RBAC_001",
  "traceId": "b1f2c3d4-...",
  "requiredPermission": "tenant:write"
}
```

Note the human-readable text is under `detail` (the RFC 7807 field every Nexus error uses), and the extra field is camelCase `requiredPermission` — not `message` / `required_permission`. This is distinct from the platform's generic `ACCESS_DENIED` 403 (filter-chain-level denials); `RBAC_001` is specific to a `@RequiresPermission` check failing.

**401 vs. 403 — where the boundary is.** A missing, malformed, expired, or signature-invalid JWT never reaches `@RequiresPermission` at all: `JwtAuthenticationFilter` rejects it and the request short-circuits to a **401 `AUTH_003`** before Spring's method-security proxy — and therefore `TenantAwarePermissionEvaluator` — ever runs. **403 `RBAC_001` only ever means "you are authenticated, and you specifically lack this one permission."** If you see `RBAC_001`, authentication already succeeded.

**A typo'd permission string fails closed — permanently, and silently at startup.** `@RequiresPermission("tennant:write")` (note the typo) compiles fine and is **not validated against the seeded permission list at application startup**. Since no real token's `permissions[]` claim will ever contain that misspelled string, every call to that endpoint is denied with `RBAC_001`, for every caller, forever — indistinguishable at runtime from "this caller genuinely lacks the permission." There is no separate error for "this permission string doesn't exist." When adding `@RequiresPermission`:
- Copy the permission string from the seeded list (`V5__rbac_schema.sql` / the seven system permissions) rather than typing it from memory.
- Write the MockMvc positive-control test (caller **with** the permission → 200) alongside the negative test — a positive control that unexpectedly 403s is your signal that the string doesn't match anything real.

See `GuardedTestController` (`src/test/java/.../support/web/`) for a working, minimal usage example, and `TenantAwarePermissionEvaluatorTest` / `RequiresPermissionMockMvcTest` for the full behavioral contract (fail-closed on malformed authentication, tenant-presence guard, etc.).

## 4. Input validation & output encoding

- Validate at the controller boundary (Bean Validation); re-validate security-sensitive operations at the service layer. Reject oversized inputs. Allowlist over blocklist.
- Jackson escapes JSON by default — do not disable. Never render user input as raw HTML server-side.
- Angular: interpolation `{{ }}` is safe; never `[innerHTML]` with user content; `bypassSecurityTrustHtml` only after explicit review. Enforce CSP without `unsafe-inline` in prod.

## 5. Injection prevention

- Spring Data JPA named parameters for all queries. **Never** string-concatenate user input into JPQL/SQL.
- Dynamic queries via `CriteriaBuilder`/Specifications. Native SQL only via `@Query(nativeQuery=true)` with `?1` binding.

## 6. Cryptography

| Operation | Algorithm | Notes |
|-----------|-----------|-------|
| Password hashing | Argon2id | `Argon2PasswordEncoder` |
| Token generation | `SecureRandom.nextBytes(32)` → hex | Never `Math.random` |
| Symmetric encryption | AES-256-GCM | `Encryptors.stronger()` |
| Signatures | RSA-2048+ / Ed25519 | JWT: RS256 |
| Digests | SHA-256 | For token hashes stored in DB |
| TLS | 1.2 min, 1.3 preferred | Enforced at LB/ingress |

Never implement custom crypto.

## 7. Sensitive data (PII)

PII for Nexus: email, full name, IP, device fingerprint, government ID.
- Mask in logs: emails → `u***@example.com`, ids → first 4 + `***`. Never full email in "already exists" errors.
- No PII in URLs/query params. Minimize collection. Encrypt sensitive fields at rest beyond DB-level (`@Convert` with an `AttributeEncryptor`) where warranted.

## 8. Rate limiting

Applied at the security-filter level, before controllers. On exceed: `429` + `Retry-After`; do not reveal remaining attempts.

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| `POST /auth/login` | 5 | 5 min | per IP + per username |
| `POST /auth/password-reset/request` | 3 / 10 | 1 hour | per email / per IP |
| `POST /auth/register` | 5 | 1 hour | per IP |
| Other unauthenticated | 100 | 1 min | per IP |

## 9. Security response headers

Configure at Spring Security or the reverse proxy (nginx implements the non-CSP/HSTS subset today):

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

## 10. Audit logging

Security-relevant events go to a separate, append-only audit log (never deleted by application code; retention ≥ 1 year):

```json
{ "timestamp": "...", "eventType": "PASSWORD_RESET_REQUESTED",
  "actor": { "userId": null, "email": "u***@example.com" },
  "target": { "type": "User", "id": null }, "outcome": "ACCEPTED",
  "metadata": { "ip": "1.2.3.4", "traceId": "abc-123" } }
```

Audit: login (success+failure), logout, password change, reset request/confirm, account lock/unlock, permission change, data export, admin action.

## 11. Dependency security

- OWASP Dependency-Check in CI — block CVSS ≥ 7 (`./mvnw -Psecurity dependency-check:check`).
- `npm audit --omit=dev --audit-level=high` in CI. Trivy filesystem scan. Update monthly. Pin all versions — no ranges.

## 12. OWASP Top 10 review checklist

Used by `/security-review` and the `security-reviewer` agent for every feature:

- [ ] A01 Broken Access Control — object-level authz, no default-allow
- [ ] A02 Cryptographic Failures — algorithm/key strength, TLS
- [ ] A03 Injection — parameterized queries, no eval/command injection
- [ ] A04 Insecure Design — threat model done, security requirements defined
- [ ] A05 Security Misconfiguration — headers, error pages, debug off in prod
- [ ] A06 Vulnerable Components — dependency-check, `npm audit`
- [ ] A07 Auth Failures — brute-force protection, session invalidation, MFA readiness
- [ ] A08 Software & Data Integrity — dependency pinning, signed artifacts, no untrusted deserialization
- [ ] A09 Logging & Monitoring — audit log present, alerts wired, no PII in logs
- [ ] A10 SSRF — validate/allowlist any outbound URL built from user input

## 13. Incident response

Detect → Contain (revoke tokens / kill-switch flag / block IP) → Assess scope → Notify → Remediate → Blameless post-mortem within 48h.

## Reporting a vulnerability

Open a private GitHub Security Advisory (Security → Advisories) or contact the engineering team directly. Never open a public issue for a vulnerability.
