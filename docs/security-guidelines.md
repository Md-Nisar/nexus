# Security Guidelines — Nexus

## Authentication

### JWT
- **Algorithm:** RS256 (asymmetric). Private key signs; public key verifies. Never HS256 in production.
- **Access token TTL:** 15 minutes.
- **Refresh token TTL:** 7 days, rotated on use (one-time use).
- **Claims:** `sub` (userId), `iat`, `exp`, `jti` (unique ID for revocation).
- **Storage (frontend):** Refresh token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Access token in memory only — never `localStorage`.
- **Revocation:** Store revoked `jti` values in a revocation table (or Redis if latency matters). Check on each request.

### Session management
- Invalidate all sessions on password change or reset.
- Invalidate on detected suspicious activity (geography change, concurrent sessions if policy).
- Session table columns: `id`, `user_id`, `jti`, `expires_at`, `revoked_at`, `user_agent`, `ip`.

### Multi-factor authentication (future)
- Design auth flows to be MFA-ready — separate the "credential check" step from "issue token" step.

---

## Password Security

- **Hashing:** Argon2id. Parameters: memory=19456 KiB (19 MiB), iterations=2, parallelism=1.
- Never MD5, SHA-1, SHA-256, or bcrypt-alone for new code.
- Minimum password length: 12 characters. No maximum (hash it).
- Implement credential stuffing checks (have-i-been-pwned API on registration / password change).
- Never store plaintext or reversibly encrypted passwords.
- Never log plaintext passwords — not even a partial match.

---

## Authorization

- **Default deny.** Spring Security config: `anyRequest().authenticated()`. Every endpoint opts in.
- `@PreAuthorize` on application service methods for role / permission checks.
- **Object-level authorization (IDOR prevention):** Every resource fetch verifies the requesting user owns or has permission for that specific object. Returning 404 (not 403) for inaccessible resources prevents enumeration.
- Tenant ID comes from the JWT — never from the request body or path parameters.
- Admin endpoints require an explicit admin role check, not just authentication.

---

## Input Validation

- Validate at the controller boundary with Bean Validation.
- Validate again at the application service for any security-sensitive operation.
- **Field-level:** `@NotBlank`, `@Size(max=...)`, `@Email`, `@Pattern(...)`.
- Reject oversized inputs before processing — set `spring.mvc.content-negotiation` or a `MaxUploadSizeExceededException` handler.
- Never trust user-supplied IDs for ownership — always verify against the authenticated user.
- Allowlist, not blocklist, for input character sets where possible.

---

## Output Encoding

- Spring MVC returns JSON — Jackson escapes by default. Do not disable.
- Never render user-supplied input as raw HTML on the server side.
- Angular: interpolation (`{{ }}`) is safe. Never use `[innerHTML]` with user content.
- Sanitise any user content rendered via `DomSanitizer` — use `bypassSecurityTrustHtml` only after explicit review.
- XSS prevention via Content-Security-Policy header — no `unsafe-inline` in prod.

---

## SQL Injection Prevention

- Use Spring Data JPA named parameters for all queries. **Never** string-concatenate user input into JPQL or SQL.
- For dynamic queries, use `CriteriaBuilder` or Specifications — never raw `String.format` into a query.
- If native SQL is genuinely needed, use `@Query(value = "...", nativeQuery = true)` with `?1` binding.

---

## Secrets Management

- No secrets in code, ever. Secrets in env vars (local dev) or Vault (staging/prod).
- `.env` is gitignored. Never commit it.
- Rotate credentials on any suspected exposure. Treat rotation as a normal operation (automate it).
- `application.yml` references secrets as `${VAR_NAME}` — the variable is never in the file itself.
- The secret-scan hook blocks obvious patterns on write. It is not exhaustive — also audit in CI.

---

## Cryptography

| Operation | Algorithm | Notes |
|-----------|-----------|-------|
| Password hashing | Argon2id | Spring Security `Argon2PasswordEncoder` |
| Token generation | `SecureRandom.nextBytes(32)` → hex | Never `Math.random` |
| Symmetric encryption | AES-256-GCM | Use Spring Security `Encryptors.stronger()` |
| Signatures | RSA-2048+ or Ed25519 | JWT: RS256 |
| Digests | SHA-256 | For token hashing stored in DB |
| TLS | TLS 1.2 minimum, 1.3 preferred | Enforce in Spring Security or load balancer |

Never implement custom crypto. Use standard library implementations.

---

## Sensitive Data

### PII definition (for Nexus)
Email address, full name, IP address, device fingerprint, any government ID.

### Handling rules
- Mask in logs: emails → `u***@example.com`, IDs → first 4 + `***`.
- Mask in error responses: never return full email in "email already exists" errors.
- Do not include PII in URLs or query parameters (logged by web servers and CDNs).
- Encrypted at rest for sensitive fields (beyond DB-level encryption): use `@Convert` with `AttributeEncryptor`.
- Minimize collection — only store what's necessary for the feature.

---

## Rate Limiting

Apply at the Spring Security filter level, before controllers are reached:

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| `POST /auth/login` | 5 attempts | 5 minutes | Per IP + per username |
| `POST /auth/password-reset/request` | 3 requests | 1 hour | Per email |
| `POST /auth/password-reset/request` | 10 requests | 1 hour | Per IP |
| `POST /auth/register` | 5 requests | 1 hour | Per IP |
| All other unauthenticated | 100 requests | 1 minute | Per IP |

On limit exceeded: return `429` with `Retry-After` header. Do not reveal remaining attempts in error body.

---

## Dependency Security

- Run `./mvnw dependency:check` (OWASP plugin) in CI. Block on CVSS >= 7.0.
- Run `npm audit --audit-level=moderate` in CI. No high/critical vulns ship.
- Update dependencies on a schedule (monthly at minimum).
- Pin all versions. No ranges.

---

## Audit Logging

Log all security-relevant events to a dedicated audit log (separate appender, immutable storage):

```json
{
  "timestamp": "2025-11-14T09:12:00.000Z",
  "event": "PASSWORD_RESET_REQUESTED",
  "userId": null,
  "email": "u***@example.com",
  "ip": "1.2.3.4",
  "userAgent": "Mozilla/5.0 ...",
  "traceId": "abc-123",
  "result": "ACCEPTED"
}
```

Events to audit: login (success + failure), logout, password change, password reset request/confirm, account lock/unlock, permission change, data export, admin action.

---

## Security Response Headers

Configure in Spring Security or the reverse proxy:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## OWASP Top 10 Checklist

Use this at Phase 7 (security review) for every feature:

- [ ] A01 Broken Access Control — object-level authz, no default-allow
- [ ] A02 Cryptographic Failures — algorithm check, key strength, TLS
- [ ] A03 Injection — parameterized queries, no eval, no command injection
- [ ] A04 Insecure Design — threat model done, security requirements defined
- [ ] A05 Security Misconfiguration — security headers, error pages, debug off in prod
- [ ] A06 Vulnerable Components — `./mvnw dependency:check`, `npm audit`
- [ ] A07 Auth Failures — brute force protection, session invalidation, MFA readiness
- [ ] A08 Software & Data Integrity — dependency pinning, signed artifacts, no untrusted deserialization
- [ ] A09 Logging & Monitoring Failures — audit log present, alerts wired, no PII in logs
- [ ] A10 SSRF — validate / allowlist any outbound URL built from user input

---

## Incident Response (Summary)

1. **Detect** — alert fires or report received.
2. **Contain** — revoke affected tokens / disable feature flag / block IP.
3. **Assess** — determine scope; identify affected users.
4. **Notify** — internal stakeholders, then affected users per legal requirements.
5. **Remediate** — patch and deploy.
6. **Review** — blameless post-mortem within 48h.

Full runbook in `docs/runbooks/security-incident-response.md`.
