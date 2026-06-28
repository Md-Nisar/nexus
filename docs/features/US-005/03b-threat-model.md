# US-005 Threat Model

**Status:** APPROVED — Gate 2 passed 2026-06-29
**Story:** US-005 | Epic: EPIC-001
**Date:** 2026-06-29
**Reviewer:** Claude (security-reviewer)

---

## 1. Trust boundary map

```
  [ User / Browser ]
        |  (1) HTTPS, HttpOnly+Secure+SameSite=Strict refresh cookie + Bearer access token
        v
  [ Angular SPA ]  — in-memory AuthStore session signal (access token), auth.interceptor
        |  (2) POST /api/v1/auth/logout (withCredentials)
        v
  ===== Trust boundary: network → server =====
        |
  [ Spring Security filter chain ]  — JWT verification (JwtPort), CorrelationIdFilter, rate limiter
        |  (3) Authentication resolved (userId) or anonymous; cookie read via @CookieValue
        v
  [ LoginController.logout ]  — derives userId, reads refresh cookie, sets Max-Age=0
        |  (4) execute(userId, rawRefreshToken, clientIp)
        v
  [ LogoutUseCase ]  @Transactional  — resolve user, revoke-all, audit
        |  (5) revokeByUserId() + record(LOGOUT)  (single TX)
        v
  ===== Trust boundary: app → datastore =====
        |
  [ MySQL ]  — refresh_tokens (revoked_at), auth_events
```

Boundaries relevant to US-005:
- **(1) Browser ↔ SPA:** access token lives in JS memory (`AuthStore`); refresh token is `HttpOnly` and unreachable from JS. XSS is the primary cross-boundary risk but is outside US-005's changed surface (no new DOM sinks; `NxButton` content is static text).
- **(2) Network → server:** the only state-changing operation is the logout POST, protected by `SameSite=Strict` against cross-site invocation.
- **(4)/(5) App → datastore:** revocation and audit are atomic; partial failure rolls both back (`@Transactional`).

---

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| **Refresh-token family** (`refresh_tokens`) | The durable 14-day credential. If not revoked on logout, a captured refresh cookie silently re-mints access tokens indefinitely. |
| **In-memory session signal** (`AuthStore.session`) | Holds the live access token in the SPA. Must be wiped on logout so the SPA stops authenticating. |
| **LOGOUT audit trail** (`auth_events`) | Forensic record of session termination (who/when/where). Completeness matters for incident response and compliance. |
| **Access token (residual)** | Stateless JWT valid for ≤15 min post-logout (ADR-0008). Bounded-exposure asset. |

---

## 3. STRIDE threat table

| ID | Category | Description | Attack vector | Mitigation | Residual risk | Status |
|----|----------|-------------|---------------|------------|---------------|--------|
| **T-5.1** | Spoofing / Information Disclosure | Residual access-token validity: a previously-issued access token still verifies for ≤15 min after logout. | Attacker who exfiltrated the raw access token *before* logout (e.g. via prior XSS or log capture) continues calling protected APIs until the JWT expires. | Short 900 s TTL (US-003); refresh family revoked immediately in DB; `AuthStore.clearSession()` drops the SPA's copy instantly; `jti` denylist deferred and tracked in **ADR-0008**. | A ≤15-min window remains for a token stolen *before* logout. Accepted for GA. | **Accepted (ADR-0008)** |
| **T-5.2** | Tampering / DoS | Logout CSRF: a malicious site forces a logged-in user to POST `/logout`, ending their session (force-logout annoyance/DoS). | Cross-site auto-submitting form or `fetch` to `/api/v1/auth/logout` while the victim is authenticated. | Refresh cookie is `SameSite=Strict; Path=/api/v1/auth` — the browser will not attach it on a cross-site POST. Access token lives only in SPA memory (not auto-attached cross-site). Forged call cannot act on victim's session; endpoint impact is limited to the caller's own tokens only. | Negligible. `Strict` is sufficient (Gate 1 decision). | **Existing (mitigated)** |
| **T-5.3** | Information Disclosure | Token-less logout path leaks whether a refresh cookie was valid/known via differential response or timing. | Attacker POSTs `/logout` with guessed/forged `refresh_token` cookie and observes response differences to enumerate valid tokens. | `LogoutUseCase` returns the **same 204 + cookie-clear** for all four branches (valid bearer, valid cookie, malformed cookie, unknown cookie); no body, no distinguishing status. `LogoutUseCaseTest` §2.1 locks identical externally-visible outcomes for all branches. | Minor timing side-channel (hash + DB lookup occurs only when a cookie is present), not practically exploitable for enumeration at realistic request rates. | **Existing (mitigated)** |
| **T-5.4** | Tampering | AUTH_PATHS gap → session resurrection: a 401 from `POST /logout` triggers the interceptor's refresh branch, issuing `POST /refresh` and reviving the session the user is ending. | An expired access token at logout time returns 401; the unpatched interceptor reactively refreshes, re-establishing a valid session via `setSession`, racing `clearSession`. | Add `/api/v1/auth/logout` to `AUTH_PATHS` (§3.1) so `isAuthEndpoint` suppresses both proactive and reactive refresh on logout. Regression locked by `auth.interceptor.spec.ts` (§3.2) asserting `expectNone(/refresh/)`. | None once patched. | **New (this story)** |
| **T-5.5** | Denial of Service | Mass-revocation pressure: repeated logout calls force repeated `revokeByUserId` UPDATEs against `refresh_tokens` plus an `auth_events` INSERT each time. | Authenticated user (or holder of a stolen short-lived access token) scripts a high-rate logout loop to load the DB. | Existing auth-endpoint rate limiting; `revokeByUserId` is a single indexed UPDATE on `user_id` (idempotent — second call revokes nothing new); audit INSERT is small and append-only. | Low. Rate-limited authenticated abuse can generate audit-table writes; bounded by the rate limiter. | **Existing (mitigated)** |
| **T-5.6** | Spoofing | Stolen refresh cookie re-use in the race between the logout POST committing and cookie expiry propagating. | Attacker holding a copy of the raw refresh token calls `/refresh` concurrently with (or just after) the victim's logout, before revocation commits. | Revocation is committed inside `LogoutUseCase`'s single `@Transactional` boundary; once committed, every subsequent `/refresh` for that user-family returns 401 (revoke-by-user, not by-cookie — proven by the new `bearer_logout_revokes_tokens_across_multiple_families` IT). `Max-Age=0` cookie clear is defence-in-depth. Theft detection (`REFRESH_FAMILY_REVOKED`) covers replay of a rotated-out token. | Sub-second pre-commit race window; effectively closed by the atomic TX and the family-theft detection already in place. | **Existing (mitigated)** |

---

## 4. Control summary

| Control | Threats mitigated | Status |
|---------|-------------------|--------|
| Short access-token TTL (900 s) | T-5.1 | Existing |
| Immediate server-side refresh-family revocation (revoke-by-user, `@Transactional`) | T-5.1, T-5.6 | Existing |
| `AuthStore.clearSession()` wipes in-memory access token on logout | T-5.1 | Existing |
| `SameSite=Strict; Path=/api/v1/auth` on refresh cookie | T-5.2 | Existing |
| Uniform 204 + cookie-clear across all logout branches | T-5.3 | Existing |
| `LogoutUseCaseTest` 4-branch coverage (locks uniform behaviour) | T-5.3 | New (this story) |
| `/api/v1/auth/logout` in `AUTH_PATHS` (suppresses spurious refresh) | T-5.4 | New (this story) |
| `auth.interceptor.spec.ts` regression (`expectNone(/refresh/)`) | T-5.4 | New (this story) |
| Auth-endpoint rate limiting | T-5.5 | Existing |
| Idempotent indexed `revokeByUserId` UPDATE | T-5.5, T-5.6 | Existing |
| Refresh theft detection (`REFRESH_FAMILY_REVOKED`) | T-5.6 | Existing |
| `AuthAuditIT` Bearer/multi-family test (proves revoke-by-user) | T-5.6 | New (this story) |
| `jti` access-token denylist (Redis) | T-5.1 (fully) | Deferred — ADR-0008 fast-follow |

---

## 5. Residual risk acceptance

After all in-scope controls, the only material residual risk is **T-5.1**: an access token
exfiltrated *before* logout remains valid for up to its 15-minute TTL, because access tokens are
stateless (ADR-0007) and the `jti` denylist is deferred (ADR-0008). This is a **bounded,
short-lived** window that affects only an attacker who already compromised the access token through a
separate vector prior to logout. The durable refresh credential is revoked immediately, so the
session cannot be extended past that window.

This residual risk is **accepted for GA**. Re-evaluation is triggered by any of:
- a compliance or security audit mandating a revocation SLA shorter than the access-token TTL;
- an increase of the access-token TTL beyond 15 minutes;
- introduction of an admin "kill session now / log out everywhere" capability;
- adoption of Redis for any other reason (lowering the marginal cost of the `jti` denylist).

All other threats (T-5.2 through T-5.6) are mitigated by existing or new in-scope controls and
carry no accepted residual risk beyond negligible timing side-channels and rate-limited authenticated
abuse.
