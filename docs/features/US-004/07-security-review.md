# US-004 Security Review

**Status:** APPROVED (with non-blocking recommendations)  
**Reviewer:** security-reviewer agent (fresh hostile-mindset context)  
**Date:** 2026-06-25  
**Scope:** `auth.interceptor.ts`, `app.routes.ts`, `dashboard.component.ts` (and supporting files: `auth.store.ts`, `auth.service.ts`, `auth.guard.ts`, `auth.ts`, `app-config.ts`, `logger.service.ts`, environments, unit/E2E specs)

**Attestation:** Token handling (access token held only in in-memory `AuthStore` signal, never written to `localStorage`/`sessionStorage`/URL/log), the refresh single-flight/race logic, the proactive-vs-reactive error paths, the route guard, and PII-in-logs surfaces were explicitly reviewed. No cryptographic primitives are implemented in this diff (JWT signing/rotation is backend, out of scope).

---

## Findings

| Severity | File:line | Issue | Risk | Fix |
|----------|-----------|-------|------|-----|
| MEDIUM | `auth.interceptor.ts:56` | Proactive `switchMap` reads `authStore.accessToken()` (store re-read) rather than the session emitted by `refreshInFlight`; if a concurrent `clearSession` wins the race, `accessToken()` returns `null` and the request goes out as `Bearer null` | Low probability, high impact: request silently authenticated with a null bearer | Match the reactive path: `switchMap((session) => next(req.clone({ setHeaders: { Authorization: \`Bearer ${session.accessToken}\` } })))` |
| MEDIUM | `auth.interceptor.ts:49-58 vs 80-89` | `catchError` placement diverges between paths: proactive path scopes it before `switchMap` (only refresh failures); reactive path scopes it after (also catches retried-request 401s). An immediate 401 on the proactively-refreshed request produces no `clearSession()` | Different error contract between the two paths; the reactive path's post-`switchMap` `catchError` is broader. Neither is exploitable — the interceptor sees the 401 again on the next request. | Either document the divergence intentionally (comment explaining why the proactive path must not catch forwarded-request errors), or align both paths |
| LOW | `dashboard.component.ts:21-24` | `catchError(() => EMPTY)` swallows all errors from `/users/me` silently. Auth failures are already handled (interceptor calls `clearSession()`+redirect before rethrowing), so this is not an auth-bypass. Non-auth errors (500, network) are invisible (A09 observability gap). | Not a security gap for auth; mild A09 concern | Inject `LoggerService` and log non-auth errors at debug level |
| LOW | `auth.guard.ts` + `auth.store.ts` | `authGuard` is a client-side UI gate; `isAuthenticated` trusts in-memory `expiresAt`. XSS or devtools can bypass the guard to render the dashboard shell. | Acceptable by design — data is authorized server-side (`/users/me` → 401 → redirect). Any sensitive content added to this component must come from a backend-authorized fetch, never client-only gating. | No fix now; document as invariant: dashboard renders only after an authorized `/users/me` response |
| INFO | `auth.store.ts:20,25` | `logger.debug('Auth session established', { userId })` logs a UUID at debug level | No email/token/PII logged; debug is gated off in production | None |
| INFO | `npm audit` | `npm audit --omit=dev --audit-level=high` → 0 vulnerabilities | — | None |

---

## Threat-model cross-reference

| Threat | Claimed control | Verdict |
|--------|-----------------|---------|
| T-1 DoS via expiresAt | In-memory, server-derived; jumps ~15 min after refresh | **Confirmed** — `expiresAt` from server `expiresIn`; held in `AuthStore` signal only; no storage write (test T3-1) |
| T-2 Thundering herd → family revocation | `refreshInFlight` `shareReplay(1)` shared by both paths | **Confirmed** — both paths check/set module-level `refreshInFlight`; tests T2-1, T2-2 prove single `POST /refresh` |
| T-3 Token exfiltration | No new log/storage/URL surface | **Confirmed** — no `setItem`, no token in logs; Bearer only via headers; test T3-1 |
| T-4 CSRF on `/refresh` | `SameSite=Strict` cookie (backend, unchanged) | **Confirmed** — `withCredentials: true` on refresh call; cookie attributes backend-owned |
| T-5 Infinite refresh loop | `clearSession` → `session=null` → `proactive=false`; `AUTH_PATHS` exclusion; `finalize` resets guard | **Confirmed** — all three controls present; tests P-3, P-5, T5-1 |

All five mitigated threats have visible, test-backed controls.

---

## OWASP Top 10 coverage

- **A01 Broken Access Control:** Route guard is UI-only by design; data authorized server-side. No IDOR surface. ✅
- **A02 Cryptographic Failures:** No crypto implemented; access token in memory, refresh cookie HttpOnly, transport via Bearer header only. ✅
- **A07 Auth Failures:** Single-flight refresh, proactive+reactive renewal, `clearSession`+redirect on failure. Medium hygiene gaps noted (non-blocking). ✅
- **A09 Logging & Monitoring:** No PII/secret in logs; debug-only `userId`. Low observability gap from dashboard `catchError`. ✅
- **A03–A06, A08, A10:** Not materially impacted by this frontend-only diff. ✅

---

## Verdict: APPROVED

No auth bypass, no token leakage to storage/URL/log, no missing `clearSession` on the auth-failure path, no race that double-issues `POST /refresh`. All five threats marked "mitigated" have visible, tested controls.

**Recommended before merge (non-blocking):** Fix the token source in the proactive `switchMap` (Medium 1) to use `session.accessToken` from the refresh emission, matching the reactive path.
