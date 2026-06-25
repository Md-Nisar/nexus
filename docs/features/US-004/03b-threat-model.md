# US-004 Threat Model — Refresh sessions silently with rotating refresh tokens

Status: DRAFT — awaiting Gate 2 approval  
Author: Security Reviewer Agent  
Date: 2026-06-24  
Inputs reviewed: `docs/features/US-004/03-design.md`, `docs/features/US-004/01-requirements.md`,
`docs/features/US-003/03b-threat-model.md`, `nexus-frontend/src/app/core/http/auth.interceptor.ts`,
`core/auth/auth.store.ts`, `features/auth/auth.service.ts`, `app.config.ts`

Reviewer attestation: the proactive-refresh design (pre-request TTL check, interaction with the
existing `refreshInFlight` single-flight guard, reactive-401 fallback), the in-memory session
handling (`AuthSession`, no `localStorage`), and the cross-tab cookie-sharing assumptions were
reviewed. The backend rotation/theft-detection design is unchanged from US-003 and inherits its
threat model; this document covers **only the frontend proactive-refresh delta**.

---

## 1. Scope and Trust Boundaries

**In scope:** the new proactive branch of `authInterceptor`, the shared `refreshInFlight` guard
now driven by two entry points, and the `AuthStore.session().expiresAt` value the proactive check
reads.

**Out of scope:** the backend `POST /api/v1/auth/refresh` flow, rotation, theft detection,
optimistic locking, cookie attributes, and audit events — unchanged from US-003; those threats
are covered in `docs/features/US-003/03b-threat-model.md`.

| TB | Boundary | Untrusted side | What crosses it |
|----|----------|----------------|-----------------|
| TB-A | Browser JS runtime ↔ in-memory `AuthSession` | Page's own JS (and any XSS script) | `expiresAt`, `accessToken` |
| TB-B | Browser ↔ Backend `POST /auth/refresh` | Network client | `HttpOnly` refresh cookie (rotated each call) |
| TB-C | Tab ↔ Tab (same origin) | Concurrent tabs sharing the cookie jar | Shared refresh cookie |

**Key architectural facts that bound the model:**

- `expiresAt` is set server-side (`expiresIn` from the signed JWT response) and held **in memory
  only** — never `localStorage`/`sessionStorage`. An out-of-process attacker cannot set or
  persist it.
- The proactive path issues the **same** `POST /refresh` as the reactive path. No new endpoint,
  header, or token-transport surface is introduced.
- The refresh cookie is `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` (US-003) —
  unchanged.

---

## 2. STRIDE Analysis (proactive-refresh delta)

| ID | Name | STRIDE | Description | Mitigation | Residual | Owner |
|----|------|--------|-------------|------------|----------|-------|
| **T-1** | Proactive refresh as DoS amplifier | D — Denial of Service | Attacker tries to make `expiresAt - Date.now() < 120_000` evaluate true on every request, causing the client to fire `POST /refresh` continuously. | `expiresAt` is set server-side from the signed JWT's `expiresIn` and held **in memory only** — no `localStorage`, so it cannot be set from outside the JS process. The only lever is the attacker's own device clock; skewing it forward is a self-DoS with no leverage on others. After a successful refresh, `expiresAt` jumps ~15 min into the future, bounding the rate to at most one refresh per token lifetime, not per request. Backend per-IP throttle on `/auth/refresh` (30 refresh / 5 min / IP from US-003 `LoginRateLimitFilter`) caps the blast radius. | **Low** | Backend (existing rate limit) |
| **T-2** | Thundering herd across tabs/requests triggers spurious family revocation | T / D — Tampering + DoS | Multiple in-flight requests (or multiple tabs) all observe TTL < 2 min and POST `/refresh` simultaneously. Each successive rotation invalidates the previous token; a second refresh presenting an already-rotated token trips theft detection and revokes the whole family. | **In-tab:** `refreshInFlight` guard (`shareReplay(1)`) guarantees exactly one `POST /refresh` per concurrent burst, shared by both the proactive and reactive entry points. **Cross-tab:** both tabs share the same `HttpOnly` cookie jar; once Tab A rotates, the browser stores the new cookie, so Tab B's next refresh presents the *rotated* cookie (not the stale one) — no reuse, no false revocation. **Same-millisecond race:** if both tabs fire inside the optimistic-lock window, the server's `@Version` lock yields one winner and one `AUTH_004` — the loser presented the *original* (not a revoked) token, so it is a benign rotation conflict, not family revocation. | **Low** (documented & accepted) | Frontend (`refreshInFlight`); Backend (`@Version`); Browser (cookie sharing) |
| **T-3** | Token exfiltration via proactive retry | I — Information Disclosure | The proactive path attaches the Bearer access token to the forwarded original request's `Authorization` header. Does this create new exfiltration surface? | No new surface. The proactive path sends the Bearer token on the same request the interceptor already sends today; the token is fresher, not differently routed. The refresh cookie remains `HttpOnly` (unreadable by JS) and `SameSite=Strict`. No token is written to storage, URL, or log (the optional `debug` logs carry `msRemaining`/`reason` only, never the token). | **Low** (N/A — no new surface) | Frontend |
| **T-4** | CSRF on `POST /auth/refresh` | S — Spoofing | Attacker page tricks the browser into POSTing to `/api/v1/auth/refresh` to force a rotation or ride the victim's cookie. | Unchanged from US-003. The refresh cookie is `SameSite=Strict`; the browser does **not** attach it to any cross-site POST. A forged `/refresh` arrives with no cookie and fails `AUTH_004`. US-004 adds no cross-origin capability. | **Low** | Backend (`SameSite=Strict` in `LoginController`) |
| **T-5** | Infinite refresh loop on non-401 refresh failure | D — Denial of Service | If `POST /refresh` returns 500 or 429 (not 401), the proactive path could re-enter and refresh endlessly. | The proactive branch's `catchError` calls `authStore.clearSession()` and navigates to `/auth/login`, then rethrows — **terminating** the chain. After `clearSession()`, `authStore.session()` returns `null`, so on any subsequent request `proactive = (session !== null && …)` evaluates **false**; the branch is never re-entered. Additionally, `AUTH_PATHS` excludes `/api/v1/auth/refresh`, so the refresh call itself never triggers a nested proactive refresh (primary loop guard). `finalize(() => refreshInFlight = null)` ensures a failed refresh does not wedge the guard. | **Low** | Frontend (`catchError` + `AUTH_PATHS` + `finalize`) |

---

## 3. Threats Requiring Design Changes

**None.** Every threat above is mitigated by existing controls (backend rate limiting, `@Version`
optimistic lock, `SameSite=Strict` cookie) or by the design as written (the `AUTH_PATHS`
exclusion, the shared `refreshInFlight` guard, the proactive `catchError` → `clearSession` +
login). No change to `03-design.md` is required to close a threat.

---

## 4. Residual-Risk Summary

No **High** or **Medium** residual items for US-004.

| Threat | Residual | Note |
|--------|----------|------|
| T-1 DoS amplifier | Low | `expiresAt` in-memory + server-derived; backend rate limit caps blast radius |
| T-2 Thundering herd → false revocation | Low (accepted) | Worst case is a benign `AUTH_004` on a same-millisecond cross-tab race, never a family revocation; documented in design §8 |
| T-3 Exfiltration | Low | No new surface over the existing reactive path |
| T-4 CSRF | Low | `SameSite=Strict` unchanged; US-004 adds no cross-origin capability |
| T-5 Infinite loop | Low | Terminated by `clearSession` (session becomes `null` → `proactive = false`) and the `AUTH_PATHS` exclusion |

US-004 **inherits** all US-003 backend residuals unchanged (notably T-3.9 access-token
irrevocability within the 15-min TTL, and T-4.6 `refresh_tokens` table growth) — those are
tracked in `docs/features/US-003/03b-threat-model.md`.

---

## 5. Required Security Tests

| Threat | Required test | Type |
|--------|---------------|------|
| T-2 | Two concurrent requests with `expiresAt - now < 120_000` → exactly **one** `POST /api/v1/auth/refresh`, both originals retried with the new token | Unit (Vitest + `HttpTestingController`) |
| T-2 | Proactive refresh in flight + a concurrent reactive 401 → still one shared `POST /refresh` (cross-path guard) | Unit |
| T-5 | Proactive refresh returns 500/429 → `clearSession()` called, `router.navigate(['/auth/login'])` called, original error rethrown; the **next** request takes the non-proactive path (`session == null`) | Unit |
| T-5 | `POST /api/v1/auth/refresh` itself is never subjected to a proactive refresh (matches `AUTH_PATHS`) — no nested refresh call | Unit |
| T-1 | After a successful proactive refresh, a following request does **not** re-trigger proactive refresh (new `expiresAt` is ~15 min out) | Unit |
| T-1 / TS-1 | Idle past the access-token TTL boundary, then act → action succeeds, no login prompt, exactly one `POST /refresh` | E2E (Playwright) |
| T-3 | No log line or storage write during a proactive-refresh cycle contains the access token, refresh cookie, or email | Unit (log spy + `localStorage`/`sessionStorage` assertion) |
