# US-020 — STRIDE Threat Model: RBAC Access Management console

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** An adversarial STRIDE pass over `03-design.md` (Draft 1, 2026-10-23, commit `741d369`) and the two ADRs it proposes (0028, 0029). It is organised by component and trust boundary, so each slice's PR (S1a to S3b) can trace its own threats. It feeds `/breakdown` (Phase 4)._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-020 · **Reviewer:** Application Security Engineer · **Status:** **Conditional pass, not closed.** Two Medium findings and three Low findings need design text changes (§6) before Gate 2 closes. No Blocker and no High. Five Low items land as tasks (§7). Three items need a human decision (§9).

No PII. People are referred to by role. Persona addresses and dev credentials are not repeated.

Legend in tables: **OK** addressed as designed · **GAP** partly addressed · **CHANGE** design change required · n/a.

---

## 0. Scope, verification basis, headline

### 0.1 Scope

This pass covers every component and trust boundary that US-020 adds or changes:
- the `authGuard` cold-start change and `UnavailableState`;
- the `/unavailable` route under `PublicLayout`, and the widened public-route pin;
- `safeReturnUrl` and `returnUrl` handling;
- `anyPermissionGuard`, `accessConsoleEnabledGuard`, any-of nav, the dashboard card and the kill switch;
- `AuthorizationProfileStore` and affordance prediction;
- the save flow (ETag, `If-Match`, 412 rebase, 428, retry-once, 401 replay, double submit) and create/clone;
- assign and revoke (self-revoke, last administrator, PENDING targets, 429);
- the nginx `gzip off` change, the edge assumptions and the edge smoke job;
- rendering of user-authored text (stored XSS, bidi and look-alike spoofing);
- PII in the DOM, logs, URLs and Playwright artifacts;
- `sessionStorage` drafts;
- dev personas and seeding;
- `RBAC_001` reason disclosure (RES-47);
- the CSV export deferral.

The backend is unchanged (design decision 1). Backend facts are used only where the console depends on them. The Gate 1 decisions (`01-requirements.md` §12a) are not reopened. Where a finding touches one (Q21), it concerns the implementation, and the decision itself goes to its owner (§9).

### 0.2 Verification basis

**Rule applied (per `/design`):** a fact that US-018 or US-019 verified in code is trusted unless `git log -- <path>` shows the file changed since. US-019's Phase 7 review (`docs/features/US-019/07-security-review.md`) read the merged code at `946d771`, which merged as `adda702`. `git log` shows only documentation commits after `adda702` (`d35d334` to `741d369`). `git diff --stat adda702` on `package.json`, `package-lock.json` and `pom.xml` is empty. So the following US-019 facts stand and are cited, not re-read:
- the epoch filter order (B-8, B-9);
- B8's check order and strong-tag rule (B-2, B-3, RC-55, RC-58);
- `CorrelationIdFilter`;
- directory tenant predicates and miss equivalence (US-019 C1, C2);
- `resolveRoleInTenant`;
- RC-59 handlers;
- RC-62 (Angular upgrade and ESLint sink ban);
- RC-63(g) (seeder `!prod`);
- RC-63(h) (CI artifact scan).

The table lists what US-020 newly depends on, each re-read in this session.

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| 1 | `authGuard` treats only `AUTH_005` and `NETWORK_ERROR` as "unavailable" and calls `AuthService.refresh()` directly | `auth.guard.ts:7-10, 34-43` | **Confirmed.** The guard does not use the interceptor's `sharedRefresh`. RC-65 was closed by dropping `canActivateChild` (`app.routes.spec.ts:123-135`), not by extracting a shared refresh service |
| 2 | `refresh()` is POST `/auth/refresh` **then** GET `/users/me` | `auth.service.ts:172-183, 192-196` | **Confirmed.** A cold-start `AUTH_005` comes from the `fetchMe` leg **after** the cookie has rotated, so a Retry presents the new cookie (no reuse). This supports design §0.4 #1 |
| 3 | Refresh reuse has no grace window | `RefreshTokenUseCase.java:47-52, 164-167` | **Confirmed.** A revoked token revokes the family and writes `TOKEN_REFRESH_REUSE`. This matters when a refresh response is lost after the rotation committed (T-R19) |
| 4 | `HTTP_ERROR` is any non-problem-document response; a problem document needs only a string `code` | `api-error.interceptor.ts:93-127, 162-166` | **Confirmed.** `retryAfterSeconds` is parsed only for problem documents, so nginx's HTML 429 yields no wait (T-D31) |
| 5 | Interceptor failure log | `api-error.interceptor.ts:42-56` | Logs `req.url` and `HttpErrorResponse.message`, which contains `urlWithParams`. The console never puts an email in a URL (lookup is a POST body), so this is clean for the designed paths |
| 6 | `safeReturnUrl` does no decoding; `/auth` is rejected by literal prefix | `safe-return-url.ts:8, 24-40` | **Confirmed.** The router decodes path segments, so a literal-prefix rule misses `/%75navailable` (and today `/%61uth/…`) (T-T26) |
| 7 | Public children pinned to exactly three; no `canActivateChild` | `app.routes.ts:46-100`; `app.routes.spec.ts:100, 116-121, 123-135` | **Confirmed** |
| 8 | Redaction is by context **key** only; `message` and `operation` strings are not scrubbed | `logger.service.ts:25, 37-56, 111-130` | **Confirmed.** `GlobalErrorHandler` puts `JSON.stringify(error)` of a non-`Error` object (every `AppError` is a plain object) into the message string (`global-error-handler.ts:31, 57-66`) (T-I27) |
| 9 | Logout clears the session in `finalize`; `clearSession` is a signal reset only | `auth.service.ts:156-160`; `auth.store.ts:74-77`; refresh-failure path `auth.interceptor.ts:193-197` | **Confirmed.** No `sessionStorage` use exists in `src/app` today (grep), so the `nexus.session.` sweep has no collateral |
| 10 | nginx | `nginx.conf:9-10` (auth zone 10 r/min per IP, `limit_req_status 429`), `:26` (CSP `connect-src 'self'`, `frame-ancestors 'none'`), `:28-30` (gzip JSON ≥ 1 kB), `:35-42`, `:45-51` (`/api/` has no `add_header`, so server-level security headers are inherited) | **Confirmed** as the design states. `gzip off` inside `/api/` removes nothing security-relevant |
| 11 | Revoke propagation (Q3) | `RoleAssignmentService.java:456-475` (evict, then `invalidateUser` in `afterCommit`); `PermissionFreshnessService.java:1055-1065` (a failed bump is caught and queued), `:1093` ("the 204 waits for every batch"); replace `RoleManagementService.java:940-970` (removes bump holders; adds-only evict caches); assign evicts (`RoleAssignmentService.java:207`); TTLs `application.yml:157` (cache, env-overridable), `:192` (fail-open window), `:269` (token) | **Confirmed with conditions** (§4.3) |
| 12 | PENDING accounts | `LoginUseCase.java:227-229` (PENDING cannot sign in); `RegisterUserUseCase.java:103-110` (a duplicate registration is acknowledged silently, so the first registrant's password stays); `RegisterRequest.java:15` (`@Email`); `EmailBlindIndexService.java:38` (`trim → NFC → lowercase` only) | **Confirmed.** An unverified account carries a password chosen by whoever registered the address (T-E55). NFC folds neither format characters nor confusables (T-S15) |
| 13 | Dev seed guard | `DevDataInitializer.java:34`, `DevUserSeeder.java:28`, `DevRbacSeeder.java:26` (`dev & !break-glass & !prod`); `DEV_SEED_ACTIVE` WARN `DevDataInitializer.java:63`; compose runs `dev` (`docker-compose.yml:102`) | **Confirmed** (RC-63(g) landed) |
| 14 | CI artifacts | `e2e-full-stack.yml:4-7, 20` (`pull_request`, read-only); `:106-125` (PII scan over logs, report, results and test-results; upload only if the scan passed; 7-day retention); `playwright.config.ts:16-23` (trace on first retry, screenshots off in CI, video default off) | **Confirmed.** Upload is gated on the scan, so a PII leak fails closed (no artifact) |
| 15 | Lookup field cannot put the email in a URL | `search-field.ts:8-14` (submit mode emits on Enter; no `<form>`) | **Confirmed.** No native GET form submission and no form-history autofill path |
| 16 | Correlation id randomness | `correlation-id.interceptor.ts:27` (`crypto.randomUUID()`) | **Confirmed.** Safe to show as "Reference" (AS-8) |
| 17 | `npm audit --omit=dev` | Ran this session | **0 findings.** RC-62 landed (`@angular/core` 22.2.3). Full graph: 2 findings (1 high, 1 low): `vite` 8.3.0–8.3.2 through `@angular/build` (dev server and toolchain only; RES-60) |
| 18 | `./mvnw -o dependency:tree` | Ran this session | **No manifest delta.** Boot 4.1.1, Tomcat 11.0.26, BC 1.86, jjwt 0.12.6, Lettuce 7.5.2, Connector/J 9.7.0, Jackson 3.1.5 (and 2.21.5 transitively via jjwt), springdoc 3.0.3: the US-019 baseline. The design adds no dependency |

**Not verified (marked where used):**
- nginx weakening strong ETags on gzip (AS-1, **[INFERENCE: nginx documentation]**). The edge smoke job is the control either way.
- Hibernate Validator's `@Email` local part admitting `\u0080-￿`, and therefore Unicode format characters (**[INFERENCE: Hibernate Validator pattern]**; T-S15 asks for a test that settles it).
- Angular's `DefaultUrlSerializer` decoding path segments before matching (**[REPORTED framework behaviour]**; T-T26's test settles it).

### 0.3 Headline

**The design is security-literate, and its riskiest moves hold up.** These survived direct attack (§4):
- The **`/unavailable` route** is static, makes no HTTP call, keeps the reference out of the URL and cannot trigger an action. The pin widening is safe (SD-2).
- **Fail-closed in every guard branch** (SD-3). The narrow reclassification sends only "nobody authoritative answered" to the view. Every backend problem document still goes to login.
- **One refresh per attempt** (SD-4). The console never calls `AuthService.refresh()`. Own-access events go through the interceptor's shared refresh. Retry is user-initiated.
- **ETag discipline** (SD-8, SD-9). Strong tags only, echoed verbatim; weak or missing tags are detected before work is staged; 412 never resubmits; restored drafts always use the current tag.
- **Retry-once** is scoped to `RBAC_012` on two verbs and is safe on both (SD-10). I accept RES-53 including the defensive PUT case.
- **401 replay** of PUT, POST assign and DELETE revoke is their first execution (SD-11).
- **No client lockout prediction** (SD-18), **no `memberCount` predictor**, **mirror-only grant rules** (SD-19).
- **Q3's revoke copy is accurate** (§4.3).

**What does not survive, in order of consequence:**
1. **Email display spoofing** (**T-S15, Medium**). Emails are self-asserted and may carry Unicode format characters (bidi overrides, zero-width). `<bdi>` isolates the string from its surroundings, but it does not neutralise an override **inside** the string. An address can therefore render the same as a colleague's. This is the screen where an administrator picks who gets a role.
2. **Assignment to PENDING accounts** (**T-E55, Medium**). The server allows it (Q21). An unverified account's password belongs to whoever registered the address. A duplicate registration is acknowledged silently, so the real owner cannot reset it by registering. If the real owner later clicks the verification link, the account becomes ACTIVE **with the registrant's password and the role the administrator assigned**. The design's warning copy does not convey this.
3. Five Low items: `safeReturnUrl` bypass by percent-encoding (T-T26); lost-response refresh reuse made reachable by the new Retry (T-R19); the edge smoke's negative control tripping the design's own alert, and its credentials outside CI (T-R20); `GlobalErrorHandler` serialising `AppError` past key-based redaction (T-I27); another user's drafts lingering in the same tab (T-I28).

**Verdict:** conditional pass. Gate 2 can close once RC-68 to RC-72 are folded into the design (§6). RC-73 to RC-77 land as tasks (§7). No Gate 1 decision is reopened. Q21 has a human question attached (§9).

### 0.4 Attestation (auth, crypto and PII are never approved silently)

- **Authentication: reviewed. No new mechanism.**
  - Sound: the `authGuard` change is fail-closed in every branch. It keeps one refresh per activation, with no `canActivateChild`. `AUTH_005` on cold start arrives after rotation (§0.2 #2), so Retry does not reuse a token. The console never refreshes on its own (ADR-0028). 401 replays run once.
  - Gaps: a lost refresh response followed by Retry is a reuse (T-R19, Low, accepted with RC-71). The `returnUrl` rule needs RC-70.
- **Authorization: reviewed.** Every affordance is UX only, and every server refusal is handled inline.
  - Sound: `anyPermissionGuard` fails closed. Every child carries its own `permissionGuard`. The kill switch uses `canMatch`, which runs no auth and is config-only. Tenant isolation is entirely server-side: tenant comes from the JWT, ids in paths resolve within the tenant (US-019 C1, `resolveRoleInTenant`), and missing and foreign ids get the same copy.
  - Client caches are route-scoped and reset on user change. Drafts are keyed by user id.
  - Gaps: PENDING targets (T-E55); a stale restored intent (T-E56, Low).
- **Cryptography: reviewed. No findings.** No key, algorithm or randomness change. The ETag is a concurrency token, not a capability (ADR-0027). The correlation id uses `crypto.randomUUID()`.
- **PII: reviewed against the no-PII rule.**
  - Sound: emails appear only in the DOM of `user:directory:read` holders. They are kept out of titles, toasts, history, URLs and logs by design. The e2e artifacts are gated by the scan.
  - Gaps: T-I27 (message-string serialisation past redaction); T-I28 (another user's draft ids in the same tab).
  - Spoofing through email content: T-S15.
  - DPO acknowledgement (Q22) is unchanged and remains a release blocker.
- **Secrets: reviewed.** No new secret. The edge smoke job must not run with an administrator credential outside CI (RC-72). Dev persona credentials remain dev-only (RC-63(g) confirmed; RES-57).

### 0.5 Numbering

This continues the epic sequence. US-019 ended at T-S14, T-T25, T-R18, T-I26, T-D30, T-E54, RC-67 and RES-53. **US-020 starts at T-S15, T-T26, T-R19, T-I27, T-D31, T-E55, RC-68 and RES-54.** The design's "SD-n" labels (§21) are kept and given verdicts in §4. The design uses "RC-63(i)" and "RC-65" as US-019's ids.

---

## 1. Trust boundaries and data flow (what US-020 adds or changes)

```
[ Internet: anonymous client -- self-registers into the DEFAULT tenant with any @Email string,
  stays PENDING until the mailbox owner clicks verify; a duplicate registration is silently
  acknowledged (T-E55); the string may carry \p{Cf} (bidi overrides, zero-width) (T-S15)       ]
[ Signed-in tenant user (bearer in memory; refresh cookie HttpOnly; permissions[] <= 900 s stale) ]
=== TB8 browser (the console) ===================================================================
  Router: '' redirect | PublicLayout {auth, access-denied, design-system, unavailable*}  <- SD-2
          | Shell canActivate authGuard (refresh() direct; POST /refresh then GET /users/me)
              NETWORK_ERROR | HTTP_ERROR* | AUTH_005  -> UnavailableState (memory) -> /unavailable?returnUrl
              backend problem document              -> /auth/login?returnUrl
            admin/access  canMatch accessConsoleEnabledGuard (config only) -> canActivate anyPermissionGuard
              children: permissionGuard(data.permission)   (JWT AuthStore = nav + guards)
              AuthorizationProfileStore (live GET /users/me/authorization = affordances)
  /unavailable: no HTTP; Retry after cool-down -> navigateByUrl(safeReturnUrl(returnUrl))  <- T-T26, T-R19, T-D31
  Rendering: interpolation only, <bdi>/dir=auto; emails, descriptions are attacker-chosen   <- T-S15
  sessionStorage nexus.session.access-draft.v1.<userId>.<roleId> {ids, baseEtag, savedAt}    <- T-I28, T-E56
  LoggerService (key-based redaction) <- GlobalErrorHandler JSON.stringify(AppError) in message <- T-I27
  Interceptors: correlation-id -> api-error (403 redirect skipped by console context) -> auth (shared refresh, 401 replay)
  RbacApi: PUT If-Match (strong, verbatim) | POST assign | DELETE revoke | retry-once RBAC_012
=== TB-EDGE (new focus): CDN / LB (unknown, Ops) -> nginx frontend container =====================
  /api/v1/auth/: limit_req 10 r/min/IP, burst 10, HTML 429 (-> HTTP_ERROR -> /unavailable)
  /api/: gzip off* (ADR-0029)   ETag strong must survive; If-Match must pass through
  edge-etag-smoke.mjs --base <env>: login, GET set, PUT system role -> 409 RBAC_003, PUT W/ -> 428  <- T-R20
=== TB1..TB5 backend (unchanged; US-019 03b §1) ==================================================
  JwtAuthenticationFilter: epoch before handler (401 replay = first execution; 503 AUTH_005 applies nothing)
  B8 PUT: 428 at controller; 404, 409 RBAC_003, 404, 403, 412, no-op; afterCommit bump/evict holders
  assign/revoke: A2..A4 + RBAC_002 under set lock; afterCommit evict + epoch bump (revoke)
=== TB7 dev / CI =================================================================================
  Dev seed (dev & !break-glass & !prod): + role-reader user manager (directory + assign), + auditor,
  + 2 non-sign-in targets   <- T-E58
  e2e-full-stack: pull_request, read-only; PII scan gates upload; new edge-etag-smoke job (nginx in loop)
```
`*` marks a change made by this design.

---

## 2. STRIDE tables, per component

### C1 — `authGuard` cold-start change and `UnavailableState` (S1b)

| | Threat | Verdict |
|---|---|---|
| **S** | A forged or intermediary response makes the guard admit a signed-out user | **OK.** Every error branch returns a `UrlTree` (to `/unavailable` or `/auth/login`). Only a successful `refresh()` (POST plus `/users/me`) returns `true`. A captive portal's 200 HTML fails JSON parsing, which gives `HTTP_ERROR` and denial |
| **S** | Retry causes a second, concurrent refresh (RC-65 reuse) | **OK.** The view makes no HTTP call. Retry is a user click that re-enters the shell once. No `canActivateChild` (`app.routes.spec.ts:123-135`). Nothing else in the public subtree issues requests (asserted by §19.1's real-Router spec). Cross-tab concurrent cold starts are pre-existing (RES-55) |
| **S** | Lost refresh response (gateway 504, or a dropped connection after commit), then Retry presents the rotated-away cookie | **GAP: T-R19 (Low).** Family revocation and a false `TOKEN_REFRESH_REUSE`. The outcome is fail-closed (login) |
| **T** | `AUTH_005` spoofed by an intermediary to keep a user on the view | **OK.** Only availability is affected. A problem document needs a string `code`, so an intermediary can make the guard show "unavailable" or "login", never "allow" |
| **R** | The guard decision leaves no trace | **OK.** `auth_guard_unavailable` warn with code and `correlationId` (§17) |
| **I** | `traceId` or other error detail in the URL | **OK.** `UnavailableState` is in memory only (design §4.5; `app-error.ts:44`) |
| **D** | Retry storms against nginx's auth zone after an outage (shared NAT), HTML 429 with no `Retry-After`, and each Retry consuming the refresh family bucket | **GAP: T-D31 (Low)** |
| **E** | — | n/a. No branch grants access |
| **X** | — | n/a. No tenant data |

### C2 — `/unavailable` route, `UnavailablePage`, `UnavailableNotice`, and the public-route pin (SD-2)

| | Threat | Verdict |
|---|---|---|
| **S** | A crafted link shows a fake "Nexus is unavailable" page and steers the user | **OK (Low, accepted).** The content is static copy. The reference comes from memory, so a link cannot inject text. "Go to sign-in" leads to the real login page with a re-validated `returnUrl`. The worst case is a nuisance |
| **T** | The view is used to trigger an action (CSRF-like) | **OK.** No HTTP on render, no auto-retry, and no route mutates on activation (SD-17). Retry only navigates in-app |
| **T** | A future public child is added unguarded by mistake | **OK.** The pin is widened deliberately to exactly four paths and stays exact-match (`app.routes.spec.ts:116-121`). **Security sign-off on the widening: granted**, conditional on RC-70 and the §19.1 specs (no `HttpClient` injected; no request while on the view) |
| **R** | — | n/a |
| **I** | The view reveals session state | **OK.** The copy says "may still be valid". It reveals nothing a signed-out visitor could not infer |
| **D** | Reloading `/unavailable` loses `UnavailableState`, so the countdown is gone and Retry is enabled at once | **GAP (Low), folded into T-D31.** RC-75 defines the empty-state behaviour |
| **E** | The view under `PublicLayout` inherits gated `data` | **OK.** `PublicLayout` has no `data` or guard (`app.routes.ts:46-50`), and the view carries only `selfManagedFocus` |

### C3 — `safeReturnUrl` and `returnUrl` (SD-5)

| | Threat | Verdict |
|---|---|---|
| **T** | Open redirect through the view's `returnUrl` | **OK.** `navigateByUrl` cannot leave the origin. `safeReturnUrl` checks the origin, rejects `//`, `\`, controls and `:` before `?`/`#`, and does no second decode (`safe-return-url.ts:24-40`) |
| **T** | `/unavailable` loop through an encoded first segment (`/%75navailable`, also `/%61uth/login` today) | **CHANGE: T-T26 (Low).** Harmless (an in-app loop on click), but the adversarial table's expectation is wrong unless the rule is segment-based |
| **I** | `returnUrl` carries search text into history | **OK.** Only role and catalogue `q` (role names are ASCII, not PII). The email lookup text never enters the URL (§0.2 #15) |

### C4 — `anyPermissionGuard`, `accessConsoleEnabledGuard`, nav, dashboard card, kill switch (S1a)

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a |
| **T** | A misconfigured `data.anyOf` admits everyone | **OK.** Fails closed on a missing, empty or non-catalogue value, with a contract spec (design §4.3). Stricter than `permissionGuard` (RES-39 unchanged) |
| **T** | Inherited `data.anyOf` misread as `data.permission` | **OK.** `permissionGuard` reads only `data.permission`, and every child declares its own (`app.routes.spec.ts` walks lazy children) |
| **I** | The kill switch leaves the console chunk in the bundle | **OK.** Code, not data. APIs are gated server-side |
| **D** | — | n/a |
| **E** | Client gating trusted | **OK.** UX only. The server enforces every call (SD-1) |
| **E** | A later edit makes a `canMatch` on a shell descendant read `AuthStore`. `canMatch` runs during recognition, before the shell's `authGuard` restores the session | **GAP: T-E57 (Low).** Today it reads config only. Pin that |
| **E** | The kill switch is treated as a security control | **GAP: T-E57 (Low).** It is a release control. APIs stay live behind their backend flags. Say so in ADR-0028 and §18 |

### C5 — `AuthorizationProfileStore` and affordance prediction (SD-1, SD-15)

| | Threat | Verdict |
|---|---|---|
| **S** | The profile of user A is used after user B signs in, in the same tab | **OK.** Route-scoped. Every exit from the console (logout, refresh failure to `/auth/login`) destroys it. It also resets on `currentUser().userId` change |
| **T** | A predicted "allow" is wrong (stale profile) | **OK.** The server is final. A predicted-allow 403 re-reads the profile, keeps the work and shows the reason (design §6.3) |
| **R** | — | n/a |
| **I** | The profile exposes more than the caller's own data | **OK.** An identifier-free self read (US-019 C3) |
| **D** | Reload loops | **OK.** Coalesced, no polling. Reloads happen on own-access events and predicted-allow 403s only, and each is a user action |
| **E** | A console-initiated refresh races the interceptor (RC-65) | **OK.** The console never calls `AuthService.refresh()` (spy spec, §19.1). The self-revoke path goes through the shared 401 refresh (`auth.interceptor.ts:188-191`, `:63-75`) |
| **E** | Nav (JWT) lags the profile after a grant | **OK, accepted (RES-59).** At most the token TTL, and affordance only |
| **X** | — | **OK.** Self-only endpoint; tenant from the JWT |

### C6 — Save flow: `RbacApi` PUT, ETag, 412, 428, retry-once, 401 replay, double submit; create and clone (S2)

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a (bearer only; CSRF n/a for a bearer API, US-019 C2) |
| **T** | Lost update through a weak or stripped tag | **OK.** The client classifies strong, weak or missing before staging. The server refuses anything but exactly one strong tag (B-2). RC-55 fixed the membership comparison |
| **T** | 412 auto-resubmit or a blind rebase resurrects an upstream removal | **OK.** Rebase is intent-based (§8.2), so an upstream removal the user did not touch stays removed. Every rebase needs a new Review and Save |
| **T** | Retry-once re-applies a mutation | **OK.** A 409 `RBAC_012` applied nothing (assign rolls back). The PUT path is unreachable today and would be harmless, because the same `If-Match` can succeed only against the same version. At most one retry; never on 403, 412, 429 or 503 (RES-53 accepted, §4.4) |
| **T** | 401 replay runs a mutation twice | **OK.** The filter rejects before the handler (B-8, verified by US-018/019; file unchanged), so the replay is the first execution. This holds for PUT, POST assign and DELETE revoke |
| **T** | Double submit | **OK.** `loading` ignores repeats and dialogs `disableClose`. Server convergence covers what remains: PUT twice gives 412 then "already in place"; assign twice gives `RBAC_004`; revoke twice gives 404 "already removed"; create twice gives `RBAC_006` |
| **T** | A restored draft or rebased intent contains adds the caller may no longer grant | **GAP: T-E56 (Low).** The server answers 403, and the UI shows a staged state for a disabled row |
| **R** | Saves are not attributable | **OK.** Server inline audit (ADR-0024, US-018 A6). The client shows the reference |
| **I** | Error-code oracles beyond RES-47 | **OK.** 403 precedes 412 and the no-op (RC-58). The client adds no new bit: the pigeonhole pre-check uses `permissionCount` (role:read), and the "missing labels" list reads a set the caller may read |
| **D** | 20 parallel role pages per entry | **OK.** Admin-only, bounded, with a budget test |
| **E** | — | **OK.** The server mirrors A3, the role-subset rule and the PII rule (SD-19) |
| **X** | Role ids from another tenant in path or `?from=` (clone) | **OK.** `resolveRoleInTenant`, so a foreign id is a 404 `ROLE_NOT_FOUND`, the same copy as missing (SD-20) |

### C7 — Assign and revoke: self-revoke, last administrator, PENDING targets, 429 (S3b)

| | Threat | Verdict |
|---|---|---|
| **S** | Administrator assigns to the wrong person because of a look-alike email | **CHANGE: T-S15 (Medium)** |
| **S** | Assignment to a PENDING account whose password belongs to whoever registered the address | **CHANGE: T-E55 (Medium)** |
| **T** | Client prediction of "last administrator" | **OK.** None. The server's `RBAC_002` decides. The hint is never `memberCount`-based (SD-18) |
| **R** | — | **OK.** Server audit; 409 `RBAC_002` WARN |
| **I** | `RBAC_001` reasons shown to the user | **OK.** Exactly RES-47's three reasons; `requiredPermission` is never rendered; `ACCESS_DENIED` carries no reason (RC-63(l)) |
| **D** | `RBAC_011`/`USER_DIR_*` 429 handling | **OK.** No auto-retry; countdown from `Retry-After` (capped at 300 s, `api-error.interceptor.ts:150-157`) |
| **E** | A self-revoke leaves a stale JWT with the old permissions | **OK.** The epoch bump happens in `afterCommit` before the 204 (§0.2 #11). The profile re-read gets 401, then the shared refresh returns a new token without the role |
| **X** | Target user id from another tenant | **OK.** Tenant-scoped resolution; the same `USER_NOT_FOUND` copy |

### C8 — Edge: nginx `gzip off`, production edge, edge smoke job (S1d)

| | Threat | Verdict |
|---|---|---|
| **T** | An intermediary weakens `ETag` or strips `If-Match` | **OK in design.** `gzip off` for `/api/`, a static config test, the nginx-in-the-loop smoke, client detection of weak tags, the 428 alert, and an Ops confirmation that blocks enabling (§20.2 item 3). The production topology is a human item (§9) |
| **T** | `gzip off` changes security headers | **OK.** `/api/` has no `add_header`, so server-level headers stay inherited (`nginx.conf:19-26, 45-51`) |
| **R** | The smoke's negative control (weak `If-Match` gives 428) raises `precondition_required` in staging or production, which is the series the new alert watches | **CHANGE: T-R20 (Low)** |
| **I** | The smoke prints persona addresses | **OK.** Status codes and tag classes only |
| **S** | The smoke against staging or production needs a real credential; personas do not exist there (`!prod`) | **CHANGE: T-R20 (Low).** The credential source and privilege are unspecified |
| **D** | Uncompressed API responses | **OK.** Admin-only, low RPS (AS3) |
| **E** | The smoke account holds administrator rights | **CHANGE: T-R20.** `role:read` plus `role:write` suffice: `RBAC_003` comes before every 403 (B-3) |

### C9 — Rendering user-authored text; copy module; error disclosure (SD-6, SD-7, SD-20)

| | Threat | Verdict |
|---|---|---|
| **T** | Stored XSS through descriptions, emails, names, tooltips, dialogs, toasts | **OK.** Interpolation only; the ESLint sink bans (`eslint.config.js:44-103, 125-139`) plus the `DomSanitizer` import ban; `format()` substitutes text; Angular 22.2.3 (RC-62, audit clean); the scenario-24 unit and e2e tests |
| **S** | Bidi reordering of surrounding UI text by a description | **OK.** `<bdi>` and `dir="auto"` with `unicode-bidi: isolate` |
| **S** | Spoofing **inside** an email (RLO, LRO, zero-width, look-alikes) | **CHANGE: T-S15 (Medium).** Isolation does not neutralise intra-string overrides |
| **I** | Server `detail` shown to users | **OK.** Never shown. Only `details[].message` for a field with no copy, and those are server-authored validation messages (RC-59) |
| **I** | Enumeration through different copy for foreign and missing ids | **OK.** The same copy (SD-20) |
| **E** | — | n/a |

### C10 — PII: DOM, logs, URLs, titles, Playwright (SD-12, SD-13, SD-14)

| | Threat | Verdict |
|---|---|---|
| **I** | Emails in `document.title`, history, toasts, live regions | **OK.** Static titles; ids-only URLs; toasts and announcements carry counts only |
| **I** | Emails or search text in log contexts | **OK.** Allow-listed keys (§2.4); redaction extended to `email|query|search|description` |
| **I** | An `AppError` reaches `GlobalErrorHandler` and is serialised into the message string, which redaction does not touch | **GAP: T-I27 (Low)** |
| **I** | Emails in URLs or access logs | **OK.** Lookup is a POST body; the field is submit-mode without a `<form>` (§0.2 #15) |
| **I** | Emails in CI artifacts | **OK.** Trace off for directory specs, `enterAddress`, no email-text assertions, screenshots off; upload gated on the scan (§0.2 #14) |
| **R** | — | n/a (no client analytics, Q29) |

### C11 — `sessionStorage` drafts (SD-16, SD-17)

| | Threat | Verdict |
|---|---|---|
| **S** | User B restores user A's draft in the same tab | **OK.** The key carries the user id; restore requires `userId === currentUser().userId` |
| **T** | A tampered draft injects ids or an old ETag | **OK.** Storage is treated as untrusted: parse, version, canonical UUIDs in the catalogue, at most 100, 12 h. `If-Match` is always the current tag. The only writer is same-origin script, which already holds the token |
| **T** | A restored intent re-stages adds the caller can no longer grant | **GAP: T-E56 (Low)** |
| **I** | After a session expiry, user B in the same tab can read user A's draft keys (A's user id, role ids, permission ids) | **GAP: T-I28 (Low)** |
| **I** | Drafts on a shared machine after explicit logout | **OK.** The `nexus.session.` sweep on logout. It must run in `finalize` so it also runs when the POST fails (RC-74) |
| **D** | Quota or disabled storage | **OK.** try/catch; drafts are off silently |

### C12 — Dev personas, seeding, contract fixtures (SD-23)

| | Threat | Verdict |
|---|---|---|
| **S** | Known-password personas active outside dev | **OK.** `dev & !break-glass & !prod` on all three seeders; a `DEV_SEED_ACTIVE` WARN (§0.2 #13) |
| **I** | The new role-reader user manager persona holds `user:directory:read` with a public dev password. Any shared environment running `dev` against real data exposes the directory to anyone with the repo | **GAP: T-E58 (Low)** |
| **T** | Seeding mimics break-glass (`assigned_by = self`) | **OK.** `assigned_by` = the seeded administrator (RC-63(g); design §19.4) |
| **I** | Fixture emails | **OK.** `example.test`, synthetic ids; the frontend check is stricter (design §0.4 #3) |

### C13 — Deferred: CSV export (Q20) and S4 to S6

| | Threat | Verdict |
|---|---|---|
| **I** | Unaudited bulk PII extract | **OK.** Deferred (Q20). `csv-neutralise.ts` is "kept ready, not wired". Recommend not adding unwired code now (CLAUDE.md §2). When E3 lands it must prefix `=`, `+`, `-`, `@`, tab and CR, **quote every cell and double embedded quotes**, and be audited (F-3) |
| **—** | S4 to S6 | Out of scope. Each delta to the design gets its own threat-model delta. Members emails via `ids=` stay under US-019 RC-61 detection |

---

## 3. Identified threats

Each entry gives the attack, the existing mitigation, the required mitigation (RC), and the severity with its residual.

### T-S15 — Self-asserted emails can render the same as a colleague's address; `<bdi>` does not neutralise overrides inside the string · **Medium** · CHANGE (OWASP A04)

**Mechanism.**
- Registration accepts `@Email` up to 254 characters (`RegisterRequest.java:15`). The local part admits non-ASCII characters **[INFERENCE: Hibernate Validator pattern]**.
- Normalisation is `trim → NFC → lowercase` (`EmailBlindIndexService.java:38`). It removes neither `\p{Cf}` (U+202E RLO, U+202D LRO, U+2066–2069 isolates, U+200B–200D zero-width, U+2060) nor confusables.
- `<bdi>` and `unicode-bidi: isolate` stop a string from reordering its **neighbours**. An RLO inside the email still reverses the rest of the email itself. A zero-width character makes two distinct addresses look identical.

**Attack.**
1. An anonymous attacker registers, into the default tenant, an address that renders the same as a colleague's (an override in the local part, or a zero-width character). The attacker controls the mailbox, so they can verify it, and it shows ACTIVE and Verified.
2. An administrator or user manager browses Users (design §12.7). They see two rows that look identical, or pick the attacker's row.
3. On the user page and in "Assign a role to {email}" (design §12.9), the address looks correct. The administrator assigns a privileged role. The server cannot help: the target is a legitimate tenant member.

**Existing mitigation.**
- Status and Verified badges in the list and on the user page (RC-63(e)).
- The `(you)` marker by user id.
- Exact-match lookup, which does not match a spoof typed honestly.
- PENDING warning (Q21).

None of these marks a hidden character, and the dialogs do not show the badges.

**Required: RC-68.** **Residual:** RES-54 (confusables across scripts, for example Cyrillic letters, remain visible-but-similar): Low.

### T-E55 — Assignment to a PENDING account makes privilege latent on a password chosen by whoever registered the address · **Medium** · CHANGE (A07, A04)

**Mechanism.**
- PENDING accounts cannot sign in (`LoginUseCase.java:227-229`).
- A second registration of the same address is acknowledged silently, and the original password stays (`RegisterUserUseCase.java:103-110`).
- Verification is a token mailed to the address. Clicking it moves the account to ACTIVE with **whatever password the registrant set**.

**Attack (pre-account hijack, amplified by the console).**
1. The attacker registers a colleague's real address. It stays PENDING, and the verification email goes to the colleague.
2. An administrator, expecting the colleague to join, finds the PENDING row and assigns a privileged role. The server allows it, and Q21 allows it with a warning.
3. The colleague clicks the verification link (it is their address, and they are expecting access). The account is now ACTIVE with the attacker's password and the role.
4. The attacker signs in. A later password reset by the colleague ends this, but only after the window.

**Existing mitigation.**
- The PENDING warning: "This person hasn't verified their email address. Make sure it's the right person." It warns about identity, which is not the risk here. The address **is** the right person's.
- The PENDING banner on the user page.

**Required: RC-69** (copy and confirm strength, within Q21's "allow with warning"), plus a human decision (§9 H-2) and a backend follow-up (F-4). **Residual:** RES-56, Medium until F-4 lands, Low after it.

### T-T26 — `safeReturnUrl`'s literal-prefix rule is bypassed by percent-encoding inside the first segment · **Low** · CHANGE (A01)

`safeReturnUrl` deliberately does not decode (`safe-return-url.ts:13-16`). It rejects encoded `/`, `\` and controls only (`:8`). The router decodes path segments before matching **[REPORTED framework behaviour]**:
- `/%75navailable` passes the planned "starts with `/unavailable`" rule and still lands on the view;
- `/%61uth/login` already passes the `/auth` rule (`:32`) today.

Both outcomes are in-app pages reached by a click, so the impact is a loop, not a redirect. Design §4.7 lists `/%75navailable` in the adversarial table without saying what result is expected.

**Required: RC-70.** **Residual:** none after RC-70.

### T-R19 — A lost refresh response followed by Retry is a refresh-token reuse · **Low** · CHANGE (A07, A09)

**Mechanism.**
- The backend commits a rotation, but the response is lost: a gateway 504 (now `HTTP_ERROR`, now "unavailable"), or a connection reset (`NETWORK_ERROR`).
- The browser never stored the new cookie. Retry presents the old one.
- `RefreshTokenUseCase` revokes the family and writes `TOKEN_REFRESH_REUSE` (`:47-52, :164-167`). The user lands on login: fail-closed, correct.

Two side effects:
- a **false theft signal** on the priority lane during an outage, which is when responders are busiest;
- surprise logouts.

This is pre-existing for a manual reload. The design adds a dedicated Retry for exactly these error classes.

Cross-tab concurrent cold starts (two tabs at once) are the same pre-existing class.

**Required: RC-71** (document and test; no mechanism change). **Residual:** RES-55, Low.

### T-R20 — The edge smoke's negative control trips the design's own alert, and the smoke is unspecified outside CI · **Low** · CHANGE (A09, A05)

**Mechanism.**
- Step 5 sends `If-Match: W/…` and expects 428 (design §19.6). That increments `nexus.rbac.permission_replace{outcome="precondition_required"}`.
- §17 alerts on that series being greater than 0 over 15 minutes in staging or production. §20.2 item 3 tells Ops to run the script against those environments. The release check therefore raises the alert that is meant to detect a broken edge, which trains people to ignore it.
- Outside CI, the script "reads persona credentials the way `scan-pii.mjs` reads `PERSONAS`". Personas do not exist under `!prod`. An operator will reach for an administrator credential on the command line.

**Required: RC-72.** **Residual:** none after RC-72.

### T-I27 — `GlobalErrorHandler` serialises an `AppError` into the log message, past key-based redaction · **Low** · TASK (A09)

`LoggerService` scrubs context **keys** only (`logger.service.ts:25, 37-56`). It does not touch `message`. `GlobalErrorHandler` builds `Unhandled runtime exception: ${JSON.stringify(error)}` for any non-`Error` object (`global-error-handler.ts:31, 57-66`). Every `AppError` is a plain object.

An `AppError` that escapes a store therefore logs these fields unredacted:
- `message` (server `detail`);
- `details[]`;
- `requiredPermission`, which the design says is never logged (§2.4).

The design relies on "every store catches" (§6.2). That is a convention, and the new redaction keys (design §15.3) do not cover this path. Production log level is `warn`, so `error` reaches the console. There is no remote sink (Q29), so exposure is limited to the local console and to screenshots or pastes by support.

**Required: RC-73.** **Residual:** none after RC-73.

### T-I28 — Another user's draft keys linger in the same tab after a session expiry · **Low** · TASK

By design, drafts survive `clearSession` (refresh failure) so FR-G4 can restore them. If a **different** user then signs in to that tab, the keys stay readable by that user until 12 h pass or the tab closes. The keys carry the first user's id, role ids, permission ids and the base ETag. Restore is correctly refused. The leak is metadata about the first user's edit in progress: low value, but avoidable.

**Required: RC-74.** **Residual:** none after RC-74.

### T-E56 — A restored or rebased intent can stage adds that the caller can no longer grant · **Low** · TASK

`rebase` (design §8.2) reconciles the intent against the **set**, not against the caller's current affordances. A draft from earlier, or a 412 rebase after the caller's own access shrank, can show a staged add on a row that is now disabled (`not-held`, `admin-only-directory`). The server refuses with 403. This is a UX defect with a security flavour: a disabled checkbox that is visibly checked misrepresents what the user is authorised to do.

**Required: RC-74 item 3.**

### T-D31 — Unavailable-view retries against the nginx auth zone, and an empty state after reload · **Low** · TASK

nginx's auth zone allows 10 r/min per IP, burst 10, and answers with HTML 429 without `Retry-After` (`nginx.conf:9-10, 35-37`). That becomes `HTTP_ERROR`, back to the view, with the 5 s default countdown.

After an outage, every tab behind one office NAT retries on roughly the same 5 s cadence and keeps the shared IP throttled. Each successful POST also spends the per-session `REFRESH_FAMILY` bucket (`RefreshTokenUseCase.java` class Javadoc), even when `fetchMe` then fails with `AUTH_005`. Separately, a reload of `/unavailable` has no `UnavailableState`, and the design does not say what the countdown shows then.

**Required: RC-75.** **Residual:** accepted. Retries are user-initiated and bounded.

### T-E57 — `canMatch` runs before the shell's `authGuard`; the kill switch is a release control, not an authorization control · **Low** · TASK

`accessConsoleEnabledGuard` is `CanMatchFn` and runs in recognition, before the parent's `canActivate` restores the session (design §4.3). It is config-only today, which is correct. A later change that reads `AuthStore` there would see an empty session at cold start and 404 the console, or a future "allow" variant would run before authentication. Separately, §18 calls `accessConsoleEnabled` a "kill switch". It removes the UI only. The APIs stay reachable for any token holder while their backend flags are on.

**Required: RC-76.**

### T-E58 — The new dev persona carries directory access with a public password · **Low** · TASK

The role-reader user manager persona holds `user:directory:read` and `user:role:assign` (design §19.4). The seed guard is correct (`!prod`). But any shared environment that runs `dev` (as compose does, `docker-compose.yml:102`) against **real** data hands directory read and assignment to anyone with the repository. The `DEV_SEED_ACTIVE` WARN is the only signal.

**Required: RC-77.** **Residual:** RES-57, Low.

### 3.3 Attacked and survived (no finding)

| Attack | Why it fails |
|---|---|
| Use `/unavailable` to pivot a click into a mutation | No HTTP and no auto-retry; no route mutates on activation (SD-17); draft restore needs a click |
| Make `authGuard` admit on an intermediary response | Only a completed `refresh()` (POST plus `/users/me`) returns `true` (§0.2 #1, #2) |
| Double refresh through the self-revoke flow | The profile re-read and the post-revoke list re-read both 401 and join `refreshInFlight` (`auth.interceptor.ts:63-75`) |
| Cold-start `AUTH_005` then Retry reuses a token | `AUTH_005` comes from `fetchMe` after the POST rotated the cookie, so Retry sends the new cookie (§0.2 #2) |
| Blind overwrite through a weak tag stripped client-side | The client never strips `W/`; the server answers 428 for anything but one strong tag (B-2, RC-55) |
| A draft's `baseEtag` used as `If-Match` | Never: `If-Match` is the current tag only (design §10) |
| Retry-once turns a 403 into a loop | One retry at most; 403, 412, 429 and 503 are never retried |
| 401 replay applies a PUT twice | The filter rejects before the handler (B-8) |
| BREACH-style oracle through `gzip off` | `gzip off` removes compression on `/api/`, which only shrinks the surface. `/api/v1/auth/` keeps gzip, but its responses reflect no attacker input (pre-existing, unchanged) |
| Cross-tenant ids in role or user paths, clone `?from=`, or the "Assigned by" id | All resolve within the JWT tenant server-side; foreign and missing ids get the same copy; the "Assigned by" email comes only from the caller's own directory page cache |
| `RBAC_001` reasons as a new oracle in the console | The console renders exactly RES-47's reasons. The assign dialog's "missing permissions" list reads a set the caller can already read with `role:read`. The admin hint uses `permissionCount` and the catalogue total, both visible to `role:read` |
| Stored XSS through `format()` placeholders, dialog titles or `confirmTyped` | Text substitution plus interpolation. `expectedText` is a role name, which is ASCII by pattern (B-15) |

---

## 4. Verdicts on the design's security decisions (§21) and the brief's items

### 4.1 SD-1 to SD-23

| SD | Verdict | Note |
|---|---|---|
| SD-1 Gating is UX only | **Confirmed** | "Predicted allow, server deny" tests are in §19.1 |
| SD-2 `/unavailable` public; pin 3 to 4 | **Confirmed. Security sign-off granted**, conditional on RC-70 and the §19.1 assertions | — |
| SD-3 Guard classification | **Confirmed fail-closed** | An intermediary 4xx HTML now shows "unavailable". That is acceptable (an availability effect only) |
| SD-4 One refresh per attempt; the console never refreshes | **Confirmed** | Add T-R19's documentation (RC-71) |
| SD-5 `safeReturnUrl` | **Confirmed with RC-70** | — |
| SD-6 Stored XSS | **Confirmed** | Audit clean (RC-62 landed) |
| SD-7 Bidi | **Confirmed for neighbours; insufficient inside emails** | T-S15, RC-68 |
| SD-8 ETag | **Confirmed** | T-R20 for the smoke |
| SD-9 412 | **Confirmed** | Intent rebase does not resurrect upstream removals |
| SD-10 Retry-once | **Confirmed** | §4.4 |
| SD-11 401 replay | **Confirmed** for PUT, POST assign and DELETE revoke | B-8 |
| SD-12 PII in logs | **Confirmed with RC-73** | — |
| SD-13 PII in URLs | **Confirmed** | §0.2 #15 |
| SD-14 PII in reports | **Confirmed** | Upload is gated on the scan (§0.2 #14) |
| SD-15 Stale profile | **Confirmed** | RES-59 |
| SD-16 Drafts | **Confirmed with RC-74** | — |
| SD-17 No mutation on activation | **Confirmed** | — |
| SD-18 Lockout | **Confirmed** | — |
| SD-19 Grant-rule mirroring | **Confirmed** | Over-blocking if Ops disables the PII rule is the safe direction (US-019 RC-66.4 logs it) |
| SD-20 Enumeration | **Confirmed** | — |
| SD-21 Kill switch via `canMatch` | **Confirmed as a release control** | RC-76 wording |
| SD-22 Propagation copy | **Confirmed** | §4.3 |
| SD-23 Personas dev-only | **Confirmed** | RES-57 |

### 4.2 The public-route pin (RC-63(i)) and the guard change: sign-off

**Approved by Security** for the threat model, subject to:
- RC-70;
- the §19.1 real-Router spec (exactly one `POST /refresh` per attempt; no request while on the view; the page injects no `HttpClient`);
- the pin remaining an **exact** set of four.

The formal Gate 2 acceptance remains the Platform Security Owner's (§9 H-1).

### 4.3 Q3: the revoke propagation claim (AS7)

**Confirmed, with conditions. No copy change is required.**
- **"On the person's next request"** holds in the healthy case:
  - Revoke evicts the cache and bumps the epoch in `afterCommit` on the request thread, before the 204 (`RoleAssignmentService.java:456-475`; `PermissionFreshnessService.java:1093`).
  - A replace with removes bumps every holder (`RoleManagementService.java:960-967`).
  - The filter rejects a stale epoch before any handler (B-8).
- **"In every case within about 30 minutes"** holds as a ceiling:
  - A failed bump is queued and replayed, not lost (`PermissionFreshnessService.java:1055-1065`).
  - During fail-open, the old token is bounded by its TTL (900 s, `application.yml:269`). A mint from a stale cache adds at most the cache TTL (900 s, `:157`). The sum is 1,800 s.
- **Condition:** `NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS` is environment-overridable. Release checklist item 8 must compare it per environment. It does.
- **Grant copy:** adds evict caches (`RoleManagementService.java:968-970`; `RoleAssignmentService.java:207`), so "or when the person signs in again" holds.
- Optional wording, not required: "usually on the person's next request".

### 4.4 RES-53: retry-once on the PUT

**Accepted, including the defensive PUT case.** A 409 applied nothing. The retry carries the same strong `If-Match`, so it can succeed only against the version the user reviewed. A changed set yields 412 and the explicit rebase. This decision closes the corresponding §23 row.

### 4.5 RES-47: `RBAC_001` reason disclosure in the console

**Unchanged at Low.** The console shows exactly the three accepted reasons plus `UNSPECIFIED`. It never shows `requiredPermission`. `ACCESS_DENIED` carries no reason. No new composition bit is added (§3.3).

---

## 5. Summary of threats by severity

| Severity | Count | Ids |
|---|---|---|
| Blocker | 0 | — |
| High | 0 | — |
| Medium | 2 | T-S15, T-E55 |
| Low | 9 | T-T26, T-R19, T-R20, T-I27, T-I28, T-E56, T-D31, T-E57, T-E58 |

| Slice | Threats |
|---|---|
| S1a | T-E57 |
| S1b | T-T26, T-R19, T-D31 |
| S1d | T-R20 |
| S1e | T-I27 |
| S2 | T-I28, T-E56 |
| S3a | T-E58 |
| S3b | T-S15, T-E55 |

---

## 6. Required design changes (block Gate 2)

Each item is a concrete edit to `03-design.md` (or a proposed ADR) and becomes at least one `/breakdown` task.

**RC-68 — Show hidden characters in emails; badges in dialogs (T-S15, Medium; S3b)**
1. **§15.3 and §6.1 `UserText`:** add an `email` mode. Every `\p{Cf}` code point (bidi embeddings, overrides and isolates U+202A–202E and U+2066–2069; U+200B–200F; U+2060–2064; U+FEFF) is rendered as a visible token such as `⟨U+202E⟩`. In the DOM this is a separate `<span>` with an accessible name, as text, never HTML. The row gets a "Contains hidden characters" badge (icon plus text). Descriptions keep `<bdi>` isolation and also get the badge when they contain `\p{Cf}` (no token substitution needed).
2. **§12.7, §12.8, §12.9, §12.10:** the Assign and Revoke dialogs show the target's status, Verified badge and hidden-character badge next to the email, not only in the list and header.
3. **§14.2:** add the badge label and a one-line explanation ("This address contains characters that are invisible or change text direction. Check it carefully before giving access.").
4. **§19.1 / §19.3:** unit render tests with an RLO email, a zero-width-joined email and a clean email (token rendered; badge present; `textContent` with the tokens removed equals the input). One e2e test, with a target seeded through the API in the dev tenant, uses `enterAddress` and is asserted by test id.
5. **§23:** add follow-up **F-5** (backend, identity): reject `\p{Cf}` in emails at registration and invitation, and report existing rows that contain them.

**RC-69 — PENDING targets: say what the risk is, and make it a deliberate confirm (T-E55, Medium; S3b)**
1. **§12.9 and §14.2:** replace the PENDING warning with `role=alert` copy that names the risk. Proposal: "This account hasn't been verified. Until it is, it may have been created by someone other than the owner of this address, and they would get this role when it's verified. Prefer assigning after the person has signed in."
2. **§12.9:** for a PENDING target, the confirm button reads "Assign to unverified account" (`danger`). If the role is hinted admin-defining (Q17 hint), the dialog uses `confirmTyped` with the role name. This stays within Q21 ("allow with a warning"). It adds no client block.
3. **§8.3 assign table:** add the PENDING row (hint plus confirm variant, never disabled).
4. **§23:** add **H-2** (§9) and backend follow-up **F-4**: on verification of an account that has never signed in, require the verifier to set a new password, or invalidate the registrant's password (pre-hijack defence). The owner is Identity.

**RC-70 — Segment-based return-URL rule (T-T26, Low; S1b)**
1. **§4.7:** the rule rejects a value when the first path segment, **as the router parses it** (`router.parseUrl(raw)`, primary outlet, first segment), equals `unavailable` or `auth`. This needs no second decode of the validated string: the value navigated stays the value validated. Alternatively, reject any `%` in the first segment.
2. **§4.7 / §19.1:** the adversarial table states that the expected result is `/dashboard` for `/unavailable`, `/unavailable?returnUrl=%2Fadmin`, `/%75navailable`, `/%61uth/login` and `/unavailable;x=1`.

**RC-71 — Document the lost-response reuse and pin fail-closed (T-R19, Low; S1b)**
1. **§4.5 and ADR-0028:** state that a refresh whose response is lost after the server rotated it (504, reset) makes Retry a reuse. The result is a family revocation, a `TOKEN_REFRESH_REUSE` event and a login redirect. This is accepted as fail-closed.
2. **§17 / runbook:** the `TOKEN_REFRESH_REUSE` triage step checks for gateway 5xx and `auth_guard_unavailable` in the same window before it treats the event as theft.
3. **§19.1:** a guard spec in which Retry's refresh returns 401 `AUTH_004` lands on `/auth/login` (not `/unavailable`), with no loop.

**RC-72 — Edge smoke outside CI (T-R20, Low; S1d)**
1. **§19.6:** step 5 (the weak-tag negative control) runs only with `--negative-control`. CI passes it; Ops runs against staging or production omit it.
2. **§19.6:** outside CI, the script runs as a dedicated **non-administrator** smoke identity holding only `role:read` and `role:write`. That is sufficient because `RBAC_003` precedes every 403 (B-3). It reads credentials from environment variables only (never argv), never prints them, and logs out at the end.
3. **§17:** the alert note says that a CI run produces exactly one 428 per run, and that CI is not a scraped environment.
4. **§20.2 item 3:** reference the smoke identity and the flag.

---

## 7. Tasks (Low; land inside their slice's merge gate)

**RC-73 — Safe global error logging (T-I27; S1e).**
- `GlobalErrorHandler` logs an `AppError`-shaped value (an object with a string `code`) as `code`, `correlationId` and `traceId` only, in context keys. It never `JSON.stringify`s it into the message.
- Spec: an `AppError` with `message`, `details` and `requiredPermission` produces a log line containing none of them.
- Each console store has a spec that its load and action errors never reach `ErrorHandler`.

**RC-74 — Draft hygiene (T-I28, T-E56; S2).**
1. When a session is established for a user id that differs from the owner id in any `nexus.session.access-draft.v1.*` key, those keys are removed. This runs on login or refresh success, in `AuthService`, not on `clearSession`.
2. `clearSessionScopedStorage()` runs inside the logout `finalize`, so it also runs when the POST fails. Reads reject a `savedAt` in the future.
3. Restore and rebase drop intent entries whose row affordance is disabled, and list them in the banner ("Not restored because you can't grant them: {labels}"). A disabled row is never shown as staged.

**RC-75 — Unavailable-view cool-down (T-D31; S1b).**
- The countdown is `min(retryAfterSeconds ?? 10, 60)` plus 0–5 s of jitter.
- With no `UnavailableState` (a reload or direct visit), the page shows a 10 s countdown from render.
- Specs for both cases.

**RC-76 — `canMatch` and kill-switch wording (T-E57; S1a).**
- A contract spec: every `canMatch` guard on a shell descendant is in an allow-list of config-only guards (initially `accessConsoleEnabledGuard`), and its spec asserts that it injects neither `AuthStore`, `AuthService` nor `HttpClient`.
- ADR-0028 and §18 state that `accessConsoleEnabled` is a release control and that the backend flags are the off switch for the APIs.

**RC-77 — Persona exposure note (T-E58; S3a).**
- §19.4 and §20.2 gain a checklist line: an environment holding real user data must not run the `dev` profile. The `DEV_SEED_ACTIVE` WARN is an alertable signal there.
- `DevPersonaSeedIT` asserts that the new personas are absent under `dev,prod` (extend `DevSeedProfileGuardTest`'s `dev,prod` context to the new rows).

---

## 8. Residual risk register

RES-54 onward is new. Owners are roles. **Accept** means the residual can be accepted at Gate 2 once its RC lands. **Escalate** means it needs a named role's explicit decision.

| # | Residual | Severity (after RC) | Owner | Disposition |
|---|---|---|---|---|
| **RES-54** | Cross-script confusable emails (homoglyphs) stay visually similar after RC-68; NFC does not fold them | Low | Security + PM | Accept; revisit with F-5 (a mixed-script badge is an option) |
| **RES-55** | Lost-response refresh followed by Retry, or cross-tab concurrent cold starts, gives a family revocation and a false `TOKEN_REFRESH_REUSE` | Low | Frontend Tech Lead + SRE | Accept with RC-71 |
| **RES-56** | Latent privilege on PENDING accounts (pre-hijack) | **Medium** until F-4 · Low with F-4 and RC-69 | PM (Q21) + Identity owner | **Escalate** (§9 H-2) |
| **RES-57** | Known-password dev personas, including directory access, in any environment running `dev` | Low | Ops | Accept with RC-77 |
| **RES-58** | The kill switch is build-time and UI-only; turning the console off needs a redeploy | Low | Tech Lead + Ops | Accept (it is not a security control; the backend flags are) |
| **RES-59** | Nav (JWT) can lag the live profile by up to the token TTL after a grant | Low | Architect | Accept (ADR-0028) |
| **RES-60** | `vite` 8.3.0–8.3.2 (high) through `@angular/build`; dev server and toolchain only | Low | Frontend Tech Lead | Accept with a review date; not in the production graph |
| **RES-47** *(inherited)* | `RBAC_001` reasons | Low | Security | Unchanged (§4.5) |
| **RES-53** *(inherited)* | Retry-once on `RBAC_012`, including the defensive PUT | Low | Frontend Tech Lead | **Accepted** (§4.4) |
| **RES-39** *(inherited)* | `permissionGuard` fails open on missing `data.permission` | Low | Frontend Tech Lead | Unchanged; the new guard fails closed |
| **RES-49, RES-51** *(inherited)* | Directory enumeration by holders; PII delegation | Low (with US-019 RC-61, RC-60) | Security/Privacy (D5) | Unchanged; the console adds no new read path |

---

## 9. Needs a human

| # | Item | Owner | Security recommendation |
|---|---|---|---|
| **H-1** | Formal Gate 2 acceptance of the public-route pin widening and the `authGuard` reclassification (SD-2 to SD-5) | Platform Security Owner | Approve, conditional on RC-70, RC-71 and the §19.1 specs (§4.2) |
| **H-2** | Q21: keep "assign to PENDING with a warning", or refuse **admin-defining** roles to PENDING accounts in the UI until F-4 lands | PM (Q21 owner) + Platform Security Owner | Keep Q21 with RC-69. Refuse admin-defining roles to PENDING targets in the UI until F-4 lands. That is a hint-based block, so a server refusal is still authoritative |
| **H-3** | Backend follow-ups F-4 (pre-hijack defence at verification) and F-5 (reject `\p{Cf}` in emails) | Identity owner | Record in `14-pending-items.md`. F-4 lowers RES-56 to Low |
| **H-4** | Production edge topology, and a non-administrator smoke identity for staging and production (RC-72) | Ops | Unchanged from design §23, plus the smoke identity |
| **H-5** | Build-time kill switch acceptable as the off path | Tech Lead + Ops | Acceptable from a security standpoint (RES-58) |
| **H-6** | DPO acknowledgement (Q22) | Legal/DPO | Unchanged; it blocks us019 in production |

These design §23 rows are **decided here** and can be closed:
- "Q3 revoke propagation claim": confirmed (§4.3).
- "RES-53 retry-once also on the PUT": accepted (§4.4).
- "Threat-model sign-off on the pin": recommended, with formal acceptance at H-1.

---

## 10. Cross-references to prior threat models

| Prior item | Status after US-020 |
|---|---|
| **US-019 RC-63(i) / T-T25** (public pin, `safeReturnUrl`) | Pin widened to four with sign-off; the rule is made segment-based (RC-70), which also closes `/%61uth` |
| **US-019 RC-65 / T-S14** (double refresh) | Closed in US-019 by dropping `canActivateChild`. US-020 keeps that invariant; the console never refreshes (ADR-0028). The guard still calls `AuthService.refresh()` directly, which is safe because it runs only at cold start |
| **US-019 RC-63(e) / T-S12** (attacker-chosen emails; CSV) | Status and Verified badges are delivered in the list and header. Extended by RC-68 (hidden characters, badges in dialogs) and RC-69 (PENDING). CSV stays deferred (Q20), with the quoting rule added in C13 |
| **US-019 RC-63(l) / RES-47** | Unchanged (§4.5) |
| **US-019 RC-67(b) / RES-53** | Accepted, including the PUT (§4.4) |
| **US-019 RC-62 / T-T23** | Landed: production `npm audit` is clean at `@angular/core` 22.2.3 |
| **US-019 RC-63(g)** (seeder `!prod`) | Confirmed in code; RC-77 extends the guard test to the new personas |
| **US-019 RC-63(h)** (CI artifacts) | Confirmed; upload is gated on the PII scan |
| **US-018 refresh reuse (no grace window)** | The basis of T-R19 and RES-55 |

---

## 11. Merge-blocking list

- **Gate 2 closes when:** RC-68 to RC-72 are folded into `03-design.md` (and ADR-0028 for RC-71), and H-1 is recorded.
- **S1a:** RC-76.
- **S1b:** RC-70, RC-71 item 3, RC-75; the §19.1 real-Router spec green.
- **S1d:** RC-72; the edge smoke green, including its CI-only negative control.
- **S1e:** RC-73.
- **S2:** RC-74. Unchanged from the design: no production enablement before the Ops edge confirmation.
- **S3a:** RC-77.
- **S3b:** RC-68, RC-69, and H-2 recorded (either decision).
- **All slices:** re-run `./mvnw dependency:tree` and `npm audit` at each Phase 7. Today's baseline: no manifest delta; the production npm graph is clean; the full graph has 2 findings (toolchain `vite`, RES-60).

---

## 12. Delta review: design Draft 2 (2026-10-23)

**Scope.** This is a delta, not a fresh STRIDE pass. It covers `03-design.md` Draft 2 (commit `f43d806`; its Revision 1 table and the sections that table lists), ADR-0028 and ADR-0029, checked against §3, §6 and §7 above. It reopens no Gate 1 decision. Code re-checked: `safe-return-url.ts:1-40` and its one caller (`login-form.component.ts:251`), and `CreateRoleRequest.java:24-33` (role names are restricted to ASCII `[A-Za-z0-9 ._-]`, so typed confirms on role names cannot carry hidden characters). There is no manifest delta, so the §11 dependency baseline still holds; scans are re-run at Phase 7.

### 12.1 Verdict per RC

| RC | Verdict | Notes |
|---|---|---|
| RC-68 | **Landed** (items 1 to 5). Hardening D-1 and D-5 to follow | `UserText` `email` mode, `splitHiddenCharacters`, the badge in both modes, `TargetIdentity` in Assign and standard Revoke, copy, unit and e2e tests, F-5. The self-revoke dialog without an identity line is **acceptable**: its target is the caller, so there is no third party to mistake, and role names are ASCII (above). The condition is D-5 |
| RC-69 | **Landed**, with the H-2 decision applied on top | Alert copy, the `danger` "Assign to unverified account" confirm, the §8.3 rows, F-4 and H-2 are all in. The typed confirm is specified and unit-tested behind the block. See §12.2 |
| RC-70 | **Landed.** Implementation detail D-2 to follow | Parsed first segment of the primary outlet, `auth` moved onto the rule, the table expects `/dashboard`, and parse failure falls back. See §12.3 |
| RC-71 | **Landed** (items 1 to 3) | §4.5, ADR-0028 decision 7, the §17 triage step, and the `NETWORK_ERROR` then `AUTH_004` real-Router spec. See §12.4 |
| RC-72 | **Landed** (items 1 to 4). Hardening D-3 to follow | The flag, the identity split, env-only credentials, logout, the §17 alert note, §20.2 item 3, ADR-0029 decisions 4 and 5, H-4. See §12.5 |
| RC-73 | **Landed** as an S1e task with §19.1 specs | Matches §7 |
| RC-74 | **Landed** as an S2 task with §19.1 specs. Consistency nit D-6 | §10's body text was not updated to match |
| RC-75 | **Landed** | The formula is exactly as specified in §7, and so is the no-state case of 10 s from render |
| RC-76 | **Landed** | §18 wording, the allow-list contract spec, ADR-0028 decision 8 |
| RC-77 | **Landed** | §19.4, §20.2 item 11, the `DevPersonaSeedIT` `dev,prod` extension |

### 12.2 H-2 and RC-69 item 2: coherent, not a contradiction

- RC-69 item 2 ("adds no client block") describes the baseline **within Q21 alone**. §9 H-2 put the block option to a human, and the block was this threat model's recommendation. The H-2 decision replaces item 2's "no block" clause for exactly one cell: a PENDING target with a hinted admin-defining role. It leaves the rest of item 2 in force.
- So the typed confirm being unreachable while the block is in force is expected. Specifying and testing it now, so that F-4 removes one row, is the right shape.
- **Adequacy.** The block is a UX hint, not a control. The server is unchanged, so RES-56 stays **Medium until F-4** whatever the UI does. As an interim measure it is adequate: it removes the worst case a hint can see, and everything the hint misses still gets the `role=alert` warning and the `danger` confirm, the same as RC-69 required. A role the hint misses is, for example, all permissions but one, or admin power assembled from several roles.
- Advisory, not required: while the block is in force, a PENDING target with a role carrying any Sensitive permission could use `confirmTyped`. This would give near-admin roles the friction RC-69 item 2 intended for admin roles.
- The fail-open edge and the test switch are D-4.

### 12.3 RC-70 bypass check

Today's checks (`safe-return-url.ts:26-31`) already reject `//`, `/\`, any `\`, controls, any `:` in the path (and so named-outlet syntax `(x:y)`), and `%2f`, `%5c` and encoded controls. The new rule then reads the parsed tree, and the value navigated is the value validated.

| Input | Result under Draft 2 | Verdict |
|---|---|---|
| `/%2575navailable` (double encoding) | Router decodes once, giving `%75navailable` ≠ `unavailable`; the value is returned and lands on Not Found | No bypass. The router decodes once, consistent with the check |
| `/unavailable;x=1`, `/auth;x=1/login` | Matrix params are separated from `segment.path`, so both are rejected | Closed. Today `/auth;x=1/login` passes the literal rule; add it to the table |
| `/unavailable#f`, `/unavailable?x` | Path part is `/unavailable`, so rejected | Closed |
| `/#/unavailable` | The fragment is ignored by path-location routing; lands on `/` | No bypass (path location strategy; no hash strategy in `src/`) |
| `/(unavailable)` | Parens without `:` parse as the primary outlet; rejected only if the check reads `root.children[PRIMARY_OUTLET]` | Holds if implemented as worded; add it to the table |
| `/x/../unavailable`, `/%2e%2e/unavailable`, `/./unavailable` | First segment is `x`, `..` or `.`, so it passes. The router treats dot segments literally (Not Found), but `pushState` normalises the address bar to `/unavailable`, so a reload lands on the view without `returnUrl` (Retry then goes to `/dashboard`) | Not a redirect and not a loop. Router and address bar disagree, though: D-2 |

### 12.4 RC-71 and RC-75: no loop, no second refresh path

- `AUTH_004` on Retry goes to `/auth/login`, not `/unavailable`. That is a terminal branch, so there is no loop. The spec pins "no further refresh".
- Retry re-enters only through the shell's `canActivate`. The button is `loading` and cannot be pressed twice, and there is no automatic retry. The console never calls `refresh()` (ADR-0028 decisions 5 and 7). No second refresh path remains. Cross-tab concurrent cold starts are pre-existing (RES-55).
- The cool-down is a client courtesy. A hostile client can skip it, but nginx's auth zone is the real limit. A `Retry-After: 0` from the backend gives only the 0 to 5 s jitter. That is the server's choice and acceptable. Non-cryptographic randomness for the jitter is fine.

### 12.5 RC-72: identity and credentials

- Credentials come from env vars only (`NEXUS_SMOKE_USER`, `NEXUS_SMOKE_PASSWORD`), never argv and never printed. The names have no security impact.
- The negative control is CI-only, and the identity is non-administrator. The blast radius of a leaked credential is bounded by the grant-subset and role-subset rules: the identity can create roles, or alter roles, only within {`role:read`, `role:write`}.
- Nothing yet **enforces** either rule. An operator can still export an administrator credential into those variables, or pass `--negative-control` against production: D-3.

### 12.6 New provisional names and copy

- **Disabled reason `pending-admin-role` and its text:** this reveals only that a role looks like an administrator role, which the Q17 hint already shows. No impact.
- **Token `⟨U+{hex}⟩` and its accessible name "hidden character U+{hex}":** this is rendered as interpolated text and attributes, never HTML (§15.3).
  - A registrant could type literal `⟨U+202E⟩` look-alike text into an address. That makes their address look suspicious and adds no badge. It cannot make a hidden character disappear, so it is not a spoofing aid.
  - The accessible name must be bound as an attribute value, not built into markup. §15.3 already requires interpolation.
- **Typed-confirm copy for PENDING:** it embeds `{role}`, and role names are ASCII. No impact.
- **Smoke env var names:** no impact (§12.5).

### 12.7 New findings (all Low; none blocks Gate 2; each lands in its slice's merge gate)

```
[LOW] Hidden-character set is narrower than "invisible"
File: docs/features/US-020/03-design.md §15.3 (also §23 F-5)
Issue: D-1. RC-68 and §15.3 tokenise \p{Cf} only. Invisible or blank code points outside Cf still render as nothing or as a space and get no badge: U+115F, U+1160, U+3164, U+FFA0 (Hangul fillers, Lo), U+034F and U+FE00–FE0F (Mn), U+E0100–E01EF, and non-ASCII spaces (Zs, for example U+00A0, U+2000–U+200A, U+3000). The local part admits non-ASCII [INFERENCE: Hibernate Validator pattern, as T-S15].
Risk: Two addresses still render the same in the list and dialogs, which is T-S15's attack (OWASP A04).
Fix: In splitHiddenCharacters, match [\p{Cf}\p{Default_Ignorable_Code_Point}\p{Zs}\p{Zl}\p{Zp}] except U+0020. JS supports these property escapes with the u or v flag. Add a Hangul-filler email and an NBSP email to the §19.1 rows. Widen F-5 to the same set. Slice S3b.
```

```
[LOW] RC-70 implementation underspecified for a pure function; dot segments
File: docs/features/US-020/03-design.md §4.7, §19.1 (safe-return-url.ts:24 is DI-free)
Issue: D-2. "router.parseUrl(raw)" needs DI that safeReturnUrl does not have, and an implementer may move the check to a place that sees a different string. Dot segments pass, and the address bar then diverges from router state (§12.3).
Risk: A future refactor validates one string and navigates another (OWASP A01). Today the impact is only cosmetic or a reload oddity.
Fix: In §4.7, state that the function stays pure and parses with `new DefaultUrlSerializer().parse(raw)`. The app registers no custom UrlSerializer; if one is ever added, inject it instead. Read `tree.root.children[PRIMARY_OUTLET]?.segments[0]?.path`. Also reject a value in which any primary segment path is `.` or `..`. Add these table rows: `/auth;x=1/login`, `/(unavailable)`, `/x/../unavailable` and `/%2e%2e/unavailable`, each expecting /dashboard; and `/%2575navailable`, returned unchanged (pins "no second decode"). Slice S1b.
```

```
[LOW] Edge smoke does not enforce its own identity and flag rules
File: docs/features/US-020/03-design.md §19.6, §23 H-4; ADR-0029 decision 5
Issue: D-3. The rules are prose only. An administrator credential in NEXUS_SMOKE_* works. `--negative-control` against production works and trips the §17 alert. Logout is "step 6", so it is skipped on early failure (for example "smoke not meaningful").
Risk: An administrator credential sits in an operator's shell environment, and the alert is trained into noise again (OWASP A07, A09).
Fix (§19.6):
(a) After login, GET /api/v1/users/me/authorization. If the identity is an administrator, or holds anything outside {role:read, role:write}, abort with a non-zero exit, logging out first. Skip this check only in the CI persona mode.
(b) Refuse `--negative-control` unless CI is set, or the base host is loopback or the compose service.
(c) Log out in a finally block on every exit path.
(d) H-4: the credential lives in the Ops secret store, and any successful write by the smoke identity (anything other than the expected 409) is alertable in the audit log. Slice S1d.
```

```
[LOW] H-2 block fails open when the catalogue total is unknown; test switch must not be runtime
File: docs/features/US-020/03-design.md §8.3 (PENDING rows), §19.1 (Assign dialog, PENDING)
Issue: D-4. isAdminDefiningHint needs catalogue.total, and §8.3 does not say what the block does if the catalogue failed to load. §19.1 tests the typed confirm "with the H-2 block switched off", but nothing says what that switch is.
Risk: An admin-defining role is offered to a PENDING target, or a runtime toggle (config, query or storage) disables the block (OWASP A04). The server stays authoritative, so the residual is unchanged (RES-56).
Fix: In §8.3, state that a PENDING target with an unknown catalogue total treats every role as hinted, so the block applies. Also state that the block is a code constant or a pure-function parameter, set only in specs, with no environment, AppConfig, URL or storage input. Slice S3b.
```

```
[LOW] Self-revoke variant selection criterion not stated
File: docs/features/US-020/03-design.md §12.10
Issue: D-5. Omitting the identity line is safe only if the self-revoke variant is chosen by id equality. §6.3 and §12.7 use userId, but §12.10 does not say so.
Risk: If the variant were chosen by comparing emails, an implementer could show the no-identity dialog for someone else (OWASP A04).
Fix: In §12.10, add: "Chosen when the route userId equals the profile's userId; never by email comparison." Slice S3b.
```

```
[LOW] RC-74 not reflected in the §10 body
File: docs/features/US-020/03-design.md §10 (Read validation and Clear rows), §14.2
Issue: D-6. §10 still says only "savedAt within the last 12 h" and "logout gains a call", with no future-savedAt rejection and no finalize. §14.2 lacks the "Not restored because you can't grant them: {labels}" string. §1.2 S2 and §19.1 carry these, so the section an implementer reads first is stale.
Risk: Partial implementation of RC-74 (hygiene).
Fix: Update the two §10 rows, add the §14.2 row, and add §10 and §14.2 to the Revision 1 RC-74 entry. Slice S2.
```

### 12.8 Delta verdict

RC-68 to RC-72 are folded in correctly and completely, and RC-73 to RC-77 are present as slice tasks. The delta found no regression. D-1 to D-6 are Low hygiene and hardening items. They go to S1b, S1d, S2 and S3b as tasks, and §11 gains them as follows:
- S1b: D-2.
- S1d: D-3.
- S2: D-6.
- S3b: D-1, D-4, D-5.

On the security side, Gate 2 can close **subject only to the human items**: H-1, H-2 confirmation by PM and the Platform Security Owner, H-3, H-4 (now including D-3(d)), H-5 and H-6. This section records review only. It is not an approval.
