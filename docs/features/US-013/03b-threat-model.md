# US-013 — Threat Model (Phase 3b / STRIDE, design-phase)

_Output of Step 3b (`/security-review` in **threat-model mode**) against `docs/features/US-013/03-design.md`. This is a **design-phase** STRIDE analysis, distinct from the Step-7 code audit that will verify the shipped implementation. Severity conventions match this project's established style (`docs/features/US-011/07-security-review.md`): **Blocker / High / Medium / Low**._

**Verdict: PASS WITH REQUIRED FOLLOW-UPS.** Blockers 0 · High 0 · Medium 4 · Low 6. The design's central framing — *client-side permission gating is UX polish, not a security boundary* — **holds up under STRIDE and is confirmed correct**. No threat found requires a design change. Six mitigations are **required** and must each become a task in `/breakdown` (§6); four are recommended (§7). The design's own §16.1 checklist was accurate as far as it went; this pass adds three items it did not identify, of which the most material is a **new, mechanical `AppError` serialisation leak path via `GlobalErrorHandler`** (T-05) and a **mechanical replacement for two documentation-only invariants** (T-03, via a route-table spec).

---

## 0. Scope, method, and attestation

### 0.1 Documents and code read in full

**Design inputs:** `docs/features/US-013/01-requirements.md`, `02-impact.md`, `03-design.md` (all 1361 lines, including §16.1's six handoff items), `docs/features/US-011/07-security-review.md` (severity convention + the shipped backend enforcement posture this story depends on).

**Frontend source read directly (not taken on the design's word):** `core/auth/auth.store.ts`, `core/guards/auth.guard.ts`, `core/http/api-error.interceptor.ts`, `core/logging/logger.service.ts`, `core/config/app-config.ts`, `core/errors/global-error-handler.ts`, `app.config.ts`, `app.routes.ts`, `shared/types/auth.ts`, `shared/types/app-error.ts`, `shared/ui/error-state/error-state.ts`, `features/dashboard/dashboard.component.ts`, `features/auth/registration-form/registration-form.component.ts`, `src/environments/environment.ts` + `environment.development.ts`.

**Repository-wide greps run to test the design's negative claims:** `localStorage|sessionStorage|sendBeacon|gtag|analytics|Sentry|document.cookie` and `innerHTML|bypassSecurityTrust|DomSanitizer|[outerHTML]` across `src/`. Results in §4.4 and §4.6.

**Dependency scan:** `npm audit` and `npm audit --omit=dev` — §8. (`./mvnw dependency:tree` is **not applicable**: this story has a verified zero-line backend diff, so the Java dependency baseline is unchanged from the US-011 audit, which recorded `spring-security 7.1.0` / `micrometer-core 1.17.0` with no applicable critical CVE.)

### 0.2 Mandatory explicit attestation (auth / crypto / PII are never approved silently)

- **Authentication — reviewed.** US-013 introduces **no new authentication path**. It adds no login, token, refresh, cookie, or credential handling. The `permissions[]` array it consumes rides the existing `GET /api/v1/users/me` call made by `login()`, `refresh()`, and the dashboard's priming `httpResource`, already Bearer-authenticated by `authInterceptor` and already reviewed under US-010. Token validation, expiry, refresh dedup, and replay protection are untouched — **verified by reading `auth.guard.ts` and `app.config.ts`, both of which this story leaves functionally unchanged**. The one authentication-adjacent decision is the composition rule `canActivate: [authGuard, permissionGuard]` (design decision 6), which is a *correctness* invariant (an entitled user must not be misrouted to `/access-denied` on cold start), not an authentication control. Sound.
- **Cryptography — reviewed, nothing to flag.** No crypto is introduced. No key material, no algorithm selection, no signing, no encryption. **Randomness: `Math.random` does not appear anywhere in this design and no token, nonce, or identifier is generated client-side**; the only identifier-like value in the touched code path is the pre-existing frontend `correlationId`, which this story does not alter. `SecureRandom`/`crypto.getRandomValues` is therefore not applicable rather than missing.
- **PII (org policy — customer PII must never be exposed) — reviewed field by field.** Every new value that crosses a boundary in this design was traced: `permissions[]` (closed-vocabulary `resource:action` strings, server-defined, non-PII), `requiredPermission` (single closed-vocabulary string — re-confirmed non-sensitive by US-011's review, which established it is a 7-item code-defined vocabulary echoed only to an already-authenticated caller), the new log record's `context.permission` (same vocabulary) and `context.route` (**the one field with a residual PII channel — see T-06**). No email, name, address, or free-text customer value is introduced into any log, DTO, URL, or store field by this story. Design §8.1's redaction analysis was independently re-verified against `logger.service.ts:25` and is correct as far as it goes; §4.4 and T-05/T-06 below record the two places it stops short.

### 0.3 Assets under protection

| Asset | Where it lives after US-013 | Sensitivity |
|---|---|---|
| The authorisation decision itself | **Server only** — `@RequiresPermission` (US-011) | Critical — and **untouched by this story** |
| `permissions[]` for the current user | In-memory `AuthStore._session` (`auth.store.ts:15`), same lifetime and exposure class as the existing `roles[]` | Low — the user's own entitlements, non-PII, closed vocabulary |
| `requiredPermission` on a 403 | Transient `AppError` object; developer diagnostic | Low — non-secret, already disclosed to this caller by the backend |
| The *existence and naming* of gated capabilities | Route table, lazy chunk names, permission strings in templates | Low — enumeration/reconnaissance value only (see T-09) |
| Access token | `AuthSession.accessToken`, in-memory | High — **not touched by this story**; verified no new read, log, or persistence path |

### 0.4 Trust boundaries

| # | Boundary | Crossed by this story? |
|---|---|---|
| B1 | Browser ⇄ Nexus API (network, TLS, Bearer) | **No new crossing.** Zero new endpoints, zero new requests, zero contract change (design §3). The story is a pure consumer of two already-shipped, already-reviewed contracts. |
| B2 | Server-authored response body ⇄ client-side type assertions | **Yes** — `permissions[]` and `requiredPermission` are newly *trusted into typed shapes* (T-04). |
| B3 | Client-side application state ⇄ the DOM | **Yes** — the directive newly makes DOM presence a function of `permissions[]` (T-01, T-02). |
| B4 | Application ⇄ browser console / future telemetry sink | **Yes** — one new log call site, plus a newly-populated field on an object that can reach `ErrorHandler` (T-05, T-06). |
| B5 | Application ⇄ browser persistence (localStorage / sessionStorage / history / Referer) | **No crossing introduced.** Verified by grep, not assumed (§4.4, §4.5). |
| B6 | User ⇄ their own browser (devtools, proxy) | **Inherently hostile and inherently unprotectable.** This is the boundary the entire "UX only" framing rests on — assessed in §4.1. |

**The critical structural observation:** the *authorisation trust boundary* (B1, server-side enforcement) is **not crossed, moved, weakened, or duplicated** by this story. Everything US-013 adds sits strictly *inside* the browser's already-untrusted zone. That is why no threat below reaches High or Blocker: there is no attacker-reachable server-side consequence available in this changeset.

---

## 1. Component STRIDE — `permissionGuard` (`core/guards/permission.guard.ts`, design §4.4)

| | Threat | Existing mitigation (design ref) | Verdict |
|---|---|---|---|
| **S** | Attacker forces the guard to return `true` by spoofing session state (devtools signal write, `/users/me` response override via a local proxy or devtools Network override, or simply calling `router.navigate()` directly) | Not prevented, and **deliberately not prevented**. §4.4 `@security` block; §11 guide block. The guard's *only* output is `true \| UrlTree` returned to the Angular Router — no application code can read it. | **Accepted by design — confirmed correct.** The bypass is trivial (§4.1) and the consequence is nil: the route activates, its component issues API calls, and every one 403s at `@RequiresPermission` (US-011 review: PASS, fail-closed on every branch). |
| **T** | Tamper with `route.data.permission` at runtime to change the required permission | Route `data` is compiled into the bundle; tampering it is equivalent to tampering the check itself — same class as S, same nil consequence. | No new risk. |
| **T** | Tamper *upstream*: a compromised or malicious backend returns an inflated `permissions[]` | Provenance is enforced server-side and locked by US-011's `JwtRs256Service.issue` regression test; a hostile server can already do anything. | Out of threat scope (server is in the TCB). |
| **R** | User denies attempting to reach a gated route | `logger.debug('permission_denied_client')` (§8.1) — **but this is a client-attested, `debug`-level, prod-inert, forgeable, suppressible signal.** The authoritative record is the backend's `nexus.rbac.permission_denied` counter + WARN log (US-011). | **No repudiation gap** — the authoritative record is server-side and already shipped. Forward risk recorded as R-c. |
| **I** | The redirect leaks RBAC internals into the address bar, browser history, bookmarks, or `Referer` | §4.4 deliberately emits **no query parameters** (`createUrlTree(['/access-denied'])`, with an inline comment stating why). | **Confirmed sufficient** — see §4.5 for the full leak-path sweep, including the two paths the design did not consider. |
| **I** | `state.url` (the attempted URL, query string included) is written to the console on denial | `debug` level; prod `logLevel: 'warn'` → verified inert in production (`logger.service.ts:135–137`, `enabled('debug')` = `0 >= 2` = false). `SENSITIVE_KEYS` (`:25`) tests **keys**, so `route` is not redacted. | **T-06 (Low) — required mitigation.** The value is unbounded and future-controlled. |
| **D** | Cost amplification on an unauthenticated path | The guard performs **zero I/O** — one synchronous `Array.prototype.includes` over ≤ ~20 entries (§4.4, §9). Denial triggers one lazy-chunk fetch of a static asset. No server work whatsoever. | **No DoS surface. Rate limiting is not applicable** — there is no unauthenticated server endpoint in this changeset to throttle. |
| **D** | Navigation loop → white screen / self-DoS | `/access-denied` is registered **top-level and unguarded** (§4.8). | Safe today. **T-07 (Low)** records the one way a future change breaks it, because §4.4 itself documents that Angular merges a parent route's `data` into child snapshots. |
| **E** | Regular user becomes admin by defeating the guard | Impossible via this component: the guard grants **no capability**. It gates only which Angular component is instantiated. Every privileged operation behind it is independently enforced server-side. | **No EoP path.** |
| **E** | Fail-open on missing/empty `data.permission` silently opens an intended-gated route | §6.2 accepts it deliberately; mitigations are the §11 guide entry + the §12.6 test convention. | **T-03 (Medium) — required mitigation.** I agree fail-open is *safe*; I do not accept a remembered-by-humans test convention as its only control when a mechanical one costs ~20 lines. |

---

## 2. Component STRIDE — `HasPermissionDirective` (`shared/directives/has-permission.directive.ts`, design §4.5)

| | Threat | Existing mitigation (design ref) | Verdict |
|---|---|---|---|
| **S** | Attacker forces a hidden control to render | Not prevented, by design. §4.5 `@security` block. | **Accepted — confirmed trivially achievable and consequence-free** (§4.1). Revealing a `<button>` does not authorise the action it fires. |
| **T** | Mutate the live permission array to flip every check at once | The design freezes only the **empty** case (`NO_PERMISSIONS`, §4.2). The populated array — `me.permissions` straight off the JSON body — is **not frozen**, and TypeScript `readonly` is erased at runtime. `authStore.permissions().push('users:delete')` mutates the one shared session array globally. | **T-10 (Low) — recommended.** Consequence is cosmetic (server enforces), but the design asserts an immutability contract it does not actually enforce, and the vector includes a compromised transitive dependency or an in-app bug, not just devtools. |
| **R** | — | Directive logs nothing, by explicit decision (§8.1, "no logging in the directive"). | Correct call. Per-change-detection-pass logging would be noise, and the directive is not an auditable event source. |
| **I** | **The directive is used to hide data that is already in the browser** — e.g. a salary column, an audit field, another tenant's row — while the backend still ships it in the payload | §4.5 `@security` JSDoc and §11's guide block both state the warning explicitly and well ("by the time it renders, that data has already been delivered to the browser"). | **T-02 (Medium) — required mitigation.** This is the single realistic route from US-013 to a genuine information disclosure, and it is *foreseeable*: `01-requirements.md` §1 lists "permission-based field hiding within a component" as explicit **future** scope. The wording exists; it must be made un-trimmable. |
| **I** | Permission strings in templates disclose the internal permission vocabulary via view-source | Inherent to any SPA; the vocabulary is non-secret (US-011 §3). | Accepted, no action. |
| **D** | N instances × permission-set change → DOM churn / CPU | `computed()` value-equality short-circuit + the plain `hasView` boolean, both explicitly justified (§4.5, decision 2); `.includes()` over ≤ ~20 entries; §12.3 mandates a "no churn" regression assertion comparing the retained `nativeElement` reference. | **Genuinely mitigated, and provable by the specified test.** No client-side DoS. |
| **D** | Unbounded `permissions[]` from a hostile server inflates every check | Server is in the TCB; `permissions[]` is RS256-provenanced. | Out of scope. |
| **E** | Directive outcome is consumed as a trust signal by a component | **Structurally impossible as designed** — `granted` is `private`, there is no output/exported signal, and the only effect is `createEmbeddedView`/`clear()`. A component cannot read the answer. | **Confirmed: the directive's API surface makes the R-1 misuse mode I most feared unavailable.** See §4.2 for where the real R-1 vector actually lives. |

---

## 3. Component STRIDE — remaining components

### 3.1 `AccessDeniedComponent` + the `/access-denied` route (design §4.6–§4.8)

| | Assessment |
|---|---|
| **S** | No identity is asserted, read, or displayed. The page injects **no state at all** (§4.6: "no injected state, no HTTP, no permission logic") and renders byte-identical output for every visitor, authenticated or not. Nothing to spoof. |
| **T** | Static template, no bindings from untrusted data, no `[innerHTML]`, no dynamic `href` — the only `href` is a compile-time `mailto:` literal. Nothing tamperable. |
| **R** | N/A — no action is recorded or performed. |
| **I** | **This is the design's strongest security decision and it is correct.** Because the page is stateless and context-free, it cannot leak *which* permission was missing, *which* URL was attempted, or *whether the resource exists*. It is therefore also immune to the enumeration oracle that a helpful "you need `roles:read` to view /roles" page would have created. Being unguarded is a *feature*: an unauthenticated visitor learns only that the string "Access denied" exists. |
| **D** | Unauthenticated, but a **static asset + client-side render with zero server calls** — no amplification, nothing to rate-limit. |
| **E** | Grants nothing. |
| **`mailto:support@yourcompany.example`** | **Non-issue, confirmed briefly as tasked.** Collects no input, submits nothing, is a static RFC 2606 reserved domain that cannot resolve, and `mailto:` is not a sanitiser-relevant scheme (Angular's URL sanitiser permits it; only `javascript:`/`data:` are neutralised). The only risk is a support request silently going nowhere — an availability/UX defect, not a security one. Design §16.1 item 6's release-checklist item is the right and sufficient response. **T-11 (Low), recorded, no security action.** |
| **Focus management** (`afterNextRender` → `h1.focus()`) | No security dimension. Focusing a visually-hidden element is an a11y trade-off the design already documents (§6.4 caveat, `role="alert"` as the independent announcement path). Not a threat. |

### 3.2 `AuthStore.permissions` / `AuthUser.permissions` / `MeApiResponse.permissions` (design §4.1–§4.3)

| | Threat | Existing mitigation | Verdict |
|---|---|---|---|
| **S** | Forged permission list | Server-side provenance (RS256 → tenant-scoped resolution → `/users/me`), locked by US-011's provenance test. The frontend **never decodes the JWT** — §4.1 even corrects the stale doc comment that wrongly implied it did. | Sound. Correcting that comment is a real (if small) security-hygiene win, because a future engineer reading "Extracted from the JWT access token" might add client-side JWT decoding as a "faster" source — which would be an unverified-claims trust bug. |
| **T** | Client-side mutation | Compile-time `readonly` only; populated array unfrozen. | **T-10 (Low)**, above. |
| **R** | — | N/A. | — |
| **I** | `permissions[]` persisted to `localStorage`/`sessionStorage`, or shipped to analytics | In-memory `signal` only (`auth.store.ts:15`). **Independently grep-verified: `src/` contains exactly one `localStorage` consumer — `theme.service.ts` (the theme string) — and zero `sessionStorage` writes, zero `sendBeacon`, zero `gtag`, zero telemetry sink. `auth.interceptor.spec.ts:336` already regression-tests that the refresh cycle writes to neither Storage.** | **Design claim confirmed true.** But see **T-08 (Low)**: `shared/types/auth.ts:52–54` — a file this story is already editing — carries a `@security` comment falsely asserting the session *is* "Stored in sessionStorage (not localStorage)". As written it **sanctions** persisting the session (now including `permissions[]`) to Storage. |
| **I** | Session data reaches a future error-tracking sink | `AppError` is the object that travels; see T-05. `AuthSession` itself is not attached to errors. | See T-05 for the adjacent path. |
| **D** | ~20-element array in one signal | Negligible. | No concern. |
| **E** | **`AuthStore.permissions()` is publicly readable by any component and can be used for a client-side-only trust decision** | `@security` JSDoc on both `AuthUser.permissions` (§4.1) and `AuthStore.permissions` (§4.2), each saying "never gate data access or trust decisions on this value". | **This — not the guard or the directive — is the actual R-1 vector.** See §4.2. The JSDoc placement on the *store accessor* is therefore load-bearing and must not be trimmed. |

### 3.3 `AppError.requiredPermission` + `apiErrorInterceptor` (design §4.9)

| | Threat | Existing mitigation | Verdict |
|---|---|---|---|
| **S** | — | N/A. | — |
| **T** | A MITM or hostile backend injects an arbitrary value | TLS for transport. `isProblemDocument` (`api-error.interceptor.ts:103–107`) validates **only** `typeof body.code === 'string'`; `requiredPermission` is copied unvalidated and merely *asserted* as `string \| undefined`. Design §4.9 flags this honestly and calls it acceptable. | **T-04 (Low) — required mitigation.** I agree with the design's *risk* assessment and disagree with its *response*: the fix is one line and removes a typed-but-unvalidated boundary permanently. Exploitability analysis in §4.6. |
| **R** | — | N/A. | — |
| **I** | Rendered to an end user, put in a URL, or sent to analytics, violating EPIC-002 §UX | JSDoc on the field (§4.9), the guide entry (§11), the Access Denied page's own `@security` note (§4.6), and §6.4's explicit consumer contract. Design §16.1 item 1 asks for a code-review-checklist line. **Nothing mechanical.** | **T-01 (Medium) — required mitigation** (assessment and proportionality argument in §4.3). |
| **I** | **The field reaches production `console.error` in full, via `GlobalErrorHandler`'s wholesale `JSON.stringify` of any non-`Error` value** | **None. The design did not identify this path.** | **T-05 (Medium) — required mitigation. This is the most material item this pass adds to §16.1.** Mechanics in §4.3. |
| **D** | — | One extra object key per problem document. | No concern. |
| **E** | — | Grants nothing; read by nothing today. | — |

### 3.4 The consumed backend contracts (design §3) — *does this story's consumption introduce a new issue?*

Out of scope to re-review (shipped and audited under US-010/US-011). Consumption-side check only:

- **`GET /api/v1/users/me`** — the story adds **one field read** to an existing, authenticated call. No new request, no new header, no auth change, no caching change (§9: "no cache is added, read, or invalidated"). The `?? []` default (§4.3) is the correct posture for a missing field: it degrades to *fewer* privileges, never more. **Fail-safe direction confirmed.**
- **403 `RBAC_001` / `ACCESS_DENIED`** — the story reads one optional property and deliberately **does not branch on `code`** (§4.9), so an `ACCESS_DENIED` 403 simply yields `undefined`. The design correctly forbids the inverse inference ("never key logic on 'status was 403 ⇒ this field is present'"). §3.2 also correctly establishes that `reason`, `userId`, and `tenantId` are **log-only** server-side and must not be modelled in `ProblemDocument` — verified to match US-011's review, which confirms the response body carries `requiredPermission` only. **Consumption is faithful to the contract; no new issue.**
- **Does the frontend ever trust `permissions[]` for something it shouldn't?** In this story: **no.** The complete set of consumers is (a) a router decision and (b) DOM instantiation. Neither is a data-access, cryptographic, tenancy, or capability decision. The forward-looking answer is T-02 + §4.2.

---

## 4. The specific challenges, answered independently

### 4.1 Is the devtools bypass really trivial, and really consequence-free?

**Trivial: yes — confirmed, by at least four independent routes**, none requiring source modification:

1. **Override the response.** Devtools Network request-override (or any local proxy) rewrites `GET /v1/users/me` to return an inflated `permissions` array. `buildSession` copies it verbatim into the store; the guard allows and the directive renders. No signature covers the response body, and none should — the body is not the enforcement artifact.
2. **Write the signal.** Angular devtools / `ng.*` global debug APIs reach the component/injector graph in a dev build; in a prod build the closure is minified but the store instance is still reachable, and `permissions()` returns a **mutable array** (T-10) — `.push()` alone is sufficient.
3. **Skip the guard entirely.** `router.navigate()` from the console, or simply requesting the URL — the guard is a client-side function in code the attacker controls.
4. **Ignore the UI.** Call the API directly. The directive's DOM decision is irrelevant.

**Consequence-free: yes — confirmed, and the confirmation is load-bearing on evidence outside this story.** Every operation behind a gated route or a hidden control is independently enforced by `@RequiresPermission`, which US-011's code audit verified is **fail-closed on every branch** (null/unauthenticated auth, non-`Map` details, absent/blank/wrong-typed `tenantId`, absent/wrong-typed `permissions`, wrong collection type, non-`String` elements — all throw 403, all unit-covered), with cross-tenant escalation proven closed end-to-end through the real filter chain in `CrossTenantPermissionIT`. **The design's claim is therefore not merely plausible, it is backed by shipped, merge-blocking evidence.** Recorded as verified rather than asserted.

**Two consequences that are NOT nil, and that the design does not state:**
- Forcing the guard open **downloads the gated feature's lazy chunk**, which is an unauthenticated static asset anyway — see T-09.
- The bypass yields a **UI in an impossible state**: buttons that render and then 403. That is an availability/UX defect, not a security one, and §8.3 already names it as expected behaviour. Acceptable.

### 4.2 Is it *possible today* for a careless future team to treat this as authorization? (the R-1 crux)

Each artifact's API surface was tested for *readability*, because a misuse requires a readable answer:

| Surface | Can application code read the permission verdict? | Therefore |
|---|---|---|
| `permissionGuard` | **No.** Returns `true \| UrlTree` to the Router. Not injectable, holds no state, exposes nothing. | Cannot become an implicit trust signal. |
| `HasPermissionDirective` | **No.** `granted` is `private`; there is no output, no exported signal, no host binding. Only effect is `createEmbeddedView`/`clear()`. | Cannot become an implicit trust signal. |
| `AuthStore.permissions()` | **Yes — public, synchronous, readable by any component or service.** | **This is the R-1 vector.** |

**Answer: yes, it is possible — but not through the two artifacts everyone will scrutinise.** The reachable misuse is a direct `authStore.permissions().includes(...)` test in arbitrary component code, and its dangerous form is narrow but real: a decision whose *entire* effect is client-side, where no server round-trip exists to independently enforce it. Concretely, only two such shapes exist in a system like Nexus:

1. **Client-side redaction of already-delivered data** — hiding a field/column/row the payload already contains. **This is T-02, and it is the one that will actually be attempted**, because `01-requirements.md` lists field-level hiding as explicit future scope.
2. **A purely client-side entitlement** — unlocking a local-only capability, a client-side computation, or a bundled asset.

Everything else — which endpoint to call, which form to show, which route to enter — is re-decided server-side and is therefore harmless to get wrong.

**This changes where the mitigation should point.** The design's mitigations are well aimed at the guard and directive (which cannot be misused as designed) and are *also*, correctly, present on the store accessor (§4.2's `@security` JSDoc). The required mitigations below therefore (a) keep that store-level JSDoc non-negotiable, and (b) target the *data-hiding* misuse specifically rather than the generic "not a security boundary" statement, which a future engineer will read as being about the guard.

**I agree with the design that R-1 cannot be fully closed mechanically at this story's size**, and I am **not** requesting the ESLint rule (§16.1 item 3). An ESLint rule can enforce guard *composition*; it cannot detect that a hidden table cell contains data the user should not see. That threat is semantic. **But two of the three documentation-only invariants in this story CAN be made mechanical for free, and T-03 requires exactly that.**

### 4.3 `AppError.requiredPermission` — is documentation-only acceptable for a 3-point story?

**Assessment: acceptable for the "someone renders it in a template" risk. NOT acceptable as the whole story, because there is a second, mechanical leak path the design missed.**

**On rendering it in a template (the risk the design considered):** the residual is genuinely small and is accepted without a lint rule, for three independent reasons. (a) The value is non-secret — US-011's review established `requiredPermission` is a closed, code-defined vocabulary echoed to an **already-authenticated** caller who just triggered the denial, so rendering it discloses to that user a string about their own failed action. (b) **Nothing reads the field anywhere in the codebase today** — the story ships it inert, so there is no existing misuse to inherit. (c) The design already places the prohibition at four separate points a future engineer would plausibly look (field JSDoc §4.9, guide §11, `AccessDeniedComponent` JSDoc §4.6, consumer contract §6.4) — that is unusually thorough, not thin. A custom ESLint/template rule to catch a `requiredPermission` interpolation would be new bespoke tooling with a real false-negative surface (aliasing, `@let`, computed signals defeat it trivially) for a Low-sensitivity string. **Disproportionate. Documentation plus the requested code-review-checklist line is the right call**, and T-01 keeps it as a required task so it cannot evaporate.

**On the path the design missed — this part is not accepted as-is.** The chain, verified end to end:

1. `apiErrorInterceptor` rejects with `appError` — a **plain object**, not an `Error` instance (`api-error.interceptor.ts:55`).
2. Any `AppError` left unhandled (a `subscribe()` with no error callback, an unhandled rejection, a throw in a template expression) reaches Angular's `ErrorHandler`.
3. `GlobalErrorHandler.handleError` calls `getErrorMessage`, which is not `instanceof Error` and not a string, so it falls through to **`JSON.stringify(error)`** (`global-error-handler.ts:57–69`).
4. That serialised payload is interpolated into the message passed to `logger.error(...)` (`global-error-handler.ts:31–38`).

Three verified mechanics make this a real leak rather than a theoretical one:

1. **`logger.error` is LIVE in production.** `environment.ts:55` sets `logLevel: 'warn'` so `minLevel = 2`; `enabled('error')` evaluates `3 >= 2` → **true** (`logger.service.ts:135–137`). The design's "inert in production" reasoning is correct for its own `debug` call site and **does not extend to this path**.
2. **`sanitizeParams` cannot help.** It scrubs `params.context` only (`logger.service.ts:111–130`); the serialised payload lands in the log **message string**, which is never scrubbed, and `SENSITIVE_KEYS` matches key *names* inside `context` — it never inspects the message.
3. **`JSON.stringify` takes the whole object.** `requiredPermission`, `traceId`, `correlationId`, `message`, and `details[]` all reach a production `console.error` in one line — precisely the "do not send it to analytics" prohibition, executed by the app's own default error handler.

And the forward risk is documented **in the repository itself**: `app.config.ts:48–50` states *"In production, you may want to send these to an error tracking service (Sentry, etc.)"* — attached to this exact handler. The day that ticket lands, the full `AppError` (every field, unredacted, unscrubbed) ships to a third party by default.

**Severity Medium, not High:** it requires a consumer to leave an error unhandled (plausible, not certain — every current consumer supplies an error callback, verified in `registration-form.component.ts:161–176` and `dashboard.component.ts:94–107`); the disclosed data is Low-sensitivity and belongs to the user seeing the console; and there is no remote sink today. **It is a defense-in-depth gap and a booby trap for the next telemetry ticket, not an exploitable defect** — hence Medium, and hence a documentation-plus-backlog mitigation rather than an in-story rewrite of `GlobalErrorHandler`, which is outside this story's diff.

### 4.4 Does anything land in `localStorage` / `sessionStorage` / analytics / beacons?

**Verified by grep, not by trusting the design. Result: no — with one documentation defect.**

| Sink | Finding |
|---|---|
| `localStorage` | Exactly one consumer in `src/`: `theme.service.ts:91,106` (the theme string, strictly validated to `light`/`dark`). No session, no permissions, no token. |
| `sessionStorage` | **Zero writes anywhere in `src/`.** Already regression-tested: `auth.interceptor.spec.ts:336` — *"proactive refresh cycle does not write to localStorage or sessionStorage"*. |
| `sendBeacon` / `gtag` / analytics SDK / Sentry | **Zero.** No telemetry sink exists (matching design §8.2 and `ARCHITECTURE.md`'s lack of frontend log shipping). The only occurrences of the words are the `app.config.ts:50` aspiration and the `app-error.ts:38` JSDoc phrase "passed to analytics", both prose. |
| `document.cookie` | **Zero.** The refresh cookie is `HttpOnly` and server-managed. |
| Browser history / bookmarks / `Referer` | No query params on the redirect (§4.4 of the design), so no RBAC value enters the URL. See §4.5. |
| Console | The one intended `debug` line (prod-inert) — **plus the unintended production-level path T-05**. |

**The documentation defect (T-08):** `shared/types/auth.ts:52–54` asserts, under a `@security` heading, that `AuthSession` is *"Stored in sessionStorage (not localStorage) to limit exposure to XSS. Cleared on logout, page close, or on 401."* **This is false** — `auth.store.ts:15` holds it in an in-memory `signal` and nothing persists it. The comment is not merely stale: it **reads as an instruction**, and this story is about to add `permissions[]` to the very object it describes. A future engineer "restoring the documented behaviour" would persist the whole session — token included — to Storage and reasonably believe they were following the security note. US-013 §4.1 is already correcting the sibling inaccuracy on `auth.ts:4` in this exact file; correcting this one is the same task and the same edit session.

### 4.5 Is "no query parameters on the redirect" sufficient? Any other leak path?

**The decision is correct and endorsed.** Suppressing `?permission=` / `?from=` keeps RBAC internals out of the address bar, browser history, bookmarks, and any `Referer` sent from `/access-denied` to an outbound link — and the design's reasoning names each of those. It also has a benefit §4.4 does not claim: because the page is context-free, it **cannot function as an enumeration oracle** (no "resource exists but you lack `x:y`" versus "no such resource" distinction is observable). **Do not add the parameters later "for better UX".**

Every other channel a permission value could escape through was swept. **Two were not considered by the design:**

| Channel | Status |
|---|---|
| URL / history / bookmarks / `Referer` | Closed by design (no query params, static page, no dynamic outbound links). |
| Page content | Closed — static copy only; `AccessDeniedComponent` injects nothing (§4.6). |
| `document.title` | Not set by this design, so no leak. Worth not "improving" into a title that embeds the permission. |
| The intended `logger.debug` line | Prod-inert; **but `context.route` carries the full `state.url` including query string — T-06.** Not identified by §8.1, whose redaction analysis correctly checks `SENSITIVE_KEYS` against the *key* `route` and stops there. Today's routes carry no PII; the field is a standing invitation for a future navigation with an email or identifier in the query string to write customer PII to a dev console. Cost to close: strip at the first `?`. |
| `GlobalErrorHandler` to production `console.error` | **Open — T-05**, §4.3. Not a *guard* leak, but the same asset class, reached from the 403 path this story newly populates. |
| localStorage / sessionStorage / cookies / beacons | Closed — §4.4. |

### 4.6 `isProblemDocument` validates only `code` — real exploitability, or theory?

**Real exploitability today: effectively nil. The design's risk read is confirmed — and the one-line fix is still required.**

Hostile-input walk-through. A malicious/compromised backend or a MITM (already outside the TLS threat model) returns a problem document whose `requiredPermission` is attacker-chosen:

- **As a script payload** — would need a template sink. **Grep-verified across all of `src/`: zero `innerHTML`, zero `[innerHTML]`, zero `outerHTML`, zero `DomSanitizer`, zero `bypassSecurityTrust*`.** Angular interpolation contextually escapes, so even the forbidden render yields inert text, not script. **No XSS route exists — A03 not reachable.**
- **As an object / array / number** — `typeof` lies, but the value is read by nothing, so no `.length` / `.toLowerCase()` / spread can throw. Worst case if someone later reads it: a `TypeError` in a dev build.
- **CRLF / log injection** — the field is *not* logged: the interceptor's log params carry `errorCode`, `status`, `statusText`, `url` — **not** `requiredPermission` (verified `api-error.interceptor.ts:24–36`). It reaches a log only via T-05's `JSON.stringify`, which escapes control characters. **No log-forging route.**
- **Prototype pollution** — the object literal in `toAppError` assigns named keys explicitly; no spread of the untrusted body, no `Object.assign`, no dynamic key. **Closed.**
- **Into a URL or `href`** — nothing constructs a URL from it, and Angular's URL sanitiser would neutralise a `javascript:` value in an `[href]` anyway.

**So: theoretical, exactly as §4.9 says.** The reason to require the fix anyway is not exploitability — it is that the type is currently a **lie at a trust boundary (B2)**, and the design's whole safety argument for the field rests on downstream code behaving correctly around a value whose declared type it cannot rely on. One narrowing expression makes `string | undefined` true at runtime, costs one line and one spec case, and cannot regress. **A08 (software and data integrity — trusting response shape without validation).**

**Pre-existing corroboration, and a genuine forward-flag (out of scope for US-013):** the same unvalidated copy already applies to `details`, which — unlike `requiredPermission` — **is rendered**: `registration-form.component.ts:164–167` iterates `err.details` and pushes `fe.message` into `ctrl.setErrors({ server: fe.message })`, which the form renders. A hostile body could supply `details` as a non-array (a `TypeError` in the error handler, breaking the form's error path) or with attacker-chosen `field`/`message` strings (escaped by interpolation, so text-injection only). **This is not US-013's defect and must not be fixed here** — but it proves that "validate only `code`" is a real weakness with an already-rendered field, and it strengthens the case for not adding a second unvalidated field. Recorded as **T-12 (Low, pre-existing, forward-flag)**.

### 4.7 Fail-open on missing `data.permission` — independent re-check

**The behaviour is safe. A remembered test convention is not a sufficient control for it.**

Why safe (independently reached, same conclusion as §6.2): the guard is not a security boundary, so "open" means "the router lets you render a component" — every operation inside it is still 403-enforced server-side. Fail-*closed* would be strictly worse: a `data` typo would lock every user, including admins, out of a working feature, converting a config error into an outage. And §6.2's reasoning for **not** logging a warning on that branch is endorsed: it also fires for the legitimate "gating intentionally removed, guard left behind" case, and a per-navigation warning trains reviewers to ignore warnings. **The design's judgement here is better than the obvious alternative.**

Why the control is nonetheless insufficient: the design's own words are the indictment — the failure is *silent* and "impossible to catch except by a route-specific test that must be remembered." §12.6 convention 4 is a **human-memory control**, and it decays exactly when it matters: the tenth route, added by a team that never read this design doc. The identical exposure applies to decision 6 (composition order), the story's *other* documentation-only invariant.

**Both collapse into one mechanical control that needs no new tooling** — a single table-driven spec that walks the exported `routes` array (recursing `children`, tracking ancestors) and asserts, for every route whose `canActivate` includes `permissionGuard`: (a) `data['permission']` is a non-empty string, and (b) `authGuard` appears earlier in the same `canActivate` array or on an ancestor. Guard functions compare by reference identity, so this is straightforward; `app.routes.ts:122` shows the shape. Roughly 20 lines, zero dependencies, **applies automatically to every future route without anyone remembering anything**, and turns two prose invariants into a red build. Today it is vacuously green (no route uses the guard), which is the right time to add it. **Known limitation to record with it:** `loadChildren` route arrays (e.g. `AUTH_ROUTES`) are not statically reachable from `routes`, so a lazily-loaded child route table needs the same assertion in its own spec — note it in the spec's own comment. **T-03 (Medium), required.** This is the single highest-value change this threat model asks for, and it is a *test* task, not a design change.

---

## 5. Findings

### [Medium] T-01 — `AppError.requiredPermission` has no mechanical control against being rendered to end users
**File:** `nexus-frontend/src/app/shared/types/app-error.ts` (new field per design §4.9) · `nexus-frontend/src/app/core/http/api-error.interceptor.ts:67–73`
**Issue:** EPIC-002 §UX forbids surfacing RBAC internals to end users. The prohibition is carried by JSDoc in four places and by the §11 guide entry; nothing prevents a future template from interpolating `error.requiredPermission`.
**Risk:** An end user is shown an internal permission identifier — a minor information disclosure (**A01 / A04**) and a compliance deviation from the epic's UX contract. Not attacker-triggerable; the value is a non-secret, closed-vocabulary string about the viewer's own failed action.
**Fix (required, documentation-level — proportionality argued in §4.3):** (a) keep the `@security` JSDoc on the field verbatim as designed; (b) add one line to the code-review checklist: *"AppError.requiredPermission must never be bound in a template, placed in a URL, or forwarded to a telemetry sink."* Do **not** build a bespoke lint rule for this — §4.3 explains why it is disproportionate and unreliable.

### [Medium] T-02 — `*appHasPermission` will be reached for as a data-redaction tool, which is a real information disclosure
**File:** `nexus-frontend/src/app/shared/directives/has-permission.directive.ts` (new, design §4.5) · `docs/DEVELOPMENT_GUIDE.md` (AC-6 entry, design §11)
**Issue:** The directive hides DOM, not data. Wrapping a payload-resident value in `*appHasPermission` leaves it fully readable in the network response and the JS heap. `01-requirements.md` §1 lists "permission-based field hiding within a component" as explicit **future** scope, so this misuse is not hypothetical — it is scheduled. The correct warning already exists in the directive JSDoc and the §11 draft; the risk is that it gets trimmed as boilerplate during implementation or review.
**Risk:** A future feature "hides" salary, audit, PII, or cross-tenant fields with the directive while the API still returns them, producing a genuine unauthorised disclosure (**A01 Broken Access Control**, **A04 Insecure Design**). This is the only path from US-013 to real data exposure.
**Fix (required):** Make the wording un-trimmable rather than advisory. (a) The AC-6 documentation task must carry, as an explicit **acceptance criterion**, that the guide contains the clause *"never use appHasPermission to hide data — by the time it renders, the data is already in the browser"* and that the directive JSDoc retains its equivalent sentence. (b) Add the matching code-review-checklist line: *"if appHasPermission wraps data rather than a control, the field must also be omitted server-side."*

### [Medium] T-03 — Two load-bearing guard invariants (fail-open `data.permission`, `authGuard`-before-`permissionGuard`) are enforced only by human memory
**File:** `nexus-frontend/src/app/core/guards/permission.guard.ts` fail-open branch (design §4.4 line 440, §6.2) · design decision 6 (composition) · design §12.6 convention 4
**Issue:** Both invariants are documented and both fail **silently** — a typo'd `data.permission` opens an intended-gated route with no error, warning, log, or failing test; a missing `authGuard` misroutes entitled users to `/access-denied` on cold start. The stated control is a per-route test convention that a future team must remember to apply.
**Risk:** A route intended to be gated ships ungated (client-side only — the server still enforces, so the impact is a confusing UI and a false sense of coverage, not a breach), or an entitled user is locked out (availability). The deeper risk is **erosion of the "UX only" posture into an assumed control** that silently is not applied — R-1 by another route.
**Fix (required):** Add one table-driven spec (e.g. `app.routes.spec.ts`) that walks the exported `routes` tree and asserts, for every route whose `canActivate` includes `permissionGuard`: (a) `data['permission']` is a non-empty string, and (b) `authGuard` precedes it in the same array or sits on an ancestor. Roughly 20 lines, no new tooling, vacuously green today, automatically binding on every future route. Record in the spec's own comment that `loadChildren` route arrays are not statically reachable and need the same assertion locally. Full rationale: §4.7.

### [Medium] T-05 — A full `AppError` (including `requiredPermission`) is `JSON.stringify`'d into a **production-level** log by `GlobalErrorHandler`, and that handler is the documented future home of an error-tracking SDK
**File:** `nexus-frontend/src/app/core/errors/global-error-handler.ts:57–69` (`getErrorMessage`) and `:31–38` (`logger.error`) · reached from `nexus-frontend/src/app/core/http/api-error.interceptor.ts:55` · sink aspiration recorded at `nexus-frontend/src/app/app.config.ts:48–50`
**Issue:** `apiErrorInterceptor` rejects with a **plain object**, not an `Error`. Any `AppError` that reaches Angular's `ErrorHandler` (a `subscribe()` without an error callback, an unhandled rejection, a throw in a template expression) is not `instanceof Error`, so `getErrorMessage` falls through to `JSON.stringify(error)` and the entire object — `requiredPermission`, `traceId`, `correlationId`, `message`, `details[]` — is embedded in the log **message**. Three verified mechanics make this live: `logger.error` is **enabled in production** (`logLevel: 'warn'` gives `minLevel 2`, and `3 >= 2` is true, `logger.service.ts:135–137`); `sanitizeParams` scrubs `context` only and never the message (`:111–130`); and `SENSITIVE_KEYS` matches key names, not message content (`:25`). **The design's "inert in production" argument covers only its own `debug` call site and does not extend here — §16.1 did not identify this path.**
**Risk:** Today, unredacted diagnostic disclosure to the production browser console — low impact, self-disclosure, no remote sink. Tomorrow, `app.config.ts:50` explicitly anticipates wiring Sentry to this handler, at which point the full `AppError` ships to a third party by default, mechanically violating the field's own "do not send it to analytics" contract. **A09 (security logging failure) and A01-adjacent information disclosure.**
**Fix (required, two parts, both cheap and neither an in-story rewrite):** (a) extend the `@security` JSDoc on `AppError.requiredPermission` to name this concrete path — that an AppError reaching Angular's ErrorHandler is serialised in full into a production-level log, and that any error-tracking integration must redact this field — so the constraint is discoverable at the field, not only in the guide; (b) raise a backlog ticket, referenced from this threat model, requiring that `GlobalErrorHandler` stop `JSON.stringify`-ing non-`Error` values wholesale and that **any** error-tracking integration allow-list `AppError` fields rather than forwarding the object. Do **not** rewrite `GlobalErrorHandler` inside this 3-point story.

### [Low] T-04 — `requiredPermission` is asserted, not validated, at the response trust boundary
**File:** `nexus-frontend/src/app/core/http/api-error.interceptor.ts:103–107` (`isProblemDocument`, validates only `code`) and `:67–73` (`toAppError`)
**Issue:** The new field is copied straight out of an untrusted body and typed `string | undefined`, a claim nothing checks. Design §4.9 flags this and accepts it.
**Risk:** Theoretically nil today, and confirmed so: **grep-verified zero `innerHTML` / `bypassSecurityTrust*` / `DomSanitizer` in all of `src/`**, so no XSS sink exists even if the field were rendered (interpolation escapes); the field is not logged by the interceptor, so no CRLF or log-forging route; keys are assigned explicitly, so no prototype pollution. The real cost is a **false type at a trust boundary (B2)** that the design's own safety argument leans on. **A08.**
**Fix (required — one line, cannot regress):** narrow on copy, assigning `requiredPermission` only when `typeof body.requiredPermission === 'string'` and `undefined` otherwise, with one spec case for a non-string value. Full exploitability walk-through: §4.6.

### [Low] T-06 — The denial log records the full `state.url`, query string included
**File:** `nexus-frontend/src/app/core/guards/permission.guard.ts` denial log (design §4.4 lines 444–448, §8.1)
**Issue:** `context: { route: state.url }` captures the attempted URL verbatim. `SENSITIVE_KEYS` tests **keys**, so nothing inspects the value, and `sanitizeParams` will not touch it. Prod-inert at `debug`, so this is a **development-console** exposure only.
**Risk:** No current route carries PII, so today's leak is nil. The field is unbounded and future-controlled: the first navigation carrying an email or identifier in a query string writes customer PII to a developer console, against the org PII-in-logs policy. **A09.**
**Fix (required — one expression):** log the path only, stripping at the first question mark, with a short inline comment stating that the query string is deliberately dropped to keep unbounded, potentially-PII values out of logs. Update the §12.1 log assertion accordingly. The path segment is all §8.3's diagnostic actually needs.

### [Low] T-07 — `/access-denied` must remain top-level and unguarded, or the denial redirect becomes a navigation loop
**File:** `nexus-frontend/src/app/app.routes.ts` (new route, design §4.8)
**Issue:** Design §4.4 correctly notes that Angular's default `paramsInheritanceStrategy` merges a parent route's `data` into child snapshots. If `/access-denied` were ever nested under an ancestor carrying `data.permission` and `permissionGuard`, a denial would redirect to a route that itself denies, producing repeated navigation or a blank screen.
**Risk:** Client-side self-DoS and total loss of the denial UX. Not attacker-triggerable; requires a future refactor. Safe as designed (top-level, unguarded).
**Fix (required — one clause):** state in the AC-6 guide entry, and in the route's own JSDoc block that §4.8 already drafts, that `/access-denied` **must remain a top-level, unguarded route and must never become a descendant of a route carrying `data.permission`**. The T-03 route spec incidentally catches the guarded-descendant variant.

### [Low] T-08 — A false `@security` comment in a file this story is editing sanctions persisting the session — now including `permissions[]` — to `sessionStorage`
**File:** `nexus-frontend/src/app/shared/types/auth.ts:52–54`
**Issue:** The `AuthSession` doc block asserts the session is *"Stored in sessionStorage (not localStorage) to limit exposure to XSS. Cleared on logout, page close, or on 401."* **This is factually false** — `auth.store.ts:15` holds it in an in-memory `signal`, and grep confirms zero `sessionStorage` writes in `src/` (`auth.interceptor.spec.ts:336` already regression-tests this). Under a `@security` heading, the sentence reads as an instruction.
**Risk:** A future engineer "restoring the documented behaviour" persists the whole `AuthSession` — **access token included** — to `sessionStorage`, believing they are following the security note, converting an XSS into token theft (**A02 / A07**). US-013 raises the stakes by adding `permissions[]` to the described object.
**Fix (required — one line, same file, same edit session):** while §4.1 is already correcting the sibling inaccuracy at `auth.ts:4`, correct `:52–54` to state that the session is **in-memory only (never `localStorage` or `sessionStorage`), is lost on reload, and is restored via the HttpOnly refresh cookie by `authGuard`**. Fold into the same task.

### [Low] T-09 — A permission-gated lazy chunk is still an unauthenticated static asset
**File:** `docs/DEVELOPMENT_GUIDE.md` (AC-6 entry, design §11) — architectural property, no single code site
**Issue:** `canActivate: [authGuard, permissionGuard]` gates *component activation*, not *chunk delivery*. Anyone, including an unauthenticated visitor who guesses the filename, can fetch a gated feature's JS chunk and read its templates, endpoint paths, permission strings, and client-side business rules. Inherent to any SPA and **not created by US-013**, but US-013 is the story that establishes the "gate a route" pattern and will be read as if it provided confidentiality.
**Risk:** Reconnaissance — internal endpoint and permission enumeration, disclosure of unreleased feature names, and, if anyone ever embeds a key, internal hostname, or proprietary rule in an "admin-only" component, real secret exposure (**A01 / A02**).
**Fix (required — one clause in the guide, alongside the existing "UX only" block):** *"Route gating does not protect code. A gated route's lazy chunk is an unauthenticated static asset: never place secrets, credentials, internal hostnames, or confidential business logic in a permission-gated component."*

### [Low] T-10 — The live `permissions[]` array is not frozen, so `readonly` is a compile-time-only fiction
**File:** `nexus-frontend/src/app/features/auth/auth.service.ts` `buildSession()` (design §4.3) · `nexus-frontend/src/app/core/auth/auth.store.ts` (design §4.2)
**Issue:** Design §4.2 freezes only the empty case (`NO_PERMISSIONS = Object.freeze([])`) and explicitly reasons about mutation there — but the populated array is `me.permissions` straight off the JSON body, unfrozen. TypeScript `readonly` is erased at runtime, so a single `push()` on the value returned by `authStore.permissions()` permanently mutates the one shared session array that every subsequent guard and directive check reads.
**Risk:** Cosmetic in isolation (the server still enforces), but the design asserts an immutability contract it does not enforce, and the vector is broader than devtools: a compromised transitive npm dependency or an in-app bug could silently and globally alter every client-side permission check. **A08 defense-in-depth.**
**Fix (recommended, one line):** freeze a copy in `buildSession` so the freeze is symmetric with `NO_PERMISSIONS`, turning tamper attempts into a `TypeError` in strict mode.

### [Low] T-11 — `mailto:support@yourcompany.example` placeholder — confirmed non-issue security-wise
**File:** `nexus-frontend/src/app/shared/pages/access-denied/access-denied.component.ts` (design §4.6)
**Issue / Risk:** Collects no input, submits nothing, is a static compile-time literal on an RFC 2606 reserved domain that cannot resolve, and `mailto:` is neither neutralised by nor relevant to Angular's URL sanitiser. **No injection, no SSRF, no open redirect, no data exfiltration.** The only consequence is a support request going nowhere — an availability/UX defect.
**Fix:** No security action. Design §16.1 item 6's release-checklist item is sufficient and appropriate; keep the `TODO(PM)` marker.

### [Low] T-12 — Pre-existing, NOT this story: `details` is copied unvalidated *and is rendered*
**File:** `nexus-frontend/src/app/core/http/api-error.interceptor.ts:72` reaching `nexus-frontend/src/app/features/auth/registration-form/registration-form.component.ts:164–167`
**Issue:** The same "validates only `code`" weakness applies to `details`, which unlike `requiredPermission` **is** rendered: `err.details` is iterated and each `message` is pushed into the form control's errors and displayed. A hostile body could send `details` as a non-array (a `TypeError` breaking the form's error path) or with attacker-chosen strings (escaped by interpolation, so text injection only, no XSS).
**Risk:** Requires a hostile or compromised backend, or a broken TLS assumption. Low.
**Fix:** **Out of scope for US-013 — do not fix here.** Recorded as a forward-flag for a future `core/http` hardening ticket (validate the full `ProblemDocument` shape, including `details` element shapes). Cited only because it demonstrates that T-04's "validate on copy" habit has already been needed once.

---

## 6. Required mitigations — each becomes a task in `/breakdown`

**These six are conditions of this threat model's PASS. `04-tasks.md` must contain a task for each, traceable back to its T-number.** None of them changes the design's API, component boundaries, or decisions — they are documentation wording made binding, one test, and two one-line code hardenings.

| # | Threat | Required mitigation | Suggested task home | Cost |
|---|---|---|---|---|
| M-1 | **T-03** | Add a table-driven route-table spec asserting, for every route whose `canActivate` includes `permissionGuard`: a non-empty string `data['permission']`, **and** `authGuard` earlier in the same array or on an ancestor. Comment the `loadChildren` limitation in the spec. | **New task** (new spec file, e.g. `app.routes.spec.ts`) — do not bundle with the guard task | ~20 lines |
| M-2 | **T-04** | Narrow `requiredPermission` on copy in `toAppError` (assign only when `typeof` is `string`) plus one spec case for a non-string value. | The §4.9 interceptor task | 1 line + 1 test |
| M-3 | **T-06** | Log the path only in the denial log (strip at the first question mark) with an inline comment explaining that the query string is dropped to keep unbounded/PII values out of logs. Update the §12.1 log assertion. | The §4.4 guard task | 1 expression |
| M-4 | **T-08** | Correct the false `sessionStorage` claim at `shared/types/auth.ts:52–54` to "in-memory only, never `localStorage`/`sessionStorage`, restored via the HttpOnly refresh cookie" — in the same edit as the §4.1 `auth.ts:4` correction. | The §4.1 `auth.ts` task | 1 line |
| M-5 | **T-01, T-02, T-05, T-07, T-09** | The AC-6 documentation task must carry these as **acceptance criteria**, not prose to be trimmed: (a) the "never hide data with `*appHasPermission`" clause verbatim (T-02); (b) "route gating does not protect code — no secrets in a gated lazy chunk" (T-09); (c) "`/access-denied` stays top-level and unguarded, never a descendant of a `data.permission` route" (T-07); (d) the `AppError.requiredPermission` JSDoc extended to name the `ErrorHandler` serialisation path (T-05a); (e) three code-review-checklist lines — never render/URL/forward `requiredPermission` (T-01), directive-hidden data must also be omitted server-side (T-02), no secrets in gated components (T-09). | The §11 / §13.1 guide task + the §4.9 `app-error.ts` task | Wording only |
| M-6 | **T-05b** | Raise a backlog ticket, referenced from this file: `GlobalErrorHandler` must not `JSON.stringify` non-`Error` values wholesale, and **any** error-tracking/telemetry integration must allow-list `AppError` fields rather than forwarding the object. Add it to design §16.3's backlog list. | Backlog entry (out of story) | Ticket only |

**Explicitly NOT required (and recommended against):**
- **A custom ESLint/template-lint rule for a `requiredPermission` interpolation** — disproportionate for a Low-sensitivity string with zero current readers, and trivially defeated by aliasing / `@let` / computed signals (§4.3). Design §16.1 item 3 offered it as Security's call; **the call is no.**
- **An ESLint rule forbidding `permissionGuard` without a sibling `authGuard` / `data.permission`** — M-1's spec achieves the same guarantee with less machinery and no new plugin.
- **A `logger.warn` on the fail-open branch** — §6.2's reasoning against it is sound (it also fires for legitimately de-gated routes, and per-navigation warnings train reviewers to ignore warnings). M-1 replaces it with a build-time check, which is strictly better.
- **Rewriting `GlobalErrorHandler` in this story** — outside the diff; M-6 carries it forward.

## 7. Recommended (not required, not gate-blocking)

| # | Threat | Recommendation |
|---|---|---|
| R-a | **T-10** | Freeze a copy of the populated array in `buildSession`, making immutability real and symmetric with `NO_PERMISSIONS`. |
| R-b | **T-09 / RR-1** | When Epic 3 ships the first genuinely gated route, add one Playwright assertion that the API 403s even when the client-side check is bypassed — converting "the backend enforces this" from an inherited claim into local, continuous evidence. Complements the deferred E2E already in §16.3. |
| R-c | **T-05 / RR-8** | If frontend log shipping (§16.3 backlog) ever lands, treat `permission_denied_client` as **non-admissible security evidence** — it is client-attested, forgeable, and suppressible. The authoritative denial record remains the backend's `nexus.rbac.permission_denied` counter. |
| R-d | **T-12** | Future `core/http` hardening ticket: validate the full `ProblemDocument` shape, including `details` element shapes, rather than only `code`. |

---

## 8. Dependency / supply-chain scan (A06, A08)

**Backend — `./mvnw dependency:tree` not applicable, deliberately skipped with justification.** US-013 has a **verified zero-line backend diff** (design §2, §3: no migration, no entity, no endpoint, no contract change), so the Java baseline is byte-identical to the one audited in US-011's review (`spring-security 7.1.0`, `micrometer-core 1.17.0`, no applicable critical CVE). Re-running it would reproduce that story's output; the scheduled OWASP dependency-check job continues to cover the transitive baseline.

**Frontend — `npm audit` run.**

| Scope | Result |
|---|---|
| **Production runtime (`npm audit --omit=dev`)** | **0 vulnerabilities.** The shipped bundle's dependency tree is clean. |
| Full tree (incl. dev / build / test) | 15 findings: 1 critical, 6 high, 5 moderate, 3 low — `tar` (critical: PAX type-confusion crash, decompression DoS, infinite loop, recursion stack overflow), `postcss` (source-map path traversal), `nanoid`, `brace-expansion`, `fast-uri`, `esbuild` (Windows dev-server arbitrary file read), `@babel/core` (via `@angular/build`), `undici`, `hono` / `@hono/node-server` (via `@modelcontextprotocol/sdk` → `@angular/cli`), `ip-address`. |

**Assessment:** **US-013 adds no dependency** — design §4.10 requires the new fixtures module to import nothing beyond `@angular/core`, and no other new artifact needs a package. `package.json` is untouched, so this story does not change the A06 posture in either direction. Every finding above is **dev/build-toolchain only and pre-existing**: none is reachable from the production bundle (`--omit=dev` is clean), and the realistic exploitation preconditions are local — a hostile repository or tarball, or a crafted source map processed by the local dev server or a CI runner (the `esbuild` advisory is explicitly Windows dev-server-scoped, and this is a Windows dev environment). **Out of scope for US-013 and must not be smuggled into it**, but recorded here as a real platform hygiene item: **recommend a separate dependency-hygiene ticket** to apply the non-breaking `npm audit fix` subset and evaluate the `@angular/cli` bump that clears the `@hono/node-server` chain — verified against the known Windows lockfile-pruning hazard for `@emnapi` entries before any lockfile is committed. **No `npm audit` finding blocks this story.**

---

## 9. Residual risk accepted (after all required mitigations)

| # | Residual risk | Why accepted |
|---|---|---|
| RR-1 | **A user can always defeat every client-side check** — force the guard true, reveal hidden controls, or skip the UI entirely. | Structural and unfixable in a browser; explicitly the design's premise. Consequence is nil because `@RequiresPermission` independently 403s every operation — verified fail-closed on every branch by US-011's audit, and proven end to end through the real filter chain by `CrossTenantPermissionIT`, a merge-blocking gate. |
| RR-2 | **R-1 remains partly process-mitigated.** M-1 mechanises guard *composition* and *route config*; it cannot mechanise "this hidden element contains data the user should not see" (T-02) or "do not render `requiredPermission`" (T-01), both of which stay documentation plus code review. | The un-mechanisable part is semantic, not syntactic — no linter can classify a template value's sensitivity. The mitigation set is placed where misuse is actually reachable: the `@security` JSDoc on **`AuthStore.permissions`** (§4.2 of the design), which this review established is the *only* readable trust-signal surface in the story, plus binding guide wording and review-checklist lines. Two of three documentation-only invariants become mechanical; the third is bounded because a directive-hidden field is only dangerous if the *backend* also over-returns, which is a server-side review concern with its own controls. |
| RR-3 | Guard fail-open on a missing `data.permission` remains **silent at runtime**. | Deliberate and correct — fail-closed would turn a config typo into a user-facing outage — and no longer *undetectable*: M-1 turns it into a build-time failure for every statically-declared route. Residual: `loadChildren` child route tables, which M-1's own comment flags for local coverage. |
| RR-4 | "Session not yet loaded" is indistinguishable from "genuinely zero permissions" (requirements R-4, design §6.3). | No security consequence in either direction — the ambiguity can only *hide* UI or *deny* navigation, never grant. Availability-only, self-correcting because the directive is reactive, and mitigated for the one user-visible case (cold start) by the composition rule, now enforced by M-1. |
| RR-5 | A gated feature's lazy chunk stays publicly downloadable (T-09). | Inherent to SPA bundling; not introduced or worsened by this story. Reduced to a *documented* constraint by M-5(b) so no one places a secret behind route gating believing it is protected. |
| RR-6 | `AppError` fields can still reach the production console through `GlobalErrorHandler` until M-6's backlog ticket lands. | Low-sensitivity data, console-only, **no remote sink exists today** (grep-verified: zero analytics / beacon / Sentry code in `src/`), and it requires a consumer to leave an error unhandled — every current consumer supplies an error callback. M-5(d) makes the constraint discoverable at the field before any sink is ever wired. |
| RR-7 | Dev/build toolchain carries 15 pre-existing `npm audit` findings, 1 critical. | Zero production-bundle exposure (`--omit=dev` clean), local-only exploitation preconditions, pre-existing, and outside a frontend-only 3-point story's diff. Forwarded as its own hygiene ticket (§8). |
| RR-8 | Client-side denial telemetry is unauthoritative and forgeable. | By design — `debug` level, prod-inert, no metric, no sink (§8.1 / §8.2). The authoritative record is the server's counter and WARN log. R-c guards the only way this becomes a problem. |

---

## 10. Verdict

### PASS WITH REQUIRED FOLLOW-UPS

- **Blockers: 0.** Nothing in this design is exploitable, and — critically — **nothing in it can be made exploitable by an attacker**, because every artifact it adds lives entirely inside the browser's already-untrusted zone. The authorisation trust boundary is not crossed, moved, duplicated, or weakened.
- **High: 0.**
- **Medium: 4** — T-01 (`requiredPermission` has no mechanical render control), T-02 (directive-as-redaction is a scheduled future misuse), T-03 (two silent guard invariants rest on human memory), and **T-05 (the `GlobalErrorHandler` serialisation path — the one materially new threat this pass adds to the architect's §16.1 checklist)**. All four are defense-in-depth or future-facing; none is exploitable in the shipped changeset.
- **Low: 6** — T-04, T-06, T-07, T-08, T-09, T-10 — **plus 2 informational**: T-11 (confirmed non-issue) and T-12 (pre-existing forward-flag).
- **Required mitigations: 6** (§6). Each must become a task in `/breakdown`. Four are wording made binding, one is a ~20-line spec, two are one-line code changes, and one is a backlog ticket.

**The design's central claim survives STRIDE: this is UX polish, not a security boundary, and treating it as such is correct.** The framing is not merely asserted — it is *structurally* true. This review verified independently that the guard's verdict is unreadable by application code (it goes only to the Router) and that the directive's verdict is unreadable too (`granted` is private, no output, no host binding). The only readable trust surface the story creates is `AuthStore.permissions()`, and the design already carries its `@security` warning there — which this review confirms is the load-bearing one, not the guard's or the directive's. Enforcement remains solely `@RequiresPermission`, verified fail-closed on every branch and merge-blocked end to end by US-011's shipped tests, so every client-side bypass (all four routes catalogued in §4.1 are trivially achievable) terminates in a 403.

**Auth, crypto, and PII were each explicitly reviewed and are attested in §0.2** — no new authentication path, no cryptography and no client-side randomness whatsoever, and every new field traced end to end for PII, with one residual channel found (T-06) and closed by M-3. The design's negative claims were **grep-verified rather than trusted**: zero `sessionStorage` writes, zero analytics / beacon / telemetry sinks, zero `innerHTML` or `bypassSecurityTrust*` anywhere in `src/`. The production dependency audit is clean (0 vulnerabilities).

**No design change is required.** All six required mitigations are implementation-, test-, or documentation-level and fit inside the existing task map — **`/breakdown` may proceed without returning to the architect.**

Two commendations, because they are the reason this review is short on real findings. The **no-query-parameters redirect** (§4.4) is the right call and additionally forecloses an enumeration oracle the design did not claim credit for — it must not be "improved" later. And the **stateless, context-free, unguarded Access Denied page** (§4.6) is a genuinely good security decision masquerading as a simplification.

---

## 11. Response to design §16.1's six handoff items

| §16.1 item | Response |
|---|---|
| 1. `requiredPermission` information exposure; confirm the no-query-param redirect posture | **Redirect posture confirmed and endorsed** (§4.5) — sufficient, and it additionally prevents an enumeration oracle; do not add parameters later. **Exposure: the requested code-review-checklist line is required (T-01 / M-5e) and is sufficient for the template-rendering risk** (§4.3 argues why a lint rule is disproportionate). **But the item was incomplete: it considered only the rendering path. T-05 found a second, mechanical, production-level path via `GlobalErrorHandler`.** |
| 2. `isProblemDocument` validates only `code`; `requiredPermission` asserted, not validated | **Confirmed harmless today** — the full hostile-input walk-through in §4.6 shows no XSS sink exists anywhere in `src/`, no log path, and no prototype-pollution path. **Required anyway (T-04 / M-2):** one-line narrowing, because the design's own safety argument rests on a type the runtime does not guarantee. Corroborated by T-12: the same weakness already applies to `details`, which *is* rendered. |
| 3. R-1 mitigated by process only; ESLint rule is Security's call | **Call: no ESLint rule.** Instead **M-1 (T-03)** — a ~20-line route-table spec that mechanically enforces *both* `data.permission` presence and `authGuard` ordering with no new tooling, strictly better than the proposed rule and than the §12.6 memory convention. **And the R-1 aim is redirected:** §4.2 shows the guard and directive are structurally immune to misuse-as-authorization; the reachable vector is `AuthStore.permissions()` used for client-side-only redaction (T-02 / M-5a). |
| 4. Fail-open is settled and deliberately unlogged; confirm acceptable | **Confirmed acceptable, independently reached** (§4.7) — fail-closed would convert a config typo into a user-facing outage, and the decision *not* to add a per-navigation `logger.warn` is endorsed for the reasons §6.2 gives. **Not acceptable as the only control:** M-1 replaces the remembered test convention with a build-time check. |
| 5. New client-side data (`permissions[]`), in-memory only, no new PII / endpoint / authz point | **Confirmed by grep, not assumption** (§4.4): zero `sessionStorage` writes, one benign `localStorage` consumer (theme), zero telemetry sinks. Same exposure class and lifetime as `roles[]` — correct. **One defect found in the same file the story edits: `auth.ts:52–54` falsely claims sessionStorage persistence under a `@security` heading (T-08 / M-4).** Also T-10: the populated array is unfrozen while the empty one is frozen. |
| 6. `mailto:` placeholder must not reach production | **Confirmed a non-issue security-wise** (§3.1, T-11) — no input, static RFC 2606 literal, and `mailto:` is sanitiser-irrelevant. The release-checklist item is the correct and sufficient response; no security action beyond it. |

---

### Cross-references
- Design: `docs/features/US-013/03-design.md` — §16.1 handoff answered item by item in §11 above
- Requirements: `docs/features/US-013/01-requirements.md` — R-1, R-2, R-4 addressed by T-02 / T-03 / RR-2 / RR-3 / RR-4
- Impact: `docs/features/US-013/02-impact.md`
- Backend enforcement this design depends on: `docs/features/US-011/07-security-review.md` (PASS, 0 Blockers), `docs/features/US-011/03b-threat-model.md`
- Key code inspected: `core/guards/auth.guard.ts`, `core/auth/auth.store.ts`, `core/http/api-error.interceptor.ts`, `core/logging/logger.service.ts`, `core/errors/global-error-handler.ts`, `app.config.ts`, `app.routes.ts`, `shared/types/auth.ts`, `shared/types/app-error.ts`, `shared/ui/error-state/error-state.ts`, `features/auth/registration-form/registration-form.component.ts`, `src/environments/environment.ts` and `environment.development.ts`
