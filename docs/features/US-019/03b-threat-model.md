# US-019 — STRIDE Threat Model: Prerequisites for the RBAC Access Management UI

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md` (Draft, 2026-10-19, commit `d4271c5`) and the ADRs it proposes (0026, 0027, ADR-0021 Revision 3). Organised per component and trust boundary, so each slice's PR (S1a to S5c) can trace its own threats. Feeds `/breakdown` (Phase 4)._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-019 · **Reviewer:** Application Security Engineer · **Status:** **Conditional pass, not closed.** One High finding and seven Medium findings require design changes (§6) before Gate 2 closes. No Blocker. Four of the changes are Architect decisions (marked ◆).

No PII: people are referred to by role only. Dev-seed credentials and persona addresses are not repeated.

Legend in tables: **OK** addressed as designed · **GAP** partly addressed · **CHANGE** design change required · n/a.

---

## 0. Scope, verification basis, headline

### 0.1 Scope

Every component and trust boundary in `03-design.md`: the directory endpoints (B1 list, B2 batch, by-id) and the POST lookup; B4 `GET /users/me/authorization`; B7's `reason` and the 429; B8's atomic replace with its ETag, its locks and the ETag on `GET /roles/{roleId}/permissions`; V11 and the administrator definition; B3, B5 and B6; the CORS change and the 412/428 handlers; B10/A11 contracts; the frontend shell, guards, `returnUrl`, Access Denied and the 503 notifier; the `DevDataInitializer` personas; the Playwright fixtures and the CI e2e job; the throttle port change. The Gate 1 decisions (`01-requirements.md` §13a) are not reopened. Where a finding touches one (Q4, Q5), it concerns the decision's implementation, not the decision.

### 0.2 Verification basis

**Rule applied (design instruction 6):** a fact a prior story verified in code is trusted unless `git log -- <path>` shows the file changed since. `git log` on `rbac/`, `identity/`, `common/` and `nexus-frontend/src/app` shows the last code change is `2962b0e` (US-018 M3/M8/M9/M11 merge, 2026-10-19). The US-018 re-passes (`15-`, `16-`, `17-threat-model-repass-*.md`) and the pre-PR re-review were written against that code, and nothing changed after it. So US-018's verified facts stand: the set lock shape and order (US-018 03b §12.3 RC-46, `17-…-M9.md` T-T20), RC-25.1 (administrator from locked rows), role-subset and RC-35 on PATCH/DELETE, the epoch and replay (§11–§13), the refresh limits, `RefreshTokenUseCase` reuse detection, and the `CorrelationIdFilter` charset. The items below are **new facts US-019 depends on**, each re-read in this session.

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| 1 | A column-scoped `UPDATE` grant is enough for `SELECT … FOR UPDATE` | `UserRolesPrivilegeIT.java:133-151` (as `nexus_app`); grants `02-grants-post-schema.sql:32-35`, `:39` | **Confirmed for `user_roles`.** `roles` has the same shape (`SELECT, INSERT` plus `UPDATE (name, description, deleted_at)`). The `roles` IT is still required (AS-1) |
| 2 | `role_permissions` FK to `roles` | `V5__rbac_schema.sql:49-51` (`pk_role_permissions (role_id, permission_id)`, `fk_role_permissions_role`) | **Confirmed.** An attach INSERT runs an FK parent check, which takes an **S lock on the `roles` row**. The design's §10.4 attach row says attach "requests no lock B8 holds on `roles`". That is wrong (T-T24) |
| 3 | Assign's insert locks the role row | `JpaUserRoleRepository.java:240-245` (`INSERT … SELECT … FROM roles … deleted_at IS NULL`) | **Confirmed.** It takes S on the role row, so a B8 that holds R's row X makes assign **wait, then commit on its pre-wait classification** (T-E48) |
| 4 | Set lock statement | `JpaUserRoleRepository.java:108-117` (`FORCE INDEX (fk_user_roles_role_tenant)`, `role_id IN (…) … FOR UPDATE`) | **Confirmed.** It locks `user_roles` rows only; the admin-defining set it is built from is a **pre-lock** M10' read (`RoleAssignmentService.java:519-538`) (T-E49) |
| 5 | Attach's promotion check is snapshot-only | `RoleManagementService.java:668-682`, `:248-251` | **Confirmed.** Two attaches that each see "8 of 9" both pass and jointly complete the catalogue without `RBAC_010` and without the row-14 page (T-E48, pre-existing) |
| 6 | Malformed request bodies | `GlobalExceptionHandler.java` (no handler for `HttpMessageNotReadableException`; `handleUnexpected` logs the exception at ERROR, `:195-202`); the gap is acknowledged at `AttachPermissionRequest.java:11-12` | **Confirmed.** A malformed body on the new POST lookup is a 500, and its exception text is logged (T-I21) |
| 7 | Correlation id is client-controlled | `CorrelationIdFilter.java:32-41` (any `[A-Za-z0-9._-]{1,64}` header value is adopted) | **Confirmed.** "Rows of one PUT share the correlation id" holds only for honest clients (T-R17) |
| 8 | Throttle sources | `RedisRoleChangeThrottleAdapter.java:56-58` (`SET … PX retryMs`), `:99-106`; `RateLimitRoleChangeThrottleAdapter.java:112-131`; `RoleAssignmentService.java:624-646` (`:643` throws `NOT_TENANT_ADMIN`) | **Confirmed** as the design states. `PTTL` gives the retry-after atomically |
| 9 | Rate-limit store fails open; key never logged | `RedisRateLimitStore.java:56-78` | **Confirmed** |
| 10 | URL and body sinks | `ApiRequestLoggingFilter.java` (logs `getRequestURI()`, no query, no body); no Tomcat access log, no tracing dependency (grep of `pom.xml` and `application*.yml`); `nexus-frontend/nginx.conf:35-51` (no `access_log` override, so the default combined log has the request line) | **Confirmed.** A POST body reaches no sink; a GET query would reach nginx's log |
| 11 | CORS and default cache headers | `SecurityConfig.java:205-219` (single origin, credentials, `If-Match` absent, `ETag` not exposed); `:88-91` (only HSTS is customised, so Spring Security's `no-store` default stays) | **Confirmed.** No `ShallowEtagHeaderFilter` exists (grep) |
| 12 | Dev seed | `DevDataInitializer.java:41` (`dev & !break-glass`, no `!prod`), `:100` (email at INFO), `:116` (`assignedBy = self`) | **Confirmed.** The compose `backend` runs `dev` (`docker-compose.yml:102`) and passes no rate-limit variables |
| 13 | Registration email constraint | `RegisterRequest.java:15` (`@Email @Size(max = 254)`); registration is anonymous into the default tenant (US-018 03b §0.2 #1) | **Confirmed.** Directory emails are attacker-chosen strings (T-S12) |
| 14 | Unscoped repository gate | `TenantIsolationArchitectureTest.java:33-60` (inherited `existsById` is not checked; declared methods are) | **Confirmed.** The design's `existsById` needs no allowlist entry. A declared unscoped method would (§6, RC-61.2) |
| 15 | `./mvnw -o dependency:tree` | Ran this session | **No manifest delta** since `2962b0e` (`git diff --stat` on `pom.xml`, `package*.json` is empty). Boot 4.1.1, Tomcat 11.0.26, BC 1.86, jjwt 0.12.6, Lettuce 7.5.2, Connector/J 9.7.0, Jackson 3.1.5, springdoc 3.0.3, the same as the US-018 baseline. The design adds no backend dependency |
| 16 | `npm audit` | Ran this session | **33 findings (4 critical, 13 high, 14 moderate, 2 low)**, up from US-018's 27. The increase is advisory-database drift, not a manifest change. **Production graph: 7 (1 high, 6 moderate), all `@angular/*` 22.0.4**, including GHSA-hh8m-fm6v-7cvg (sanitization bypass through directive host bindings, `@angular/core` and `@angular/compiler` < 22.1.0). The criticals (`@angular/build`, `tar`, `piscina`, `proxy-addr`) are toolchain-only. There is no SSR (`angular.json`), so the router SSR DoS advisory does not apply (T-T23) |
| 17 | Frontend sinks | grep of `src` for `innerHTML`, `bypassSecurityTrust*`, `insertAdjacentHTML`, `location.href` | **None in application code.** Role names are allow-listed `^[A-Za-z0-9][A-Za-z0-9 ._-]*$` (`CreateRoleRequest.java:27`); descriptions allow any non-control text |
| 18 | Design facts 1 and 2 (nginx throttles `/api/v1/auth/` at 10 r/min, burst 10) | `nginx.conf:9`, `:35-42` | **Confirmed** |

**Not verified (marked where used):** InnoDB's order of the FK parent check versus the clustered-index insert inside one INSERT (**[INFERENCE]**, load-bearing for T-T24, which needs an IT); Jackson 3's echo of an unquoted token in its parse-error text (**[INFERENCE from Jackson 2 behaviour]**, T-I21); Spring Boot relaxed binding of `NEXUS_SECURITY_RATELIMIT_*` for `@Value` placeholders (**[REPORTED framework behaviour]**); Flyway's single-transaction V11 (AS-3, unchanged).

### 0.3 Headline

**The design is careful, and most of its security calls hold.** These survived direct attack (§3.3):
- the POST lookup transport;
- the exact field allow-list;
- byte-identical cross-tenant misses with the same statements;
- the deliberate `USER_NOT_FOUND`/`RESOURCE_NOT_FOUND` split (flag state is not a secret, and non-holders get 403 before any 404);
- B4 as an identifier-free, live, one-predicate read;
- the content-hash ETag over a version column (it sees migration writes, so a stale editor cannot silently undo a footer);
- "locks only after authorization";
- V11's no-promotion property;
- the throttle port's fail-safe shape.

**What does not survive, in order of consequence:**

1. **The B8 locked comparison checks membership, not equality** (**T-T22, High**). Step 9 accepts the current ETag if it is anywhere in `If-Match`. ETags are deterministic hashes that any caller can compute for any hypothetical set. So a caller can list the ETags of two states and pass the lock check after a concurrent write, while steps 5 to 7 (adds, removes, classification, role-subset, the administrator rule, the lock path) were decided on the other state. The design's own soundness paragraph assumes `v1 = v0`, which the algorithm never checks.
2. **`RBAC_010` does not hold under concurrency, and B8 makes the race deterministic** (**T-E48, Medium**). B8's role-row X lock makes a concurrent assign (INSERT … SELECT) and a concurrent attach (FK parent check) wait. They then commit on a classification taken before B8's commit. Independently of B8, two attaches that each see "8 of 9" both pass. US-018's premise that "attach is the only path to admin-defining, and the race after the snapshot is paged by row 14" is false on both counts.
3. **The set lock serialises, but it does not make the administrator decisions sound** (**T-E49, Medium**). Step 10 and revoke's lockout classify the *other* roles from a pre-lock M10'. One administrator who sends two B8 demotions at once (each relying on the other role) deterministically reaches **zero administrators** in a custom-admin-only tenant. RES-28's "race-only" framing understates this: a single actor controls both requests.
4. **B8's check order is a composition oracle, and the no-op bypasses authorization** (**T-I20, Medium**). 412 and the no-op 200 both come before 403.
5. **A malformed lookup body is a 500 whose exception text is logged** (**T-I21, Medium**). The PII log-scan IT does not exercise it.
6. **Email access propagates by delegation** (**T-E50, Medium**). Any non-administrator holding `user:directory:read` together with `user:role:assign` or `role:write` (the "User Manager" persona) can grant it on, including to a self-registered second account.
7. **Bulk exfiltration through list, batch and by-id is unthrottled and unalerted** (**T-R16, Medium**). Only lookup volume is alerted.
8. **The production Angular graph carries a sanitization-bypass advisory** (**T-T23, Medium**), just as US-019 adds the directives that US-020 will feed untrusted directory data.

**Q5 (set lock when the before or after state is admin-defining): CONFIRMED, with conditions RC-55 and RC-57.** It is the right lock, taken in the right order (§4.1). It is not sufficient on its own.

**Verdict:** conditional pass. Gate 2 can close once RC-55 to RC-62 are folded into the design (§6). RC-63 lands as tasks. No Blocker. No Gate 1 decision needs reopening.

### 0.4 Attestation (auth, crypto and PII are never approved silently)

- **Authentication: reviewed. No new mechanism.** B4 and the directory reuse the bearer filter, the epoch check and `@AuthenticatedEndpoint`. These are sound:
  - the `authGuard` ancestor composition and its single-refresh test;
  - the per-worker Playwright context (refresh-token rotation);
  - the 503 notifier, which never refreshes or logs out.

  `returnUrl` is sound with RC-63(i).
- **Authorization: reviewed in depth; this is the story's core risk.** The following are not approved as written:
  - B8's comparison (T-T22);
  - the concurrency claims around `RBAC_010` and the administrator rule (T-E48, T-E49);
  - the B8 check order (T-I20);
  - PII-permission delegation (T-E50, a D5 decision).

  These are confirmed sound:
  - "locks only after authorization" (ADR-0018's bounded-lock rule);
  - the RC-46 order by current class;
  - B4's reuse of `isCallerAdministrator`;
  - B3's reuse of `resolveRoleInTenant`;
  - `isSensitive` as UX only (with an ArchUnit guard, RC-63(k)).
- **Cryptography: reviewed. No findings.** No key, algorithm or randomness source changes.
  - The ETag is SHA-256 over non-secret ids. It is a concurrency token, not a capability, and ADR-0027 must say so (RC-55.5).
  - Lookup uses `EmailBlindIndexService` only (HMAC-SHA256 with the existing key; `trim → NFC → lowercase(ROOT)`, `EmailBlindIndexService.java:26-40`).
  - Decryption is the existing AES-GCM converter.
  - The blind index never leaves the service (design §4.5); RC-63(h) adds a scan for it in CI.
- **PII: reviewed against the no-PII rule.** The new surface is emails in directory responses, gated by `user:directory:read`.
  - Sound: the field allow-list; POST transport; no email or HMAC in audit, metrics or links; the `DevDataInitializer` INFO fix.
  - Gaps: the malformed-body log path (T-I21); delegation (T-E50); detection of bulk reads (T-R16); attacker-chosen email content (T-S12, carried to US-020).
  - Legal basis and retention remain Q-N10 (Legal/DPO). This model does not decide them.
- **Secrets: reviewed.** Dev seed passwords and the dev HMAC key are public by design (dev profile). RC-63(g) adds `!prod` to the seeder guard. The CI job needs no secrets and must not be given any (RC-63(h)).

### 0.5 Numbering

The epic sequence continues. US-018 ended at T-S11, T-T21, T-R15, T-I19, T-D25, T-E47, RC-54 and RES-46. **US-019 starts at T-S12, T-T22, T-R16, T-I20, T-D26, T-E48, RC-55 and RES-47.** The design's own residual labels (RES-45 and RES-28 "extended") are kept and re-scoped in §7.

---

## 1. Trust boundaries and data flow (what US-019 adds or changes)

```
[ Internet: anonymous client -- can self-register into the DEFAULT tenant (US-018 §0.2 #1);
  chooses its own email string, stays PENDING until verified (T-S12)                        ]
[ Authenticated member: RS256 bearer, permissions[] up to 900 s stale; epoch-checked         ]
      |  GET  /users, /users?ids=, /users/{id}         (us019, user:directory:read)  <- T-R16
      |  POST /users/lookup  {email}                    (us019, user:directory:read)  <- T-I21
      |  GET  /users/me/authorization                   (us019, @AuthenticatedEndpoint)
      |  GET  /roles/{id}, GET /roles/{id}/permissions (+ETag)  (us015, role:read)
      |  PUT  /roles/{id}/permissions  If-Match         (us015, role:write)           <- T-T22, T-I20
      |  POST/DELETE /users/{id}/roles  (B7: 403+reason / 429 RBAC_011+Retry-After)
      v
=== TB1 network -> app (nginx in compose/prod: /api/v1/auth/ 10 r/min; /api/ unthrottled) =====
  CORS (dev only, cross-origin :2000 -> :1000): + If-Match request, + ETag exposed
  CorrelationIdFilter: client X-Correlation-Id adopted if [A-Za-z0-9._-]{1,64}       <- T-R17
  JwtAuthenticationFilter (epoch) -> @RequiresPermission (flat JWT claim)
=== TB2 GlobalExceptionHandler =================================================================
  RBAC_001 + reason (CallerFacingDenialReason) | 429 RBAC_011, USER_DIR_001 | 412 | 428
  ** no handler: HttpMessageNotReadable / MediaType / Method -> 500 + ERROR log of message **  <- T-I21
=== TB3 application ============================================================================
  identity.UserDirectoryService (readOnly tx)
     RateLimitStore DIR_LOOKUP:{t}:{actor} (fails open) -> blindIndex -> port (tenant predicate)
     audit USER_DIRECTORY_READ via REQUIRES_NEW (best-effort, 2nd connection per request)
  rbac.CallerAuthorizationService (readOnly, one snapshot): M13 + M15 + findActiveRoles
  rbac.RoleManagementService.replaceRolePermissions
     steps 1-7 snapshot (no locks) ** 412 and no-op BEFORE 403 (T-I20) **
     locks by current class: [set lock (user_roles X) -> roles X] | [roles X -> (promotion) set lock]
        ** concurrent assign (INSERT..SELECT, S on roles) and attach (FK check, S on roles)
           WAIT here, then commit on pre-wait classification (T-E48) **
     role_permissions FOR SHARE (current) -> compare ** v1 IN If-Match, not v1 == v0 (T-T22) **
     step 10/11 from set-lock rows, but "which roles are admin-defining" = PRE-LOCK M10' (T-E49)
     delete/insert -> audit inline (ADR-0024) -> after commit: bump or evict holders
  rbac.RoleAssignmentService: throttleStatus -> 429 (no audit) | RBAC_001 reason
=== TB4 Redis ==================================================================================
  {prefix}:identity:ratelimit:DIR_LOOKUP:{t}:{u}   (new)   rbac:throttle:{t}:{u} (PTTL read, new)
=== TB5 MySQL as nexus_app =====================================================================
  roles: SELECT, INSERT, UPDATE(name, description, deleted_at)  <- SELECT .. FOR UPDATE (B8, IT)
  role_permissions: SELECT, INSERT, DELETE                       <- FOR SHARE (B8, IT)
  users: SELECT (directory)   auth_events: INSERT (USER_DIRECTORY_READ, ROLE_PERMISSION_*)
=== TB6 migrations =============================================================================
  V11: insert user:directory:read + footer (a) A-V9 + footer (b). Catalogue 8 -> 9 for ALL code
=== TB7 dev / CI ===============================================================================
  DevDataInitializer (dev & !break-glass; ** not !prod **, T-E52) -> personas, 2nd tenant (fixture)
  GitHub Actions e2e job: compose mysql/redis/flyway/backend(nexus_app, dev) + ng dev server
     CI-only rate-limit env; Playwright worker-scoped contexts; trace on first retry (T-I24)
=== TB8 browser ================================================================================
  PublicLayout (auth, access-denied, design-system) | Shell (authGuard) -> children (permissionGuard)
  safeReturnUrl -> router.navigateByUrl (in-app only) (T-T25)   Angular 22.0.4 advisories (T-T23)
```

---

## 2. STRIDE tables, per component

### C1 — Directory reads: B1 list, B2 batch, by-id (`identity`, us019)

| | Threat | Verdict |
|---|---|---|
| **S** | Tenant taken from a parameter | **OK.** Tenant and actor come from the JWT; `TenantIsolationArchitectureTest` polices every declared method |
| **T** | — | n/a (read-only) |
| **R** | Reads leave no record | **GAP.** One best-effort `USER_DIRECTORY_READ` row per request (ids and counts). Acceptable as best-effort (RES-50, D5). The batch path has no cross-tenant WARN (T-R16) |
| **I** | Fields beyond the five (HMAC, hash, counters, tenant) | **OK.** The adapter never maps them; `UserDirectoryIT` pins the exact key set |
| **I** | Bulk exfiltration by a holder or a stolen holder token | **CHANGE: T-R16 (Medium).** List, batch and by-id are unthrottled, and §17 alerts only on lookups |
| **I** | Attacker-chosen email content rendered to administrators (look-alikes, unverified PENDING addresses, CSV formula payloads) | **GAP: T-S12 (Low)**, carried to US-020/D5 |
| **D** | Deep `page` offset, unfiltered filesort, `COUNT(*)` per page, a second pooled connection per request (audit `REQUIRES_NEW`) | **GAP: T-D26 (Low).** Holders only |
| **E** | `user:directory:read` granted onward by non-administrators | **CHANGE: T-E50 (Medium)** |
| **X (cross-tenant)** | Tenant A reads, probes or enumerates tenant B users | **OK for read and probe:** <ul><li>list: `WHERE tenant_id = :tenantId`;</li><li>batch: `id IN (:ids) AND tenant_id = :tenantId` (silent omission);</li><li>by-id: `findByTenantAndId`, then `existsById` on every miss, so missing and foreign ids run the same two statements and give the same 404 `USER_NOT_FOUND`.</li></ul> UUIDv7 ids carry 74 random bits, so foreign ids cannot be guessed. **GAP for detection:** batch probing emits no WARN (T-R16, RC-61.2). The equivalence test must normalise `traceId` and `instance` (T-I25) |

### C2 — `POST /api/v1/users/lookup` (exact-email lookup)

| | Threat | Verdict |
|---|---|---|
| **S** | CSRF on a POST read | **OK.** Bearer-only authentication; CSRF disabled for a stateless API (`SecurityConfig.java:84`); CORS allows a single origin |
| **T** | Normalisation divergence (case, whitespace, NFC) produces a false miss or a wrong hit | **OK.** `EmailBlindIndexService.blindIndex` only; tests cover the variants |
| **R** | Throttled lookups unaudited | **OK.** Bounded write volume (US-018 RC-33 reasoning); a counter remains |
| **I** | Email in URL, access log, link, error, audit, metric, trace | **OK** for every designed path: body only; `?email=` is 400; no tracing dependency |
| **I** | Email fragments in the ERROR log on a malformed body | **CHANGE: T-I21 (Medium)** |
| **I** | Timing: hit versus miss within the tenant | **OK, stated.** That is the endpoint's purpose for an authorized caller. A hit adds one AES-GCM decrypt. A cross-tenant hit is a plain miss (unique `(tenant_id, email_hmac)`) |
| **D** | Lookup flood | **OK.** 30 per 60 s per (tenant, actor). It fails open with Redis down, which is acceptable because the permission is the gate (RES-49). Each 429 logs a WARN: T-D26 asks for `selfReported` |
| **E** | — | n/a |
| **X** | Tenant A learns whether an email exists in tenant B | **OK.** Byte-identical `{data: []}`; the same HMAC, probe and audit write |

### C3 — B4 `GET /api/v1/users/me/authorization` (`rbac`, us019)

| | Threat | Verdict |
|---|---|---|
| **S** | Another user's profile through an identifier (IDOR, A01) | **OK.** `@AuthenticatedEndpoint`, `Authentication` is the only parameter, enforced by ArchUnit (`HexagonalArchitectureTest` `authenticated_endpoints_take_no_uuid_identifier`, US-018 RC-40.2) |
| **T** | — | n/a |
| **R** | — | **OK.** A read of own data needs no audit (AS8) |
| **I** | Response leaks role composition, `assignedBy`, catalogue size or tenant | **OK.** Excluded by contract (§6.2 "Must not") |
| **I** | Stale answer misguides the UI | **OK.** Live reads in one RR snapshot, not the cache or the JWT. A revoke bumps the epoch, so the old token gets 401 before B4 runs; the SPA refreshes and B4 answers live. The JWT-driven nav can disagree for up to one token TTL (US-020 G6) |
| **D** | Unthrottled for any authenticated user, including self-registered ones | **OK.** Four indexed reads, the same posture as any authenticated GET |
| **E** | `isAdministrator` re-implemented or union-based | **OK.** It reuses `RoleAssignmentService.isCallerAdministrator` (`:451-457`), per role. The IT covers the custom full-catalogue role and the union-holder |
| **X** | Tenant A's caller sees tenant B data | **OK.** Every read carries the caller's tenant predicate. The IT seeds a second tenant |

### C4 — B7: caller-facing `reason`, 429 `RBAC_011`, throttle port change

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a |
| **T** | Port change turns a store failure into a block or a permit | **OK.** `throttleStatus` keeps fail-safe (`NOT_THROTTLED`) and never-throw. `evaluateThrottle` still swallows a throw. `PTTL` is one atomic read |
| **R** | Throttled requests unaudited | **OK.** Unchanged (US-018 RC-33.1); the counter and the once-per-window WARN remain |
| **I** | `GRANT_EXCEEDS_CALLER` (one bit of composition); `ADMINISTRATOR_REQUIRED` on revoke (the RES-33 bit); 429 versus evaluation (the RES-33 bit, now explicit on every target); `Retry-After` (own window) | **GAP, accepted at Low: T-I22.** Conditions in RC-63(l) |
| **I** | Opaque paths leak through `reason` | **OK.** Malformed principal, missing tenant, `PERMISSION_ABSENT` and the unreachable cross-tenant 403 all map to `UNSPECIFIED`. The mapping test is exhaustive over `DenialReason.values()` |
| **D** | One WARN per 429 reopens US-018 RC-33.1 | **OK.** `selfReported()` moves the 429 log to DEBUG |
| **E** | — | n/a |
| **Flag** | Ships unflagged to every `RBAC_001` | **Accepted.** Additive field plus one status change on one branch; rollback is a revert. The disclosure is Low (T-I22) |

### C5 — B8 `PUT /roles/{roleId}/permissions`, its ETag and locks

| | Threat | Verdict |
|---|---|---|
| **S** | — | **OK.** `@RequiresPermission(ROLE_WRITE)` plus the L-1 live `role:write` re-check |
| **T** | Lost update between two editors (TOCTOU under RR) | **CHANGE: T-T22 (High).** The membership check defeats the lock-and-compare |
| **T** | `RBAC_010` provenance bypassed by a racing assign or attach | **CHANGE: T-E48 (Medium)** |
| **T** | Zero administrators through serialised demotions or a demotion followed by a revoke | **CHANGE: T-E49 (Medium)** |
| **T** | Lock-order proof relies on a wrong attach description | **GAP: T-T24 (Low).** The conclusion holds; the text and the IT need correcting |
| **T** | Snapshot authorization spans a role-row lock wait | **GAP: T-E51 (Low).** RES-27 restated |
| **R** | One PUT's rows grouped by a client-controlled id; no class-change signal on demotion | **GAP: T-R17 (Low)** |
| **I** | 412 and the no-op 200 before 403 reveal any role's exact set to an unauthorized `role:write` holder | **CHANGE: T-I20 (Medium)** |
| **D** | Unauthorized callers taking the set lock or the role lock | **OK.** Locks come only after step 7 (ADR-0018). A non-administrator can reach the set lock only by a promotion, which needs every added id in their union, and only once per role |
| **E** | Demotion of the caller's last administrator role | **OK** for a single request (administrator through another role, from the set-lock rows). **Not OK** for two concurrent requests (T-E49) |
| **E** | Promotion by a union-holder | **OK.** T-E41 (US-018): a union-holder already holds everything. `RBAC_010` still guards holders, subject to T-E48 |
| **X** | Cross-tenant role id, or permission ids from another tenant | **OK.** Step 1 gives 404 `ROLE_NOT_FOUND` with the cross-tenant WARN. Permissions are global, so there is no tenant B permission. `CrossTenantNotFoundEquivalenceIT` must add B8 and the ETag GET (byte equality) |
| **Priv** | `nexus_app` locking reads | **OK by precedent** (§0.2 #1). `RolesPrivilegeIT` and `RolePermissionsPrivilegeIT` must run as `nexus_app` (merge-blocking). The no-op `UPDATE` fallback is sound (it needs only `UPDATE (name)`) |

### C6 — V11 and the administrator definition

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a |
| **T** | Footer omitted or mis-bound, demoting custom administrators | **OK.** The A-V9 variant is bound to exactly the new id; `PermissionMigrationFooterScannerTest` runs unmodified (US-018 RC-48, T-T21); the V11 semantic IT covers full, 7-of-8 and soft-deleted roles |
| **T** | Promotion of a role that was not already complete | **OK.** Footer (a) completes only complete roles. A concurrent attach or detach during the migration leaves a role at 8 of 9, which fails closed |
| **R** | — | n/a |
| **I** | — | n/a |
| **D** | Administrators 403 on B1 while their tokens lack the permission | **GAP: T-I23 (Low).** "Flush, then 900 s" is not sufficient because of the L-4 re-cache race |
| **E** | New administrators by catalogue change | **OK.** None: no role is promoted, `MEMBER` is excluded, and every decision reads M15 live |
| **E** | Tenant left without an administrator | **OK** through the footers. Tenants without a system `TENANT_ADMIN` (the dev second tenant) depend on footer (a) on every later migration (RES-41, US-018) |
| **X** | — | **OK.** Footer statements are tenant-agnostic by design, and the A-V9 predicate is per role |

### C7 — B3, B5 (`isSensitive`), B6 (`memberCount`, `permissionCount`)

| | Threat | Verdict |
|---|---|---|
| **I** | `memberCount = 1` on an admin-defining role reveals a single holder; `permissionCount == catalogue size` reveals admin-defining status | **Accepted at Low (RES-48, D5).** A `role:read` holder can already read the permission list. "Last administrator" is not derivable (§2.4) |
| **E** | A server rule starts depending on `isSensitive` | **GAP (Low).** Add the ArchUnit guard (RC-63(k)) |
| **X** | Counts or B3 across tenants | **OK.** Role ids come from a tenant-scoped page; the holder count carries the tenant predicate; the permission count joins `roles` for the tenant (a code-review checklist item, because `RolePermission` has no `tenantId`). B3 reuses `resolveRoleInTenant` |

### C8 — CORS, 412/428 handlers, B10/A11 contracts

| | Threat | Verdict |
|---|---|---|
| **T/I** | Wider CORS surface | **OK.** Only `If-Match` (request) and `ETag` (exposed) are added; the single origin and credentials are unchanged |
| **I** | 412 or 428 body leaks state | **GAP.** The 412 must carry no ETag and no set (RC-58.2) |
| **I** | `/v3/api-docs` (permitAll outside prod) now lists every error code | **Accepted (Low).** springdoc is disabled in prod (`application-prod.yml:20-24`); staging exposure is pre-existing |
| **I** | `contracts/api/*.json` fixtures | **OK.** `example.test` addresses and fixed UUIDs |
| **D** | Framework exceptions become 500s | **CHANGE: T-I21** |

### C9 — Frontend: shell, guards, `returnUrl`, Access Denied, 503 notifier, wrappers

| | Threat | Verdict |
|---|---|---|
| **S** | Guard composition misroutes, or causes a second refresh (reuse detection, R5) | **OK.** `authGuard` on the shell ancestor; the contract spec rejects same-array composition; the real-Router test asserts exactly one `POST /refresh` |
| **T** | Open redirect through `returnUrl` (NF-S6) | **GAP: T-T25 (Low).** `navigateByUrl` cannot leave the origin, and `safeReturnUrl` is defence in depth. Its "decode once" is a second decode (`queryParamMap` already decodes), so the validated string and the navigated string can differ |
| **T** | XSS in role names, descriptions, emails, tooltips, chips, dialogs | **OK today.** Angular interpolation; no `innerHTML` in `src`; role names allow-listed. **CHANGE: T-T23** (Angular advisory) plus an ESLint ban (RC-62.3) before US-020 renders directory data |
| **T** | A route added under `PublicLayout` by mistake is unguarded | **GAP (Low, T-T25).** Pin the public children list |
| **R** | — | n/a |
| **I** | Access Denied shows `requiredPermission` or `reason` | **OK.** It shows neither, and makes no HTTP call; JWT role names are allow-listed text |
| **I** | `supportContact` `href` | **OK.** Only `mailto:` or `https://`; Angular sanitises URLs as well |
| **D** | 503 `AUTH_005` loops or logs the user out | **OK.** No refresh on 503 (`auth.interceptor.ts:188`); one toast per window; no navigation |
| **E** | Client-side gating trusted | **OK.** UX only (RES-39); nav is hidden by JWT permissions; the server is authoritative |
| **CSV** | Export escaping | **n/a in US-019** (no export). Carried to US-020/D5 (T-S12) |

### C10 — `DevDataInitializer` personas and the second tenant

| | Threat | Verdict |
|---|---|---|
| **S** | Known-password administrators active outside dev | **GAP: T-E52 (Low).** The guard lacks `!prod`; the compose stack runs `dev` |
| **T** | Persona assignments look like break-glass grants (`assigned_by = target`), and trip `RBAC_010` in US-020 e2e | **GAP: T-E52** |
| **R** | Seed bypasses grant-subset and A6 audit | **Accepted.** Dev only, stated in the Javadoc |
| **I** | Email at INFO (`:100`) | **OK.** The design fixes it (counts only) and adds `DevPersonaSeedIT`'s log scan |
| **E** | Second-tenant administrator signs in | **OK.** It cannot: login uses the default tenant (`LoginController.java:69`, verified by the impact analysis) |
| **X** | Second-tenant data used as an oracle in tests | **OK.** It is the intended negative fixture |

### C11 — Playwright fixtures and the CI e2e job

| | Threat | Verdict |
|---|---|---|
| **S** | Shared `storageState` replays a rotated refresh token | **OK.** Worker-scoped context jar; sequential tests in a worker. A test that opens two pages in one context at once would race a refresh and revoke the family (flake, not security; noted in RC-63(h)) |
| **T** | CI-only limit relaxation leaks into a profile or the base compose | **GAP: T-I24 (Low).** Use a CI-only compose override |
| **T** | Workflow integrity (fork PRs) | **GAP: T-I24.** `pull_request` only, read-only token, no secrets |
| **I** | PII in uploaded artifacts; scan misses blind indexes | **GAP: T-I24.** Traces record API request bodies; the dev HMAC key is public, so the HMACs can be scanned for |
| **D** | Silent-green e2e | **OK.** `E2E_REQUIRE_BACKEND=1` throws; `assert-executed.mjs` fails on skips and on zero tests |
| **E** | — | n/a |

---

## 3. Identified threats

Format per entry: attack · existing mitigation · required mitigation (RC) · severity and residual.

### T-T22 — B8's locked comparison checks `If-Match` membership, not equality with the snapshot it authorised · **High** · CHANGE

**Mechanism.** Step 4 checks `v0 ∈ acceptedEtags`. Steps 5 to 7 compute adds, removes, `before`, `after`, the demotion and promotion flags and the lock path, all from S0. Step 9 then checks `v1 ∈ acceptedEtags`. RFC 9110 allows a list of entity-tags, `IfMatchHeader.parse` keeps every strong tag (§10.5), and `RolePermissionSetVersion.of(roleId, ids)` is a public, deterministic function of non-secret ids (§10.2). **Any caller can therefore send the ETags of two states.** The paragraph "Why `v1 = v0` makes steps 6 and 7 valid" assumes an equality the algorithm never tests.

**Attack (a role-subset and administrator-rule bypass).**
1. R holds 8 of 9 (not admin-defining). The attacker holds R's permissions plus `role:write`.
2. An administrator attaches the 9th permission p, legitimately. Or the attacker races their own attach of p: A3 passes when they hold p, and R's holders are administrator-assigned, so `RBAC_010` passes.
3. The attacker's PUT removes x, with `If-Match: v(S0), v(S0 ∪ {p})`.
4. Step 6 classifies R as not admin-defining, so there is no demotion, no administrator rule and no set lock.
5. At step 9, `S1 = S0 ∪ {p}`, and `v1` is in the list.
6. Step 12 deletes x. The affected-row check passes, because `removes = {x}` exists.

Result: an admin-defining role is demoted by a caller who is not an administrator through another role, outside the set lock. The 200 returns T and `v(T)`, while the real state is `S1 − {x}`. A reverse ordering gives a promotion with no set lock, no `RBAC_010` check and no row-14 page. Adds that collide fail as a 500, so only some shapes are rejected, and only by accident.

**Existing mitigation:** step 12's affected-row assertion catches a vanished remove. Nothing else does.

**Required: RC-55.** **Residual:** none once step 9 compares to `v0` (the classification then provably applies to the locked state).

### T-E48 — `RBAC_010` provenance fails under concurrency, and B8 makes it deterministic · **Medium** · CHANGE

**Three paths to a holder assigned by a non-administrator on an admin-defining role**, which is exactly what `RBAC_010` (US-018 R1-1, ADR-0021 D8) exists to prevent (the RES-26 sock puppet):

1. **assign queued behind a B8 promotion.**
   - The attacker (`user:role:assign`, holding R's pre-promotion set) assigns R to a sock puppet while an administrator's B8 promotes R.
   - The B8 holds R's row X. Assign's `INSERT … SELECT FROM roles` (§0.2 #3) waits on it.
   - The B8 runs `RBAC_010` over the set-lock rows, sees no sock puppet and commits.
   - Assign then inserts. Its A2 and classification come from a snapshot taken before the wait.
   - The assign path never re-reads R's composition, and the post-commit `admin_role_assigned` counter fires only when the stale classification said admin-defining.
   - An assign-and-revoke loop by the attacker keeps an assign in flight, so this does not depend on luck.
2. **attach queued behind a B8.**
   - A B8 leaves R at 8 of 9. A concurrent attach of the 9th permission was classified from the pre-B8 state, so "this attach completes the catalogue" was false.
   - The attach's FK parent check waits on B8's role-row lock (§0.2 #2), then inserts, and R is complete without `RBAC_010`.
   - The attacker controls the order by sending the PUT first.
3. **Two attaches (pre-existing, US-018 code).**
   - Each sees 7 of 9 plus its own id, so neither runs `RBAC_010`. They insert different primary keys and do not block each other.
   - Row 14 never fires, because `becameAdminDefining` is false for both. Row 13 fires only as a **ticket**, unless the permission is `user:role:assign` or `role:write`.
   - US-018 §11.3 R1-1's "attach is the only path, and the race after the snapshot is paged by row 14" is false on both counts, and B8 is a second path.

**Existing mitigation:** row 13 (ticket) when a non-administrator-assigned holder exists; the zero-admin indicator is irrelevant here.

**Required: RC-56.** **Residual:** with RC-56.2 to RC-56.4, the race is converted into a retryable 409 or a 1213 victim, and the committed-state detector pages. RES-26 stays Medium (partial "catalogue minus one" escalation, US-018).

### T-E49 — The set lock serialises B8 demotions and revokes, but their "which roles are admin-defining" comes from a pre-lock read · **Medium** · CHANGE

- **Two demotions by one administrator.** The caller holds custom admin-defining roles R and R2, and no system `TENANT_ADMIN` holder exists.
  1. They send PUT(R − x) and PUT(R2 − y) together.
  2. Both pass step 7 on their snapshots: each is an administrator through the other role.
  3. The first takes the set lock, passes step 10, commits, and R is demoted.
  4. The second acquires the lock. Step 10 finds the caller's R row among the locked rows, and R is "admin-defining" in **its pre-lock M10'** set. It passes and demotes R2.
  5. The tenant now has **zero administrators**, from one actor, deterministically.
- **A demotion, then a revoke.** A B8 demotes R. A revoke of the last other administrator's assignment, queued on the set lock, computes the lockout with its own pre-lock admin-defining set, which still includes R. It counts R's holders as administrators and passes.
- **Design text.** §10.4's RES-28 extension mentions only the detach race. "A single B8 can never reach zero on its own" is true, and it is the wrong bound: the attacker sends two. US-018 RES-28's "race-only" label has the same flaw for detach (one actor, two concurrent detaches).
- **Why it matters.** RC-26.2's rule ("no single detach removes the last administrator status the caller relies on") is the control this defeats. Recovery is break-glass only where a system `TENANT_ADMIN` is seeded (RES-41).

**Existing mitigation:** the zero-admin health indicator pages (detective).

**Required: RC-57.** **Residual:** with RC-57.1, closed for B8 against other B8s, revokes and detaches (the current read waits for an uncommitted detach). Without RC-57.2, the revoke-after-B8 path remains as RES-28 (re-scoped, Low, single-actor-triggerable).

### T-I20 — B8's check order is a composition oracle, and the no-op skips authorization · **Medium** · CHANGE

- **Order (§10.5):** … 404 permission, **412 (snapshot)**, then 403. The no-op (step 5) returns **200 with the full set and ETag before step 7**, so neither the L-1 live `role:write` re-check nor any subset rule runs.
- **The oracle.**
  - A `role:write` holder (the JWT claim suffices) who lacks `role:read`, or holds none of R's permissions, sends `If-Match` guesses.
  - 412 means "no guess matches"; reaching 403 or 200 means "a guess is R's exact set".
  - Because ETags are computable and `If-Match` takes a list, a few requests with many tags binary-search the 2⁹ space: about 9 requests reveal any role's exact composition. B8 is unthrottled.
- **Why it matters.** ADR-0021 D4 removed a one-bit composition oracle from `requiredPermission`, and the design's own B7 section weighs a single bit for callers without `role:read`. This one reveals the whole set.

**Required: RC-58.** **Residual:** after reordering, a caller who passes authorization for the full replace (holds `role:write` live, every added id, and on removals every id of R) can still distinguish 412 from 200. That caller is entitled to replace R wholesale, so this is acceptable. ◆ RC-58.4 closes even that by requiring `role:read`.

### T-I21 — Malformed request bodies are 500s whose exception text is logged; the lookup carries an email · **Medium** · CHANGE

- **What happens.** `GlobalExceptionHandler` is a plain `@RestControllerAdvice` with a catch-all (§0.2 #6). Spring's `HttpMessageNotReadableException` (malformed JSON), `HttpMediaTypeNotSupportedException` and `HttpRequestMethodNotSupportedException` therefore reach `handleUnexpected`. That returns 500 and logs the exception, message and stack trace at ERROR.
- **Why the lookup is exposed.** For an unquoted token, Jackson's parse error quotes the token ("Unrecognized token 'alice': was expecting …") **[INFERENCE from Jackson 2; not run against Jackson 3.1.5]**. A client that sends `{"email": alice@example.com}` puts the local part, often a person's name, into the ERROR log.
- **Why the design misses it.** The design's error table assumes "body missing or not JSON → 400" for the lookup and for B8, and the log-scan IT covers only well-formed requests. US-012 and US-015 worked around the gap with `String` DTO fields (`AttachPermissionRequest.java:11-12`), which does not help when the JSON itself is malformed.

**Required: RC-59.** **Residual:** none once handled and pinned by the log-scan IT.

### T-E50 — `user:directory:read` propagates through delegation by non-administrators · **Medium** · CHANGE (D5 decision ◆)

- **How it spreads.** Under grant-subset, a holder of `user:directory:read` plus `user:role:assign` can assign any role carrying it to anyone in the tenant except themselves (A4). A holder plus `role:write` can attach it to any role they may edit.
- **The design makes it live.** The design's "User Manager" persona (`user:read`, `user:role:assign`, `user:directory:read`) is exactly such a delegator.
- **Persistence.** Self-registration is anonymous into the default tenant, so a delegator can give a second, self-controlled account tenant-wide email access. That access survives revocation of their main account (the RES-26 shape, applied to PII).
- **Signals.** Nothing alerts on it. `ROLE_ASSIGNED` rows exist, but no detector separates "PII access granted by a non-administrator" from routine delegation.
- **Precedent.** US-018 RC-38.3 recorded the same propagation property for `audit:read`. Here the payload is personal data, which D5 and Q-N10 must accept explicitly.

**Required: RC-60.** **Residual:** RES-51, Medium without the ◆ preventive rule, Low with it.

### T-R16 — Bulk directory reads are unthrottled and unalerted; batch probing is invisible · **Medium** · CHANGE

- **The honest statement and the gap.** §4.5 is honest that the lookup throttle does not stop a holder from enumerating. But the only volume alert in §17 is lookups per actor. A stolen holder token or a malicious holder can page `GET /users?size=100` through the whole tenant at line rate. Each request writes one best-effort audit row, but nothing fires on row volume (OWASP A09). Exfiltration of every email is the worst plausible outcome of this story, and it is not alerted.
- **Asymmetric detection.** By-id cross-tenant misses WARN. Batch omissions do not, so a prober uses batch.

**Required: RC-61.** **Residual:** the honest limit stays: a holder can read the directory (RES-49, accepted by D5). Detection becomes timely.

### T-T23 — The production Angular graph carries a sanitization-bypass advisory as US-019 adds the directives US-020 will feed untrusted data · **Medium** · CHANGE (OWASP A06)

`@angular/core` and `@angular/compiler` 22.0.4 are affected by GHSA-hh8m-fm6v-7cvg (sanitization bypass via directive host bindings on concrete host elements, fixed in 22.1.0). `@angular/common` (GHSA-p297-fm68-3q8c) and `@angular/router` (GHSA-ff3f-86qr-9cv3, SSR only, not applicable) are affected too. US-019 adds `[nxTooltip]`, `nxTableCell`, `nx-chip`, `nx-menu` and the `supportContact` `href`. US-020 binds directory emails, which are attacker-chosen through anonymous registration (T-S12), and free-text role descriptions into them. Not introduced by US-019 (no manifest delta), but US-019 is where the exposure becomes reachable.

**Required: RC-62.** **Residual:** the toolchain-only criticals (`@angular/build`, `tar`, `piscina`, `proxy-addr`) stay, owned by the Frontend Tech Lead.

### Low findings

| ID | Finding | Required |
|---|---|---|
| **T-T24** | §10.4's attach and detach rows say attach "requests no lock B8 holds on `roles`". An attach INSERT runs the `fk_role_permissions_role` parent check, which takes **S on R's row** (§0.2 #2), so attach waits on B8's role-row X. No cycle results, **provided** InnoDB runs the FK check before the clustered-index insert **[INFERENCE]**; otherwise attach would hold its new record X while waiting on `roles`, and B8's `FOR SHARE` would complete a cycle. The conclusion is load-bearing and unproven | RC-63(a) |
| **T-E51** | On B8's role-row path, the snapshot `H` (A3, role-subset, L-1) predates any wait on R's row, which another B8, PATCH, DELETE or a slow attach can hold up to `innodb_lock_wait_timeout` (50 s default). This is the T-E33 pattern, not RES-27's "milliseconds". The stake is non-admin-defining roles only, so it is Low | RC-63(b) |
| **T-D26** | Directory: unbounded `page` (deep OFFSET), an unfiltered filesort and `COUNT(*)` per page; a `REQUIRES_NEW` second pooled connection per request; `USER_DIR_001` WARNs on every 429 (US-018 RC-33.1 volume shape). Holders only | RC-63(c) |
| **T-I22** | B7 disclosures, all accepted at Low:<ul><li>`GRANT_EXCEEDS_CALLER`: one bit, "R ⊄ my holdings";</li><li>`ADMINISTRATOR_REQUIRED` on revoke: the admin-defining bit, reachable only for an existing assignment, because the 404 comes first;</li><li>429 versus evaluated: RES-33, now explicit for any role id;</li><li>`Retry-After`: the actor's own window.</li></ul>`role:read` holders already see admin-defining status through B6. Reaching the throttle requires five audited denials. Unflagged shipping is acceptable | RC-63(l); RES-47 |
| **T-I23** | V11 ordering: a mint that read the stale permission set before the flush can rewrite it after the flush (US-018 L-4, accepted for attach), so that administrator lacks `user:directory:read` for up to cache TTL plus token TTL (1,800 s) after the flush, not 900 s. It fails safe (403 on B1, an availability effect only) | RC-63(d) |
| **T-S12** | Directory emails are attacker-chosen strings:<ul><li>anonymous registration into the default tenant;</li><li>PENDING rows carry unverified addresses, including other people's;</li><li>look-alike and confusable addresses (NFC does not fold confusables);</li><li>CSV formula payloads (`=`, `+`, `-`, `@` are legal in local parts).</li></ul>An administrator browsing the directory can mistake a squatter for a colleague | RC-63(e) (D5 and US-020 carry-forward) |
| **T-R17** | B8 audit rows are grouped by `RequestContext` correlation id, which is client-controlled (§0.2 #7), so reuse or collision blurs per-PUT grouping. A demotion of an admin-defining role by B8 emits no class-change signal, while a promotion does (row 14) | RC-63(f) |
| **T-E52** | Seeders run under `dev & !break-glass`, so `SPRING_PROFILES_ACTIVE=dev,prod` seeds known-password administrators (one today, two after C1). The compose stack runs `dev`. Seeding with `assigned_by = self` mimics the break-glass signature (US-018 RC-37.5) and makes US-020's promotion e2e hit `RBAC_010` | RC-63(g) |
| **T-I24** | CI job:<ul><li>the rate-limit overrides need a home outside `docker-compose.yml`, whose `backend` passes no such variables;</li><li>`trace: 'on-first-retry'` records API request bodies (persona passwords, lookup sentinels) into uploaded artifacts;</li><li>the PII scan checks addresses but not their blind indexes, although the dev HMAC key is public;</li><li>the workflow trigger and permissions are unstated (`pull_request_target` would run fork code with a write token)</li></ul> | RC-63(h) |
| **T-T25** | `safeReturnUrl` "decodes once" on a value `queryParamMap` already decoded: a second decode. The string validated and the string navigated must be the same. `PublicLayout`'s unguarded children are not pinned. US-020 routes must never mutate on activation (an in-app `returnUrl` could otherwise trigger an action after login). Optional: `canActivateChild: [authGuard]` on the shell, so a session lost mid-shell routes to login rather than Access Denied (fails closed either way) | RC-63(i) |
| **T-I25** | `UserDirectoryIT` byte equality must normalise `traceId` **and** `instance` (Spring fills `instance` with the request path, which differs per id). The design keeps the target id out of the cross-tenant WARN, but `ApiRequestLoggingFilter` logs the path (`/api/v1/users/{id}`) under the same correlation id; ids are not PII, so state it accurately. `existsById` stays the inherited JPA method (no `UNSCOPED_ALLOWLIST` change). Any declared unscoped method needs an allowlist entry and Security sign-off (RC-61.2 is the one proposed) | RC-63(j) |

### 3.3 Attacked and survived (Low)

| ID | What I attacked | Why it holds |
|---|---|---|
| **T-S13** | B4 as an IDOR, as a cache or JWT echo, as a re-implemented predicate | No identifier is bindable (ArchUnit); four live reads in one RR snapshot; `isCallerAdministrator` reused; flag-gated; `no-store` |
| **T-I26** | Lookup and by-id as cross-tenant existence oracles; flag-off versus `USER_NOT_FOUND` | The unique `(tenant_id, email_hmac)` makes a foreign hit a plain miss, byte-identical. By-id runs the same two PK statements on both miss kinds. A non-holder gets 403 before any 404, so the code split tells only holders whether the feature is on, which is not secret. POST keeps the email out of every URL sink (§0.2 #10) |
| **T-D27** | An unauthorized caller using B8 to take the set lock or the role row (ADR-0018 follow-on rule) | Steps 1–7 take no lock. Only authorized callers lock. A non-administrator can reach the set lock only through one promotion per role (adds ⊆ union) |
| **T-E53** | V11 promoting anyone, or the content-hash ETag missing a migration write | Footer (a) completes only complete live roles; `MEMBER` gets nothing. The content hash *is* the state, so a pre-V11 ETag fails 412 after the footer (the version-column alternative would have let a PUT silently undo it, §10.2) |

---

## 4. Verdicts on the brief's scrutiny items

### 4.1 B8 soundness under REPEATABLE READ

| Claim | Verdict | Basis |
|---|---|---|
| Authorize before lock | **CONFIRMED** as a DoS and lock-amplification control | T-D27. The cost is T-E51 (snapshot spans the wait), at Low |
| ETag compared on a fresh read under the role lock | **DISPUTED as specified; CONFIRMED with RC-55** | `FOR SHARE` is a current read, and the role-row X lock serialises PUTs on R. Only equality with `v0` makes S0-based decisions valid (T-T22) |
| Lock order versus RC-46 and ADR-0018 | **CONFIRMED with a text correction** | Order by current class: admin-defining means set lock then role row; otherwise role row, then the set lock on promotion; `role_permissions` last. I found no new cycle with assign, revoke, softDelete, PATCH, B8∥B8 or break-glass. **Attach is mis-described** (T-T24): it waits on the role row through the FK check, not on the gap. RES-45 (classification flip, 1213 victim) extends as the design says |
| `nexus_app` privilege for the locking read | **CONFIRMED by precedent; the IT is merge-blocking** | §0.2 #1. The fallback is sound |
| New deadlock cycles with assign, revoke, softDelete, attach, detach | **None found** beyond RES-45, conditional on T-T24's IT | The RC-56 and RC-57 additions were checked for order: each new `FOR SHARE` on `role_permissions` comes after the requester's `user_roles` or `roles` locks, and no `role_permissions` writer waits on `user_roles` or `roles` while holding a record lock (T-T24 condition). Two racing attaches under RC-56.3 can deadlock each other: one 1213 victim, intended |
| Empty set; idempotent no-op | **Empty set CONFIRMED** (a demotion on an admin-defining role; 409 on system roles). **No-op DISPUTED** | The no-op returns the set without authorization (T-I20) |
| PUT removing the last administrator's admin-defining role, or demoting the caller | **CONFIRMED for one request; DISPUTED for two concurrent requests** | T-E49 |
| Q5 (set lock when before or after is admin-defining) | **CONFIRMED with RC-55 and RC-57** | Without RC-57 the lock serialises but decides on pre-lock classification |

### 4.2 V11 and the administrator definition

- **Who becomes an administrator:** nobody. Confirmed (T-E53).
- **Who stops being an administrator:**
  - only roles that a concurrent attach or detach caught mid-migration at 8 of 9, which fail closed;
  - and, from V11 on, any custom role an administrator later builds with eight permissions.

  The runbook, C1 and the tests enumerate the catalogue (§3.5), which I endorse. The literal-scan test and `assertAdministrator` are the right mechanical controls.
- **Token-staleness window:** 1,800 s worst case after the flush, not 900 s (T-I23). Authorization decisions are unaffected (M13/M15 are live).
- **Custom admin-equivalent roles:** preserved by footer (a), proven by the semantic IT.
- **A tenant left without an administrator:** not by V11. By B8 races, yes (T-E49).
- **Grant-subset spill-over:** after V11 a "role manager" cannot edit roles that carry the new permission. This is intended, and correctly flagged for D3.

### 4.3 Directory enumeration and PII

| Item | Verdict |
|---|---|
| POST lookup | **CONFIRMED** (T-I26). Add the RC-59 body handling |
| 404 `USER_NOT_FOUND` versus `RESOURCE_NOT_FOUND` as an oracle | **CONFIRMED not an oracle.** The flag state is visible to holders only and is not secret |
| Timing | **CONFIRMED** for cross-tenant versus missing (same statements). Hit versus miss inside the tenant is the purpose, as stated |
| Byte-identical cross-tenant misses | **CONFIRMED** with T-I25's normalisation |
| Field allow-list | **CONFIRMED** |
| Throttle fails open | **ACCEPTED** (RES-49). The permission is the gate; D5 records it |
| Best-effort audit | **ACCEPTED** (RES-50). It is a read, and the fail-closed variant would need a writable transaction. D5 may still choose fail-closed |
| Logs, metrics and traces carrying emails or hashes | **CONFIRMED** for designed paths (§0.2 #9, #10). **DISPUTED** for malformed bodies (T-I21). CI scan extension in RC-63(h) |
| Ids batch as a cross-tenant probe | **CONFIRMED not an oracle; DISPUTED on detection** (T-R16, RC-61.2) |
| Bulk enumeration by a holder | **Honest limit CONFIRMED; detection DISPUTED** (T-R16) |
| Delegation of PII access | **New, Medium** (T-E50) |

### 4.4 B7

The two disclosed bits, the explicit 429 bit and `Retry-After` are accepted at Low (T-I22, RES-47). Unflagged shipping is **accepted** under RC-63(l). The decoupled wire values are the right call: `NOT_TENANT_ADMIN` would freeze a stale name on the wire. Mapping the administrator-through-another-role failures of detach, PATCH, DELETE and B8 to `GRANT_EXCEEDS_CALLER` is also correct, because it adds no new bit on those paths.

### 4.5 B4 as the UI's source of truth

**CONFIRMED** (T-S13).
- **Stale tokens.** After a revoke the old bearer is rejected by the epoch check (401 → refresh), so B4 never answers from a revoked token. After an attach the bearer lacks the new permission (fail-safe), and B4 already shows it.
- **Divergence.** UI affordances can diverge from the JWT-driven nav for one token TTL. That is US-020 G6's to handle, and the server stays authoritative.
- **Degraded Redis.** If Redis is degraded-open (US-018 RES-30), B4 still reads live and stays correct.

### 4.6 Frontend

| Item | Verdict |
|---|---|
| Guard composition | **CONFIRMED.** Ancestor `authGuard`; contract spec; single-refresh real-Router test |
| `returnUrl` open-redirect validation | **CONFIRMED** as defence in depth; `navigateByUrl` cannot leave the origin. RC-63(i) fixes the double decode |
| 503 `AUTH_005` | **CONFIRMED** |
| XSS in role and permission names | **CONFIRMED** today. RC-62 is needed before US-020 binds directory data |
| CSV export escaping | **Not present** in US-019. Carried forward (T-S12) |
| Nav hide versus disable | **CONFIRMED** as UX. Hiding by the JWT claim leaks nothing the user's own token does not hold |

### 4.7 CI and dev

| Item | Verdict |
|---|---|
| Seeded credentials | **ACCEPTED** as dev-only, with RC-63(g) (`!prod`) |
| Email at INFO in `DevDataInitializer` | **CONFIRMED fixed by design** (`:100`). `DevPersonaSeedIT` scans the log |
| Rate-limit relaxation limited to the CI job | **CONFIRMED in intent; mechanism unspecified** (RC-63(h)) |
| `storageState` and refresh-token reuse | **CONFIRMED** sound with worker-scoped contexts |

---

## 5. Summary of threats by severity

| Severity | Count | IDs |
|---|---|---|
| **Blocker** | 0 | — |
| **High** | 1 | T-T22 (B8 `If-Match` membership instead of equality) |
| **Medium** | 7 | T-E48 (`RBAC_010` under concurrency), T-E49 (set lock with pre-lock classification; single-actor zero-admin), T-I20 (B8 check order oracle; unauthorised no-op), T-I21 (malformed body: 500 and logged text), T-E50 (PII permission delegation), T-R16 (bulk-read detection), T-T23 (Angular advisory, A06) |
| **Low** | 15 | T-T24, T-E51, T-D26, T-I22, T-I23, T-S12, T-R17, T-E52, T-I24, T-T25, T-I25, and attacked-and-survived T-S13, T-I26, T-D27, T-E53 |
| **Total** | **23** | |

Per slice, so each PR traces its own threats:

| Slice | Threats |
|---|---|
| S1a (V11) | T-I23, T-E53 |
| S1b (B3, B5) | RC-63(k); T-I25 (B3 equivalence) |
| S1c (directory) | T-I21, T-E50, T-R16, T-D26, T-S12, T-I25, T-I26 |
| S1d (B4) | T-S13 |
| S2 (frontend foundations) | T-T23, T-T25 |
| S3a (B6) | RES-48 |
| S3b (B7) | T-I22 |
| S3c (B8, CORS, 412/428) | T-T22, T-E48, T-E49, T-I20, T-I21 (body), T-T24, T-E51, T-R17, T-D27 |
| S4a (C1) | T-E52 |
| S4b–c (C2, C4) | T-I24 |
| S5a (A7–A10) | T-T25 |

---

## 6. Required design changes (back to architect)

Each item is a concrete change to `03-design.md` or a proposed ADR, required **before Gate 2 closes** unless marked "task". Each becomes at least one `/breakdown` task. **Architect decisions** (not edits) are marked ◆: RC-56.5, RC-57.2, RC-58.4, RC-60.3.

**RC-55 — B8 compares the locked state to the authorised snapshot (T-T22, High; S3c)**
1. §10.3 step 9 becomes: *"`v1 = version(roleId, S1)`; if `v1 ≠ v0` → 412 (a concurrent writer won). `v0` is the snapshot version that steps 5–7 used."* Membership of `v1` in `If-Match` is not sufficient.
2. `IfMatchHeader.parse` accepts **exactly one** strong entity-tag. A list of more than one, `*`, a weak-only header, empty or unparseable → 428 `PRECONDITION_REQUIRED`. The editor never needs a list, and this removes the multi-tag search in T-I20.
3. Rewrite the "Why `v1 = v0`" paragraph so it describes the check that is actually made.
4. `RolePermissionReplaceConcurrencyIT` adds case (g): a PUT with `If-Match: v(S0)` while an attach commits between the snapshot and the lock gives 412, with no `role_permissions` or `auth_events` change. Add a unit test for two-tag rejection.
5. ADR-0027 states that the ETag is computable by anyone who knows the ids: a concurrency validator, not a capability or a secret.

**RC-56 — `RBAC_010` holds under concurrency (T-E48, Medium; S3c, with US-018 code)**
1. §10.4 adds the B8 promotion versus a queued assign or attach to the proof table: assign (INSERT … SELECT) and attach (FK parent check) wait on R's row and then commit on their pre-wait classification.
2. **assign, non-admin-defining path:** after `assignIfRoleLive`, run a current read of R's permission ids (`… FROM role_permissions WHERE role_id = ? FOR SHARE`) against M15. If R is now admin-defining, roll back with a retryable 409 (a new code, or `RBAC_010` with a distinct `detail`). On retry the set-lock path, A4 and A2 apply.
3. **attach:** after the INSERT, the same current read. If the committed state plus this row completes the catalogue while the snapshot said it did not, roll back with the same retryable 409. Two racing attaches then deadlock: one 1213 victim (RES-45 extended); on retry, `RBAC_010` applies.
4. **Committed-state detector** (attach, B8, assign), in the existing after-commit read-only transaction: if R is admin-defining **now** and has an active holder whose assigner is not currently an administrator, page with WARN `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER {tenantId, roleId, holderCount, nonAdminAssignedCount}` (ids and counts only) and a counter, with no tenant tag.
5. ◆ Items 2 and 3 change US-018 code paths. Security recommends landing them in S3c, because B8 makes the race deterministic. If deferred, item 4 is mandatory in S3c, and RES-26 records the gap with an owner and date.
6. ADR-0021 Revision 3 corrects US-018 §11.3 R1-1: B8 is a second path to admin-defining, and two attaches bypass the snapshot check.
7. Harness: attach p ∥ attach q on an 8-of-9-minus-one role with a non-administrator-assigned holder (never both succeed); B8 (+q) then a queued attach of p (409); an assign queued behind a B8 promotion (409, never a non-administrator-assigned holder of an admin-defining R).

**RC-57 — Current classification under the set lock (T-E49, Medium; S3c)**
1. B8 steps 10 and 11: after the set lock, re-derive the admin-defining set from `SELECT role_id, permission_id FROM role_permissions WHERE role_id IN (:lockedRoleIds) FOR SHARE` (a current read; `nexus_app` holds `DELETE` on the table, and the `RolePermissionsPrivilegeIT` case covers the statement). "Administrator through a role other than R" then means a locked `user_roles` row × a currently admin-defining role. An uncommitted detach on another role is waited for and then seen.
2. ◆ Apply the same re-derivation to `revoke`'s administrator requirement and lockout, and to `softDeleteRole`'s admin-defining path (US-018 code). Security recommends it: it closes the B8-then-revoke path. If not adopted, RES-28 is re-scoped per §7.
3. Correct §10.4's residual text. The set lock serialises B8s and revokes, but without item 1 their classification of other roles predates the lock. **One administrator sending two concurrent demotions reaches zero administrators** in a tenant whose administrators hold only custom roles. Record the same correction for detach (US-018 RES-28 is single-actor-triggerable, not race-only).
4. Harness C adds: two B8 demotions by one caller holding R and R2 (exactly one succeeds; zero-admin never reached); a B8 demotion ∥ a revoke of the last other administrator (the lockout holds).

**RC-58 — B8 authorises before it reveals state (T-I20, Medium; S3c)**
1. Order of checks: 400, 428, 404 role, 409 `RBAC_003`, 404 permission, **403 (step 7: L-1, A3 on adds, role-subset on removes, the administrator rule on demotion)**, then 412 (snapshot), then the no-op 200, then the locks. The no-op is therefore authorised: L-1 at least.
2. The 412 and 428 bodies carry no ETag, no permission ids and no count.
3. Test: a `role:write` holder who lacks one of R's permissions gets 403 for every combination of body and `If-Match` that removes something, never 412 or 200. A holder whose live M13 lacks `role:write` gets 403 on a no-op.
4. ◆ B8 additionally requires `role:read` (live, M13), because its 200 returns the representation. Security recommends it. If rejected, record that a caller authorised to replace R wholesale can learn R's composition by 412 versus 200.

**RC-59 — Request-body and protocol exceptions (T-I21, Medium; S1c, S3c)**
1. `GlobalExceptionHandler` adds:
   - `HttpMessageNotReadableException` → 400 `VALIDATION_FAILED`, generic detail "Request body is not valid JSON.";
   - `HttpMediaTypeNotSupportedException` → 415;
   - `HttpRequestMethodNotSupportedException` → 405;
   - `MissingRequestHeaderException` → 400.

   Each logs `errorType` and `errorCode` only, **never `getMessage()` or the cause**. This also corrects the 500s on attach and assign that `AttachPermissionRequest.java:11-12` works around.
2. The log-scan IT (§4.7) adds:
   - `{"email": <sentinel unquoted>}`;
   - `{"email": ["<sentinel>"]}`;
   - a truncated body;
   - `Content-Type: text/plain`.

   Each must give 400 or 415, and neither the sentinel nor its local part may appear in the captured output.
3. Task: the lookup rejects a body larger than 1 KiB before parsing (an authenticated memory-amplification bound).

**RC-60 — PII-permission delegation (T-E50, Medium; S1c, D5)**
1. ADR-0026 and the D5 record state: under A2/A3 any holder of `user:directory:read` with `user:role:assign` or `role:write` can grant tenant-wide email access onward, including to a self-registered second account (the RES-26 shape). The C1 "User Manager" persona is such a delegator.
2. Detective, in S1c: when a caller who is **not** an administrator attaches `user:directory:read` (by its seeded id), or assigns a role that carries it, emit WARN `RBAC_PII_PERMISSION_DELEGATED {tenantId, actorUserId, roleId, targetUserId|null}` (ids only) and a counter (ticket). Add the marker to the ≥ 1-year retention list (RES-6).
3. ◆ Preventive option: attaching `user:directory:read`, or assigning a role that carries it, requires an administrator. This is a server rule keyed by permission id, not by `isSensitive`, and is evaluated with A2/A3. Security recommends that D5 decide explicitly. If rejected, RES-51 stays Medium with a named owner.

**RC-61 — Directory detection (T-R16, Medium; S1c)**
1. §17 adds a log-derived alert on the sum of `resultCount` per (tenant, actor) across LIST, BATCH, GET and LOOKUP: ticket above 1,000 rows per hour, page above 10,000 rows per hour or above the tenant's user count in a day (thresholds for Ops to confirm). The existing lookup-volume alert stays.
2. Batch cross-tenant parity: one extra PK-driven statement, `countByIdIn(ids)` (unscoped, count only). Emit WARN `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET {operation=BATCH, omittedCount}` when the count exceeds `returnedCount`. This needs an `UNSCOPED_ALLOWLIST` entry. **Security sign-off is given here, conditional on:**
   - it returns a count only;
   - it is called only by the directory adapter (an ArchUnit containment rule, as for `existsSuccessfulBreakGlassGrantWithChangeRef`);
   - the response never depends on it.

   Both miss kinds run the same statement, so NF-S2 holds.
3. Task: a per-actor ceiling across all directory operations (for example 600 requests per minute, on the existing `RateLimitStore`, fails open). It bounds line-rate paging by a stolen token without affecting a human.

**RC-62 — Frontend dependency and sink hygiene (T-T23, Medium, A06; S2)**
1. Upgrade `@angular/*` to ≥ 22.2.0 (covers GHSA-hh8m-fm6v-7cvg, GHSA-p297-fm68-3q8c and GHSA-ff3f-86qr-9cv3) in S2, before the new `shared/ui` directives merge. Re-run `npm audit --omit=dev`; the production graph must be clean of high or critical findings.
2. Record the toolchain-only criticals with the Frontend Tech Lead as owner and a review date.
3. Add an ESLint rule forbidding `[innerHTML]`, `[outerHTML]`, `bypassSecurityTrust*` and `nativeElement.innerHTML` in `src/app/**` (an empty allow-list today), so US-020 cannot render directory or description text unsanitised.

**RC-63 — Low items (tasks)**
- **(a) T-T24.** Correct §10.4's attach and detach rows (attach waits on R's row through the FK parent check). The concurrency IT runs B8 ∥ attach in both arrival orders **as `nexus_app`** and asserts no 1213 outside RES-45's flip case.
- **(b) T-E51.** Restate RES-27 for B8: the window runs from the first consistent read to the end of the role-row wait. Optional: `SET SESSION innodb_lock_wait_timeout = 5` for the B8 transaction (no privilege needed), mapping 1205 to 409 "retry".
- **(c) T-D26.** Reject `page × size > 10,000` with 400 (or move to keyset paging). `USER_DIR_001` is `selfReported()`, with one WARN per window. Capacity notes state the second pooled connection per directory request.
- **(d) T-I23.** The V11 runbook enables us019 only after one of: (i) 1,800 s after the flush; (ii) a second flush 900 s after the first; or (iii) an administrator's freshly refreshed token is verified to carry `user:directory:read`.
- **(e) T-S12, carried to D5 and US-020.**
  - The console shows `status` and `emailVerified` next to every email, and visually marks PENDING (unverified) rows.
  - CSV export (US-020 E3) prefixes cells starting with `=`, `+`, `-`, `@`, tab or CR, and is audited.
  - US-020/Epic 3 decides whether role assignment to PENDING users is refused.
  - D5 notes that emails are self-asserted until verified.
- **(f) T-R17.** B8 audit metadata carries a server-generated `replaceId` (UUIDv7) beside `operation=REPLACE`. A B8 that demotes an admin-defining role emits WARN `RBAC_ROLE_CEASED_ADMIN_DEFINING {tenantId, roleId, holderCount}` and a counter (ticket).
- **(g) T-E52.**
  - Seeders use `@Profile("dev & !break-glass & !prod")`, and `DevSeedProfileGuardTest` adds a `dev,prod` context.
  - Persona assignments use `assigned_by` = the seeded administrator, never self.
  - A startup WARN `DEV_SEED_ACTIVE` names the profile, so a shared environment running `dev` is visible.
- **(h) T-I24.**
  - The workflow uses `on: pull_request` (never `pull_request_target`), `permissions: contents: read` and no secrets.
  - Rate-limit overrides live in a CI-only compose override file referenced only by the workflow, with defaults equal to `application.yml`; a test asserts no `application*.yml` raises them.
  - The PII scan also covers the persona addresses' blind indexes (the dev HMAC key is public in `application-dev.yml`) and the uploaded Playwright report and traces.
  - Artifact retention is ≤ 7 days.
  - No test opens two pages in one persona context at the same time.
- **(i) T-T25.**
  - `safeReturnUrl` performs no additional decode, or validates and returns exactly the string it navigates to; the adversarial table adds `%252F%252Fevil.example`.
  - A contract spec pins `PublicLayout`'s children to `{auth, access-denied, design-system}`.
  - D6 states that no route performs a mutation on activation.
  - Optional: `canActivateChild: [authGuard]` on the shell.
- **(j) T-I25.**
  - Equivalence ITs normalise `traceId` and `instance`.
  - §4.2 states that the request log carries the path id under the same correlation id.
  - `existsById` remains the inherited method (no allowlist change).
- **(k) B5.** ArchUnit: `Permissions.SENSITIVE` and `NON_SENSITIVE` are referenced in `src/main` only by the `PermissionResponse` mapper, so no server rule can start depending on them.
- **(l) T-I22.**
  - `CallerFacingDenialReason` is applied only to `RBAC_001`, never to `ACCESS_DENIED`.
  - The SPA does not auto-retry `RBAC_011` (spec).
  - Update the RES-33 text: the bit is now explicit on every target through the 429.

---

## 7. Residual risk register

RES-47 onward is new. Owners are roles. **Accept** means the residual can be accepted at Gate 2 once its RC lands. **Escalate** means it needs a named role's explicit decision.

| # | Residual | Severity (after RC) | Owner | Disposition |
|---|---|---|---|---|
| **RES-47** | B7 discloses `GRANT_EXCEEDS_CALLER` (one composition bit), `ADMINISTRATOR_REQUIRED` on revoke, and the explicit 429 admin-defining-or-self bit | Low | Security (Gate 2) | Accept with RC-63(l) |
| **RES-48** | `memberCount` under `role:read` reveals single-holder admin-defining roles | Low | Security + PM (D5) | Accept at D5 |
| **RES-49** | A `user:directory:read` holder can enumerate the directory; the lookup throttle fails open with Redis down | Low with RC-61 (detected) · Medium without | Security/Privacy (D5) | **Escalate to D5** |
| **RES-50** | Directory audit is best-effort (`REQUIRES_NEW`, retry buffer, may drop under DB outage) | Low | Security/Privacy (D5) | Accept, or D5 chooses fail-closed |
| **RES-51** | PII permission delegation by non-administrators (T-E50) | Low with RC-60.3 · **Medium** without | Platform Security Owner + DPO | **Escalate to D5** |
| **RES-52** | V11 availability window: administrators may get 403 on B1 for up to 1,800 s after the flush if us019 is enabled early | Low with RC-63(d) | Ops | Accept |
| **RES-26** *(inherited)* | Pre-positioning through a second account; partial escalation detective | Medium, unchanged **if RC-56 lands**; **High** if neither RC-56.2–3 nor RC-56.4 lands (the provenance rule would be bypassable at will) | Platform Security Owner | **Escalate:** confirm at Gate 2 that the B8 path and the attach race are covered |
| **RES-27** *(re-scoped)* | Snapshot TOCTOU: milliseconds on lock-free paths; on B8's role-row path it spans the lock wait | Low | Architect | Accept with RC-63(b) |
| **RES-28** *(re-scoped)* | Zero administrators through concurrent demotions. **Single-actor-triggerable** (two requests), not race-only. With RC-57.1 closed for B8; remains for detach ∥ detach and, without RC-57.2, for a B8 demotion followed by a revoke. Detected by the zero-admin indicator (pages); recoverable by break-glass only where a system `TENANT_ADMIN` exists | Low with RC-57.1 and RC-57.2 · **Medium** with RC-57.1 only | Architect + SRE | **Escalate** if RC-57.2 is rejected |
| **RES-45** *(extended)* | Classification flip between non-locking reads; with RC-56.3, two racing catalogue-completing attaches also give one 1213 victim (a 500); integrity holds | Low | Architect | Accept. Revisit if the 1213 rate is non-zero |
| **RES-39** *(inherited)* | Frontend guard fail-open on missing `data.permission` | Low | Frontend Tech Lead | Accept (`nav.config.spec.ts`, route spec) |
| **RES-41** *(inherited)* | Tenants without a system `TENANT_ADMIN` (including the dev second tenant) cannot be recovered by break-glass | Medium | PM (Epic 3) | Accept (unchanged) |
| **RES-6** *(inherited)* | Log retention now also covers `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and `RBAC_PII_PERMISSION_DELEGATED` | Medium until Ops signs | Architect + Ops | Merge-checklist sign-off on S1c |

---

## 8. Cross-references to prior threat models

| Prior item | Status after US-019 |
|---|---|
| **US-018 R1-1 / ADR-0021 D8** (`RBAC_010`; "attach is the only path") | **Disputed.** B8 is a second path, and two attaches bypass the snapshot check (T-E48, RC-56) |
| **US-018 RES-28** (detach to zero administrators, "race-only") | **Re-scoped:** one actor can trigger it. Closed for B8 by RC-57.1 (T-E49) |
| **US-018 T-E33 / RC-25** (snapshot predates a lock wait) | The pattern recurs: on B8's role-row path (T-E51, Low) and for verbs queued behind B8's locks (T-E48) |
| **US-018 RC-46 / RES-45** (lock order by current class) | Upheld and extended by one verb (§4.1); the attach row needs correcting (T-T24) |
| **US-018 RES-33 / T-I18** (throttle reveals admin-defining) | Made explicit by the 429 (T-I22, RES-47) |
| **US-018 RC-38 / RES-37** (`audit:read` propagatable) | Same property for `user:directory:read`, with PII (T-E50, RES-51) |
| **US-018 T-R13 / RC-39** (cross-tenant evidence as WARN) | Extended to directory by-id; batch parity via RC-61.2 |
| **US-018 RC-33.1** (log volume of throttled requests) | Preserved for `RBAC_011` by `selfReported`; extended to `USER_DIR_001` (RC-63(c)) |
| **US-016 D5 / US-015 R-6 trap** (a locking read passes as superuser, fails as `nexus_app`) | Addressed by design (`RolesPrivilegeIT` as `nexus_app`); merge-blocking |
| **US-018 T-T16 / RES-32** (Redis is authorization state) | Unchanged. New keys (`DIR_LOOKUP`, the `PTTL` read) add no write-to-privilege path |
| **US-018 T-I19 / RC-40.7** (no query parameters on the 403 redirect) | Preserved. `returnUrl` is a deliberate, `authGuard`-only exception (T-T25) |
| **US-018 RES-39** | Unchanged |

---

## 9. Required changes back to the architect, and merge blockers

### 9.1 Required changes (concrete asks)

| RC | Severity | Ask | Slice |
|---|---|---|---|
| **RC-55** | **High** | Step 9 compares `v1` to `v0` (not to the `If-Match` list); `If-Match` takes exactly one strong tag; fix the soundness paragraph; IT case (g); ADR-0027 says the ETag is not a secret | S3c |
| **RC-56** | Medium | Record queued assign and attach behind B8; assign and attach re-classify with a current `FOR SHARE` read after insert and fail retryable 409 (◆ whether in S3c); a committed-state detector that pages; correct R1-1 in ADR-0021 Rev 3; harness cases | S3c (+ US-018 code) |
| **RC-57** | Medium | B8 steps 10 and 11 re-derive the admin-defining set from a current `FOR SHARE` read of `role_permissions` under the set lock; ◆ the same for revoke and softDelete; correct the RES-28 text (single-actor); harness C cases | S3c |
| **RC-58** | Medium | Order: 403 (step 7) before 412 and before the no-op; 412 and 428 bodies carry no state; tests; ◆ require live `role:read` for B8 | S3c |
| **RC-59** | Medium | Handlers for unreadable body, media type, method and missing header that never log the message; log-scan IT with malformed bodies; 1 KiB lookup body cap (task) | S1c, S3c |
| **RC-60** | Medium | ADR-0026 and D5 record delegation; WARN and counter on PII-permission delegation by a non-administrator; ◆ administrator-only rule for granting `user:directory:read` | S1c, D5 |
| **RC-61** | Medium | Row-volume alert per actor across all directory operations; batch cross-tenant count and WARN (allowlist entry signed off here with containment); per-actor directory ceiling (task) | S1c |
| **RC-62** | Medium | `@angular/*` ≥ 22.2.0 before the `shared/ui` directives merge; production audit clean; ESLint ban on HTML sinks | S2 |
| **RC-63(a)–(l)** | Low | Tasks as listed in §6 | Per item |

### 9.2 Merge-blocking list

**S3c (B8, CORS, 412/428) does not merge until:**
- RC-55 (all items), RC-58.1–58.3 and RC-57.1 are in the code with their tests;
- RC-56.4 (detector) is in; RC-56.2–56.3 either land or their deferral is recorded with an owner (◆ RC-56.5);
- `RolesPrivilegeIT` (the `roles` `FOR UPDATE`, blocking second connection) and `RolePermissionsPrivilegeIT` (`FOR SHARE`, including RC-57.1's statement) are green **as `nexus_app`**, with `SHOW GRANTS` unchanged;
- `RolePermissionReplaceConcurrencyIT` cases (a)–(g) and harness C (with the B8 demotion and promotion threads and RC-57.4's cases) are green, with no 1213 outside RES-45;
- RC-59.1 (body handler) is in;
- RC-63(a) is done.

**S1c (directory) does not merge until:**
- D5 is signed (POST lookup, fail-open throttle, best-effort audit, the enumeration-by-holder statement, RES-49, RES-51);
- RC-59 (handlers and malformed-body log scan), RC-60.1–60.2 and RC-61.1–61.2 are in;
- Ops has signed RES-6 retention for `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and `RBAC_PII_PERMISSION_DELEGATED`;
- `UserDirectoryIT` (with RC-63(j) normalisation) and the log-scan IT are green.

**S2c (`shared/ui` wrappers and directives) does not merge until:** RC-62.1 and RC-62.3 are in.

**S3b (B7) does not merge until:** RC-63(l) is in, and RES-47 acceptance is recorded at Gate 2.

**S1a (V11) does not merge until:** the RC-63(d) runbook ordering is written, and the V11 semantic IT and `PermissionMigrationFooterScannerTest` (unmodified) are green.

**S4a and S4c (personas, CI job) do not merge until:** RC-63(g) and RC-63(h) are in.

**All slices:** `./mvnw dependency:tree` and `npm audit` are re-run at each Phase 7. Today's baseline: no manifest delta; the production npm graph has 7 findings (1 high, 6 moderate, all `@angular/*` 22.0.4), cleared by RC-62.1.
