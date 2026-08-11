# US-013 -- Code Review

**Feature:** US-013 -- Implement Angular Permission Guard and Directive
**Epic:** EPIC-002 (RBAC Foundation)
**Branch:** `feature/US-013` (uncommitted working tree vs. `origin/main`)
**Reviewer:** code-reviewer sub-agent (fresh context)
**Cross-referenced against:** `docs/features/US-013/03-design.md`, `03b-threat-model.md` (verdict PASS WITH REQUIRED FOLLOW-UPS, 6 required mitigations), `01-requirements.md`, `04-tasks.md`, `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT_GUIDE.md`.

**Scope note:** Three unrelated, pre-existing uncommitted edits (`password-strength-meter.component.ts`, `registration-form.component.html`, `shared/ui/select/select.ts`) are excluded from this review per the task brief -- they are not part of US-013.

**Verification performed:** read every new/modified file listed in the task brief; read `03-design.md` (all 1361 lines), `03b-threat-model.md` (all 426 lines), `01-requirements.md`, `04-tasks.md`; ran `ng test --no-watch` (29 files, 195 tests, all green), `ng lint` (all files pass), `ng build` (succeeds, one pre-existing unrelated SCSS budget warning on `design-system-preview.component.scss`); grep-verified scope-creep guardrails (no `roles` computed added to `AuthStore`, no wildcard `**` route added, no `else`-template on the directive, directive not exported from `shared/ui/index.ts`); diffed every tracked file individually against `origin/main` rather than trusting the task brief's file list.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 2 |
| Low | 2 |
| Nit | 1 |

**Verdict: APPROVE WITH NITS**

The implementation is a faithful, close-to-verbatim transcription of an unusually thorough design and an unusually thorough threat model. All 6 acceptance criteria are met and test-verified; 4 of 6 required threat-model mitigations (T-04/M-2, T-06/M-3, T-08/M-4, T-02/M-5a) are shipped exactly as specified, and all three explicit scope-creep guardrails (no symmetric `roles` signal, no wildcard route, no directive `else`-template) held. The two Medium findings below are both about required threat-model mitigations that did not fully make it from `03b-threat-model.md` into shipped documentation/code, and about a real gap between the mechanical route-table contract's actual behavior and the composition rule it claims to enforce. Neither is exploitable or blocks the story's own stated infrastructure-only scope; both are cheap to close.

---

## Findings

### [Medium] Two of the threat model's six required mitigations (T-09, T-07) never made it into `04-tasks.md` or the shipped code/docs

**File:** `docs/DEVELOPMENT_GUIDE.md` (new "Permission-gating the UI" section) - `nexus-frontend/src/app/app.routes.ts:127-151` (new `/access-denied` route JSDoc) - `docs/features/US-013/04-tasks.md` (T-012, T-013)

**Problem:** `03b-threat-model.md` section 6 lists 6 mitigations as conditions of its PASS verdict, explicitly stating that `04-tasks.md` must contain a task for each, traceable back to its T-number. Grepping `04-tasks.md` for T-07, T-09, T-05a, T-05b, M-5, and M-6 returns nothing -- only 4 of the 6 (T-01/M-5e via the review-checklist note, T-02/M-5a, T-04/M-2, T-06/M-3, T-08/M-4) are traceable into a task. Consequently, two required guide clauses never shipped:
- **T-09 / M-5(b):** "Route gating does not protect code -- a gated route's lazy chunk is an unauthenticated static asset; never place secrets, credentials, internal hostnames, or confidential business logic in a permission-gated component." Grep for "lazy chunk", "static asset", "does not protect code" across `docs/DEVELOPMENT_GUIDE.md` and `app.routes.ts` returns nothing.
- **T-07 / M-5(c):** "`/access-denied` must remain a top-level, unguarded route and must never become a descendant of a route carrying `data.permission`." Grep for "top-level and unguarded" and "descendant" across the same two files returns nothing -- the new route's own JSDoc (design section 4.8 explicitly names this as the right home for the clause) documents what the route is but not this specific constraint.

**Why it matters:** These aren't the two highest-severity findings in the threat model (both are Low there), but the threat model's verdict was conditioned on all six landing, and a future engineer relying on "the threat model passed" as evidence of coverage will find two of its own required items silently dropped between `03b-threat-model.md` and the shipped artifacts. T-09 in particular protects against a realistic future mistake (treating a gated lazy chunk as if it were access-controlled) that this story is precisely the one to warn about, since it is the first story to establish the "gate a route" pattern.

**Suggested fix:** Add both clauses to the "Permission-gating the UI" section of `docs/DEVELOPMENT_GUIDE.md` (T-09 fits naturally alongside the existing "UX only" callout; T-07 fits alongside the "Gating a route" subsection) and to the `/access-denied` route's JSDoc in `app.routes.ts`. Both are one-clause additions per the threat model's own wording -- no design change needed.

---

### [Medium] `permission-guard-contract.spec.ts` enforces a stricter (and different) composition rule than the one the guard's own JSDoc and the design (decision 6) actually permit -- a legitimate future route would fail this gate

**File:** `nexus-frontend/src/app/core/guards/permission-guard-contract.spec.ts:37-61`

**Problem:** `permission.guard.ts`'s own JSDoc (and `03-design.md` decision 6) states the composition contract as: `permissionGuard` MUST be composed after `authGuard`, OR sit under a route whose ancestor already carries `authGuard`. The shipped mechanical contract only implements the first half:

    const authIndex = guards.indexOf(authGuard);
    const permissionIndex = guards.indexOf(permissionGuard);
    if (authIndex === -1 || authIndex > permissionIndex) {
      violations.push(`${path}: authGuard must appear before permissionGuard in canActivate`);
    }

`walk()` never tracks ancestor guards while recursing into `route.children` -- it only inspects each route's own `canActivate` array. A future route that legitimately relies on an ancestor's `authGuard` (the second, explicitly-documented-as-valid half of decision 6) and carries only `[permissionGuard]` itself would be flagged as a violation and fail the build, even though it is exactly the pattern the design and the guard's own JSDoc say is safe.

`04-tasks.md`'s T-007 anticipated this gap and explicitly allowed scoping it down -- "acceptable to scope this to the direct-array case only if ancestor-guard detection proves disproportionate; if scoped down, say so explicitly in the spec's own comment" -- but the shipped spec's file-level comment doesn't state the limitation; it only describes what the check does ("compose `authGuard` before it in the same `canActivate` array"), not what it deliberately does not cover.

**Why it matters:** This is the single highest-value mitigation the threat model asked for (T-03/M-1), and it currently encodes only half of its own documented contract. It's harmless today (vacuously green, no route uses the guard yet), but the first Epic 3 team to use the ancestor-guard pattern will hit a confusing, incorrect build failure and either duplicate `authGuard` needlessly or waste time debugging a spec that's enforcing an incomplete version of its own documented rule.

**Suggested fix:** Either (a) extend `walk()` to carry an `ancestorHasAuthGuard: boolean` parameter down the recursion and OR it into the pass condition, or (b) -- the cheaper, T-007-sanctioned option -- add one explicit sentence to the spec's top comment stating that ancestor-guard composition is out of scope for this mechanical check and must be verified manually/by review, so the residual gap is visible rather than silent.

---

### [Low] `AuthSession.user`'s field-level doc comment still carries the same JWT-decoding inaccuracy this story corrects two paragraphs above it

**File:** `nexus-frontend/src/app/shared/types/auth.ts:108-111`

**Problem:** This story correctly fixes two stale claims in this exact file: `AuthUser`'s header comment (`:1-8`, "Extracted from the JWT access token" corrected to "Populated from `GET /v1/users/me`...") and `AuthSession`'s header comment (`:64-71`, the false `sessionStorage` claim, per threat-model T-08/M-4). But `AuthSession.user`'s own field doc, a few lines below the corrected header, still reads:

    /**
     * Authenticated user identity and roles.
     * Extracted from the JWT claims; immutable during the session.
     */
    readonly user: AuthUser;

This is the identical inaccuracy the story is actively correcting one paragraph up, just not caught because it sits at a different line range than the two the design named explicitly (`:4` and `:52-54`).

**Why it matters:** Low -- it's a documentation-only inconsistency, and the interface it describes is otherwise correctly typed and used. But it directly undercuts the story's own stated purpose in touching this comment (per threat-model section 4.4: a future engineer "restoring the documented behaviour" might reasonably believe they were following the security note) -- the same class of risk now exists at a second, unfixed location three lines away, in a file this review confirms was already open for exactly this kind of correction.

**Suggested fix:** "Populated from `GET /v1/users/me` on login and token refresh; never decoded from the JWT client-side." -- mirrors the corrected `AuthUser` header comment.

---

### [Low] No test exercises `buildSession()`'s `me.permissions ?? []` defensive default against a response that actually omits `permissions`

**File:** `nexus-frontend/src/app/features/auth/auth.service.ts:218-221` - `nexus-frontend/src/app/features/auth/auth.service.spec.ts`

**Problem:** The inline comment on this line (correctly, per design section 4.3) states the default exists specifically for "a newly deployed frontend bundle served against an older backend [that] omits `permissions`." No test in `auth.service.spec.ts` (or elsewhere) constructs a `MeApiResponse`-shaped fixture with `permissions` actually absent and asserts `buildSession()` maps it to `[]`. The two literals that were touched (`ME_RESPONSE`/`EXPECTED_SESSION`, `:225-244`) both add `permissions: ['users:read']` to prove the mapping's happy path, but the wire-defensive-default path itself -- the reason this line exists -- is only exercised indirectly by other specs that construct `AuthStore`/`AuthUser` fixtures directly (bypassing `buildSession()` entirely via `createAuthUser()`'s own `permissions: []` default).

**Why it matters:** Low -- the default itself is a trivial one-liner and `AuthStore.permissions`'s own `?? NO_PERMISSIONS` fallback provides a second line of defense even if this one were ever removed. But it's the one code path in this story that's explicitly flagged in its own inline comment as load-bearing and easy to "simplify away," and it currently has zero direct test coverage proving the regression the comment warns about would actually be caught.

**Suggested fix:** Add one case to `auth.service.spec.ts`'s `login()`/`buildSession()` coverage: flush a `/users/me` response with no `permissions` key at all, and assert the resulting `AuthSession.user.permissions` is `[]`.

---

### [Nit] The threat model's recommended (not required) `Object.freeze` on the populated `permissions` array (T-10/R-a) was not adopted

**File:** `nexus-frontend/src/app/features/auth/auth.service.ts:218-221`

`buildSession()` freezes nothing; `AuthStore`'s `NO_PERMISSIONS` empty-array constant is frozen but the populated array straight off the wire is not, so `authStore.permissions().push(...)` (or a transitive-dependency bug) can mutate the one shared session array at runtime despite the `readonly string[]` compile-time type. `03b-threat-model.md` section 7 explicitly lists this as recommended, not required (R-a), so this is not a gate-blocking finding -- noting it only so it isn't lost, since it's a one-line, zero-risk hardening (freeze a copy of `me.permissions ?? []`) that would make the empty- and populated-array cases symmetric.

---

## Things done well

- **The directive is the standout piece of this diff.** `HasPermissionDirective`'s `effect()`-in-constructor plus `computed()` short-circuit plus plain `hasView` boolean is exactly the pattern the design specifies, and -- more importantly -- the "no redundant DOM churn" test (`has-permission.directive.spec.ts:85-98`) asserts `nativeElement` reference identity via `toBe`, not just content equality, which is the one assertion that actually proves the short-circuit is doing its job rather than coincidentally passing.
- **`permission-guard-contract.spec.ts` genuinely walks the real, imported `routes` array** (not a hand-copied stand-in) and recurses into `route.children` -- exactly what the T-03 mitigation demanded, modulo the ancestor-guard gap noted above. It is a materially better mitigation than the ESLint rule the design's own handoff notes floated and the threat model correctly declined.
- **T-04/M-2 and T-06/M-3 (both required, Low-severity threat-model findings) are both shipped exactly as specified** -- `requiredPermission` is narrowed with a `typeof` guard on copy (`api-error.interceptor.ts:74-76`) rather than a bare pass-through, and the denial log strips the query string at the first `?` with an inline comment explaining why (`permission.guard.ts:57-60`), with both behaviors directly asserted by dedicated spec cases.
- **The `ME_RESPONSE`/`EXPECTED_SESSION` "deep-equality trap" the design called out by name (section 7.3)** was avoided correctly -- both literals got the identical `permissions: ['users:read']` value in the same edit, confirmed by direct diff.
- **`AppError.requiredPermission`'s `@remarks` block names the `GlobalErrorHandler` serialization path concretely** (T-05a), not just a generic "don't render this" warning -- this is exactly the kind of discoverable-at-the-field documentation the threat model asked for.
- **Scope discipline was excellent.** No symmetric `roles` computed signal, no `else`-template on the directive, no wildcard route, no `data.permission` added to any existing route, no new dependency, no new provider -- every explicit "do NOT" from the design and requirements docs was honored, verified by direct grep rather than by trusting the diff's absence of a change.
- **Test suite is genuinely green, not just present:** 195/195 tests pass, `ng lint` is clean, `ng build` succeeds with no new budget or type-check issues.
