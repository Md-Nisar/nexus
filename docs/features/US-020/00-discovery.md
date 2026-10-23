# US-020 discovery (feature-discovery, 2026-10-23)

Story: `docs/story/2-rbac/US-020.md` (approved by the product owner 2026-10-05, written against `9820d4e`, "not yet through Gate 1"). Branch `feature/US-020`, cut from `main` at `adda702` (US-019 merged as PR #93). Bounded context: frontend only, new feature `features/access-management/`. The story says "no backend changes"; discovery below tests that claim.

**Risk tier: high-risk** (EPIC-002: permission gates, the lockout logic the UI predicts, PII shown to directory holders, user-authored text rendered in a page). Full-weight Gate 2 threat model and Phase 7 audit. Tier is for the story owner to confirm.

## Problem

Tenant administrators can manage roles and assignments only with raw HTTP calls. US-020 adds the console (roles, role detail and editor, permission catalogue, users, assignment and revoke) on top of the US-019 platform, with the honest-impact review step as the differentiator.

## Story text vs current code (found by the survey, to be confirmed by the analysis)

| # | Story says | Code at `adda702` | Effect |
|---|---|---|---|
| 1 | Lists are unpaginated `{data}`; D4 "server pagination" waits on US-018 C2 | `GET /roles` and `GET /permissions` are already paged (`data/page/links`, size max 100); `GET /roles/{id}/permissions` is the unpaginated one | A2 "up to 500 roles, client-side search and filter" must change: either page through, or search is server-side. Group D4 is not future work |
| 2 | Group D and E wait for US-018 M9 | M9 shipped: `PATCH`/`DELETE /roles/{id}`, `GET /roles/{id}/holders`, `GET /permissions/{id}/holders`, `GET /users/{id}/effective-permissions` exist | Groups D and E are buildable now; priority and split need a decision |
| 3 | Users list needs `user:read`; emails shown to `user:read` holders | Directory is `GET /users`, `GET /users/{id}`, `POST /users/lookup` behind `user:directory:read` (US-019), grantable only by administrators; `user:read` does not return emails | C1/C2/D1 routes, `data.permission`, nav gating and the "who sees emails" rule all change. A role-manager without the directory permission sees ids only |
| 4 | B4: save is sequential attaches/detaches until B8; G3 "last-write-wins, no ETag" | `PUT /roles/{id}/permissions` is atomic with `ETag`/`If-Match` (412, 428), 403 before 412, 409 `RBAC_012` retry once | Drop the sequential fallback and "partial failure" UI; add 412 "someone changed this role" flow, ETag capture on load, and the retry-once rule for `RBAC_012`. Test scenarios 7 and 18 are rewritten |
| 5 | `RBAC_001` is generic until B7 | `reason` is one of `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT`, `ADMINISTRATOR_REQUIRED`, `UNSPECIFIED`; throttled assign/revoke is 429 `RBAC_011` with `Retry-After` | `RbacErrorMessages` needs reason and 429 copy; D3 deck must cover them |
| 6 | Shell nav item visible to `role:read` **or** `user:read` | `NavItem.permission` is a single `Permission \| null`; `NAV_ITEMS` holds only Dashboard | Any-of visibility needs a model change in the shell, or a single gating permission |
| 7 | Role-detail header uses `GET /roles/{id}` | Exists (B3) with `memberCount`, `permissionCount`; `isSensitive` on permissions (B5) | As designed |
| 8 | "Administrator" = `isAdministrator` from B4 | `GET /users/me/authorization` exists (own data, live) | As designed; guard against a missing us019 flag (the profile 404s when off) |
| 9 | Permission labels and groups come from the D3 deck | `PERMISSION_LABELS` is a placeholder copy of backend descriptions "until D3" | D3 is a hard dependency for A3/A4 copy |
| 10 | F6: console shows "isn't enabled" if the resource returns 404 | Three flags gate it (us012 assignment, us015 role management, us019 directory/profile), all default `false` per environment | F6 must distinguish which flag is off; a partial enablement is likely |
| 11 | P-20/P-32 cold-start 503 | `authGuard` returns `false`; the user sees a blank shell and a toast | US-020 D2 must design the "unavailable, retry" view and the guard must navigate to it |
| 12 | Propagation "about 30 minutes" | `permission-cache-ttl-seconds` 900 + `access-token-ttl-seconds` 900; an epoch key (`key-ttl-seconds` 960) exists in `application.yml` | US-018 A9 (per-user permission epoch, Redis) has shipped; the story says it "will shorten" the text. The 30-minute wording is only an upper bound now, and the F3 constant may need per-action wording (revoke vs grant) and an outage caveat (degraded-open policy). Needs a code read in the analysis (D4) |

## Reuse

Reuse as is: `authGuard`, `permissionGuard`, `safeReturnUrl`, `SKIP_ACCESS_DENIED_REDIRECT`, `Permission` union, `NxTable`, `NxBreadcrumb`, `NxCheckbox` (tri-state), `NxChip`, `NxTabs`, `NxTooltip`, `NxAnnouncer`, `NxSkeleton`, `NxEmptyState`, `NxErrorState`, typed-confirmation dialog, `contracts/api/*.json` fixtures, e2e personas and `enterAddress`/`scan-pii`. Extend: `NAV_ITEMS`, `PERMISSION_LABELS`, e2e persona map. Create: the feature folder, `RbacApiService`, `UserDirectoryApiService`, `AuthorizationProfileService`, `RbacErrorMessages`, `diffPermissions`, propagation constant, CSV neutraliser.

## Impact map

- Backend: none planned. Possible gaps to check in analysis: role-assignment listing with `assignedBy` redaction, email resolution for holders (batch `GET /users?ids=` needs the directory permission), a holders-count for last-admin prediction.
- Frontend: `app.routes.ts`, `nav.config.ts`, dashboard card (G7), new feature folder, `shared/ui` only through existing wrappers.
- Data/Flyway: none. API: consumer only. E2E: first gated route, so the deferred `/access-denied` e2e (P-27) lands here.

## Non-functional and risk flags

- Security: UI gating is UX only; XSS from role names and descriptions (G9); CSV formula injection (E3); PII in logs and Playwright reports (F7, persona emails); ETag handling; stale profile mispredicting.
- Size: about 45 criteria, 7 groups. The story itself expects a split.
- Observability: client logs carry ids, codes and `traceId` only.
- Rollout: no frontend flag; three backend flags, all default off.

## Open questions for Gate 1

Human inputs the story owner named: D2 (designs), D3 (content deck), D4 (propagation wording), P-28 (legal basis and retention for emails), P-20/P-32 (503 retry view), Q-N5 (support contact). Questions found by this discovery: split and MVP cut given Groups D and E are unblocked (items 2); how to treat the paged roles list (item 1); Users-area gating after the directory permission (item 3); any-of nav gating (item 6); which flag-off states to design for (item 10). The business-analyst pass in `01-requirements.md` numbers them.
