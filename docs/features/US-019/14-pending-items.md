# US-019 pending items

**Recorded:** 2026-10-22, at the end of Phase 9 on `feature/US-019` (28 tasks implemented, reviewed, test-audited; not pushed, no PR). Everything below needs a human or later work. **Blocks** is a recommendation for the story owner (Md Nisar Ahmed) to confirm: "merge" means the US-019 PR, "prod" means enabling the feature in production, "US-020" means the console story.

Environments: none exists, so nothing here has run against a real staging or production stack. Local gate on 2026-10-22: backend 2626 unit tests and 693 ITs green (Docker up), frontend 515 tests, lint, format and build green ([08-test-audit.md](08-test-audit.md)).

## Humans: decisions, sign-offs and Ops

| ID | Item | Owner | Blocks | Reference |
|---|---|---|---|---|
| P-1 | Alert thresholds in [monitoring.md](monitoring.md) section 3 (directory row volume 1,000 and 10,000 per hour, lookup volume 200 per hour, cross-tenant rate, B8 contention 20%) are proposals; confirm or replace them and create the alerts | Ops | prod | design §17, §22 (RC-61.1) |
| P-2 | RES-6 retention of at least 1 year for `RBAC_PII_PERMISSION_DELEGATED`, `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and the admin-defining detector WARN `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER` | Ops | prod (design: merge-checklist item on S1c and S3c) | design §2.3 |
| P-3 | D2: wireframes and designs for every US-020 page and dialog, approved by PM and UX | UX, PM | US-020 | requirements D2 |
| P-4 | D3: reviewed content deck (errors per code, confirmations, disabled-reason text, empty states, labels for permissions and groups) | PM, UX | US-020 | requirements D3 |
| P-5 | D4: propagation wording. Config today: `permission-cache-ttl-seconds` 900 and `access-token-ttl-seconds` 900, so "about 30 minutes, or sooner on sign-in"; US-018's epoch may shorten it after a detach. Re-ground the text in current config and re-review | PM | US-020 | requirements K9, D4 |
| P-6 | D5 privacy and security sign-off: **CLOSED 2026-10-20 by Md Nisar Ahmed** for the proposed defaults (design §7 Q-D1 sensitive sets, the `user:directory:read` PII grant rule). Kept for the record | Md Nisar Ahmed | none | `04-tasks.md` header |
| P-7 | C3: per-environment flag plan for us012, us015 and us019, and confirmation of production's current values. `application-prod.yml` sets none, so the default is `false`; any environment override is invisible from the repo. Q-N8: boolean flags cannot do a percentage rollout | Ops | prod | requirements C3, Q-N8 |
| P-8 | Q-N5: the support contact value for the Access Denied page (`supportContact` in `environment.ts` is `null`, so no link shows) | PM | none (hidden link is the safe default) | design §22 |
| P-9 | Make the `e2e-full-stack` job a required check in branch protection. CODEOWNERS has a `*` default owner; decide whether `.github/workflows/` and `nexus-frontend/e2e/tools/` need explicit entries, since a PR can edit the workflow's floor and scan. Also verify the pinned action SHAs upstream (not possible in the review) | Ops, Md Nisar Ahmed | merge (a never-required check protects nothing) | S2-8, requirements Q9 |
| P-10 | `application-prod.yml` line `nexus.rbac.throttle.require-shared-store: true` (agent-write-protected; **not edited by this story**), then remove `@Disabled` from `ThrottleSharedStoreStartupAssertionTest`. Without it `RBAC_011` can be per instance | Ops | prod | US-018 closure record, deployment.md §3 |
| P-28 | Q-N10: legal basis and retention for displaying emails to directory holders | Legal, DPO | US-020 | design §22 |

## Verification not yet done

| ID | Item | Owner | Blocks | Reference |
|---|---|---|---|---|
| P-11 | The compose and CI path has never run end to end (Docker Hub rate limit during T-027; the local e2e run was 22 of 22 against the dev-profile backend only). Unproven: `nexus_app` grants for the seeder, the PII scan against the `test@example.com` traces on retry, SMTP host `mailhog` for the registration spec, the `test` profile is not covered by `RateLimitProfileDefaultsTest`, and `frontend-ci`'s separate `e2e` job runs without a backend. Run the workflow once on the PR | PR author | merge | T-027 notes, 08-test-audit |
| P-25 | No screenshot or real-browser axe review of the contrast retune (about 20 style files); `--nx-color-error` was darkened for both themes with the error surface unchanged | UX | none | R3-9 |
| P-27 | No e2e proves an unentitled user lands on `/access-denied`: no gated route exists yet. Unit and contract specs cover it. Add it with the first gated route; and the shell e2e nav map cannot catch a filtering bug until a gated item exists (unit spec `shell.spec.ts` covers it) | US-020 | US-020 | 08-test-audit gap 1, R3-3 |

## Opus re-check queue (after 2026-10-25 20:00 UTC)

| ID | Item | Owner | Blocks | Reference |
|---|---|---|---|---|
| P-12 | The review and fixes ran on Sonnet because the Opus weekly limit was reached. Re-check on Opus: **F1** the attach provenance fix (`2ca17e7`, RC-46 order); **F2** assign's set-lock classification (`fdb18ae`); **F3** `@Transactional` placement moved to `JpaUserDirectoryQueryAdapter` (`19b5352`); **F4** the lookup mapping without `consumes` plus `LookupAuthorizationFirst` (`99d2db2`); **T-025** `safeReturnUrl` percent-hazard rule and `parseSupportContact` | Md Nisar Ahmed (dispatch) | merge (recommended) | 07-security-review §3 |

## Follow-up work and decisions in the code

| ID | Item | Owner | Blocks | Reference |
|---|---|---|---|---|
| P-13 | Three feature files still import Material (registration form, verification landing, design-system preview) under an ESLint exemption. Migrate to `shared/ui` (`NxCheckbox` now exists) and delete the exemption | Frontend | none | R3-10 |
| P-14 | `axe-core` 4.14.0 (devDependency, `"license": "MPL-2.0"` in its package.json) is used by the e2e suite. Confirm that MPL-2.0 is acceptable for a test-only dependency | Legal | none (recommended before merge) | S2 |
| P-15 | RC-62.2: record the toolchain-only critical npm advisories (`@angular/build`, `tar`, `piscina`, `proxy-addr`) with the Frontend Tech Lead as owner and a review date. `npm audit --omit=dev` was clean at review | Frontend Tech Lead | none | threat model RC-62 |
| P-16 | `nexus-frontend/src/app/features/dashboard/README.md` is stale: it documents a component that navigates after logout with `Router`, but the dashboard is now an empty page and logout belongs to the shell | Frontend | none | T-010 |
| P-17 | `AppError.reason` is typed `string`; the design types it `RbacDenialReason` | Frontend | US-020 | S1-5, T-028 |
| P-18 | Decide: a by-id directory 404 writes no audit row (pinned by `UserDirectoryIT.should_notAudit_when_aByIdReadFindsNoUser`); the design says one row per request. Either keep it (the design amendment records this) or change code and that test together | Security/Privacy | none | S1-6, 08-test-audit gap 2 |
| P-19 | The shipped outcome label for a successful replace is `replaced` (design said `applied`); the design is amended. Alert rules use `replaced`. Reverse only with the `RoleManagementServiceTest` assertions | Md Nisar Ahmed | none | S1-5 |
| P-20 | Product decision: when the cold-start refresh fails with 503 `AUTH_005` or a network error, `authGuard` cancels navigation, so a user opening a deep link sees an empty page plus the toast. Choose a retry or "unavailable" view, or accept | UX, PM | none | R3-2 |
| P-21 | The logout and session-refresh e2e specs record no trace (they sign in as the administrator persona and a trace would fail the PII scan). Debugging those two specs needs a local run | Frontend | none | R3-6 |
| P-22 | `JpaRoleManagementAdapter.attachPermissions` runs one `SELECT` per id (merge on `RolePermission`), inside the role-row lock; a 100-permission replace costs about 100 extra selects. Make `RolePermission` `Persistable` or batch | Backend | none (no latency budget) | R1-3 |
| P-23 | O-1: no request rate or latency budget exists, so no load test was added. The directory and authorization endpoints are not hot paths. Design §16 proposes p95 under 200 ms for B1, B3 and B4 at dev volume | Md Nisar Ahmed | none | `04-tasks.md` G-1, O-1 |
| P-24 | ADR-0021 (Rev 3), ADR-0026 and ADR-0027 are still "Proposed"; move them to Accepted when the PR merges | Md Nisar Ahmed | none | `docs/adr` |
| P-26 | The design's `nexus.rbac.permission_replace.changes` distribution summary was not implemented; add it or drop it from the design | Backend | none | monitoring.md §1 |
| P-29 | `api-spec.json` is not committed; generate it from the running app at release time | Release owner | release | 09-technical.md |

## Not tracked here

Review findings that were fixed or accepted are in the Disposition tables of [06-code-review.md](06-code-review.md) and [07-security-review.md](07-security-review.md). US-018 pending items stay in [../US-018/14-pending-items.md](../US-018/14-pending-items.md).
