# US-019 decisions taken under delegation

**Date:** 2026-10-22. **Delegated by:** Md Nisar Ahmed (story owner): "I leave it on your intelligence" and "whatever decisions you needed from human, document them and close". **Taken by:** Claude. These are recommended defaults, not sign-offs by Ops, UX, PM or Legal. Anyone listed as owner can overturn one; the effect is stated for each. Execution steps that only a person with access can do (alerts, branch protection, production config) are collected in the release checklist at the end.

| ID | Decision | Why | If overturned |
|---|---|---|---|
| P-1 | Adopt the proposed thresholds in monitoring.md section 3 (directory rows 1,000 and 10,000 per hour, lookups 200 per hour, B8 contention 20%) as the initial alert values | No traffic data exists; the values are deliberately loose and cheap to tune | Edit the alert rules only |
| P-2 | Retain `RBAC_PII_PERMISSION_DELEGATED`, `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and the admin-defining detector WARN for at least 1 year | Matches the audit-trail retention the design assumed (RES-6) | Change the log-store retention only |
| P-3, P-4 | D2 designs and D3 content are the first deliverables of US-020 and block US-020, not this PR. US-019 ships no console page | Nothing in US-019 renders a console page | None for this PR |
| P-5 | Propagation wording for D4: "A permission change takes effect within about 30 minutes, or sooner when the person signs in again." Basis: `permission-cache-ttl-seconds` 900 plus `access-token-ttl-seconds` 900 | Worst case is the sum of the two TTLs | Re-word when US-018's epoch is surfaced in the UI |
| P-7 | Keep `feature.nexus-us019-user-directory.enabled` (and us012, us015) default `false`. Enable per environment: staging first, production after the e2e job has passed once and P-10 is done. No percentage rollout (boolean flags cannot do one) | The default is the safe state | Flip the flag per environment |
| P-8 | Ship with no support contact link (`supportContact` stays `null`) | A hidden link is the safe default; a wrong contact is worse | Set the value in `environment.ts` |
| P-9 | CODEOWNERS already assigns `/.github/` and `/nexus-frontend/` (which holds `e2e/tools/`) to the owner, so no entry is added. Making `e2e-full-stack` a required check is a release-checklist item; verifying the pinned action SHAs upstream is too | A never-required check protects nothing, but branch protection is outside the repo | Branch-protection setting only |
| P-10 | Production must set `nexus.rbac.throttle.require-shared-store: true` before the flag is enabled there, then `@Disabled` comes off `ThrottleSharedStoreStartupAssertionTest`. The line is agent-write-protected and was not edited | Without it `RBAC_011` is per instance | None |
| P-14 | Accept `axe-core` (MPL-2.0) as a test-only devDependency | File-level weak copyleft, not shipped in the production bundle, no modification | Swap for another a11y checker |
| P-15 | Record the toolchain-only advisories (`@angular/build`, `tar`, `piscina`, `proxy-addr`) with the Frontend Tech Lead as owner and a re-review by 2027-01-20. `npm audit --omit=dev` was clean | RC-62.2 asks for an owner and date | Change owner or date |
| P-18 | Keep it: a by-id 404 writes no directory audit row (pinned by `UserDirectoryIT`). The design amendment records this | No user data was read, and a row per probe would let a caller flood the audit table | Change code and that test together |
| P-19 | Keep the `replaced` outcome label; alert rules use it | Already shipped and asserted in `RoleManagementServiceTest` | Change label and assertions together |
| P-20, P-32 | Accept the cold-start 503 behaviour for this PR: navigation is cancelled and the toast shows. US-020 designs an "unavailable, retry" view under D2 | A retry view is a design decision with no mock-up | None for this PR |
| P-23 | Adopt design section 16's p95 under 200 ms for B1, B3 and B4 at dev volume as a target. No load test, no enforced budget | The endpoints are not hot paths; there is no traffic estimate | Add a load test when a budget exists |
| P-24 | ADR-0021, ADR-0026 and ADR-0027 are marked Accepted with this PR | Their decisions are implemented and reviewed | Revert the status line |
| P-25 | Accept the contrast retune on the strength of the axe e2e specs (22 of 22 green). No screenshot review | axe checks AA contrast per rendered page | Review screenshots after merge |
| P-27 | Add the unentitled-user `/access-denied` e2e with the first gated route in US-020 | No gated route exists | None |
| P-28 | Q-N10: email is shown only to holders of `user:directory:read`, which only administrators may grant (D5), inside their own tenant, and each read is audited. Retention follows the audit log. DPO acknowledgement of the legal basis is a release-checklist item | The access path is already minimised | Narrow the grant rule or hide the email |
| P-29 | Generate `api-spec.json` from the running app at release time | It is a build artefact | None |

## Release checklist (people with access)

1. Create the alerts with the P-1 values and set the P-2 retention.
2. Set `nexus.rbac.throttle.require-shared-store: true` in `application-prod.yml`, remove `@Disabled` (P-10).
3. Make `e2e-full-stack` a required check; verify the pinned action SHAs (P-9).
4. Confirm each environment's flag values (P-7).
5. DPO acknowledges P-28.
6. Generate `api-spec.json` (P-29).

Still open by nature, not by decision: P-11 (first CI run of the e2e workflow) and P-12 (Opus re-check after 2026-10-25 20:00 UTC).
