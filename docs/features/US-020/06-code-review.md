# US-020 code review (Phase 6)

**Verdict: APPROVE WITH NITS**

Scope: `git diff adda702...feature/US-020`. Two fresh-context reviews: the full review of the 18-task
implementation, then a delta review of the single fix pass (`77d03f6`). Findings below are the reviewers'
words condensed; raw reports are not kept in the repository.

## Full review (after T-018): CHANGES REQUESTED, 0 blockers, 5 major, 11 minor, 6 nits

| ID | Finding | Status |
|---|---|---|
| MJ-1 | Draft offer pending: new staging was neither kept nor safe, and Restore replaced it silently | Fixed `77d03f6`: every row is held with a reason while the offer shows; Restore clears the offer first |
| MJ-2 | Logout with staged changes showed a leave prompt claiming a draft that logout had deleted | Fixed: the guard leaves without a prompt once signed out |
| MJ-3 | Assigning to a PENDING user blocked every role on a cold page (catalogue never loaded) | Fixed: the tab reads the catalogue once; an unknown total has its own reason and Retry |
| MJ-4 | Leaving the create page with the POST in flight orphaned a role | Fixed: leave is refused while creating, the roles list is invalidated in `finalize`; bounded to 15 s afterwards so a request that never answers cannot trap the user |
| MJ-5 | A profile reload unmounted the editor and emptied the assign picker | Fixed: stale-while-revalidate profile store (`reloading()`, `settled()`); mutations off while reloading |
| MN-1 | Roles list not invalidated after assign/revoke | Fixed (invalidate + one re-read, join retained meanwhile) |
| MN-2 | `NxButton` `loading` emitted `clicked` on keyboard activation | Fixed |
| MN-3 | `NxInput` never displayed its `error` (pre-existing; affects the auth forms) | Fixed after the delta review: inner `matInput` has its own control and an error matcher driven by `error` |
| MN-4 | `UnavailableState` never cleared after a successful refresh | Fixed |
| MN-5 | 320 px card layout uses `::ng-deep` into Material, copied three times | Open (refactor; see `14-pending-items.md`) |
| MN-6 | `DirectoryCache` had no size cap | Fixed (500 entries, reset on user change) |
| MN-7 | Logger redaction is key-substring based; error handler logged messages | Error-handler part fixed; anchoring the regex skipped (it would stop redacting `userEmail`) |
| MN-8 | FR-F8 timing unmeasured | Open (needs a measured run) |
| MN-9, MN-10 | Duplicated 403 sets / `toAppError`; oversized files | Open (refactor) |
| MN-11 | Retry countdown drifted in background tabs | Fixed (deadline based) |
| Nits | rowgroup scope, an assertion-free spec, others | rowgroup and the assertion fixed; the rest left |

Carry-forward risks raised by the story owner were each confirmed real, with low impact today; the
`dialog.scss` Cancel colour change is intentional (axe contrast) and is called out in the PR.

## Delta review of `77d03f6`: APPROVE WITH NITS, 0 blocker, 0 major, 4 minor, 7 nit

About 30 mutation checks reverted each production change and re-ran its specs. Every claimed fix closes its
scenario and no regression was found. Three tests survived a revert:

| ID | Gap | Status |
|---|---|---|
| m1 | Revoke own-access `settled` wait untested (stub ignored reloading) | Fixed `b0022a9`; the mutation now fails the spec |
| m2 | "Keeps the Type badges" assertion proved nothing | Fixed `b0022a9`; fails when the join retention is removed |
| m3 | Create-page leave refusal had no way out if a request hangs | Fixed `3afbc02` (15 s bound, with a spec that fails without it) |
| m4 | Design doc drift | Fixed `b0022a9` (post-review amendments block in `03-design.md`) |
| N-1..N-7 | Stale comment, dialog-open retry spec, extra invalidate on 4xx, login skips `UnavailableState.clear`, cascade failures, "profile unavailable" wording during reload, up to 5 roles requests on large tenants | Left as nits |

## Changes after the delta review (not covered by a further delta review)

`3afbc02` (bounded leave refusal, `NxInput` error state, registration check), `3faa7c0` (registration check
widened after an automated security note), `7890307` (e2e locator and URL fixes, error-summary link
contrast), `8c7788d` (CSP / critical-CSS). Each has red-then-green unit evidence and the full local gates
(`08-test-audit.md`), but none had a separate reviewer; treat them as the first thing to look at in the PR
review.

## Praise

Pure staging engine, 412 rebase, retry-once on `RBAC_012`, stores keyed by user, untrusted-storage parsing
of drafts, return-URL handling per D-2, dev seeders kept out of `prod`.
