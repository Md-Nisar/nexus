# US-020 test audit (Phase 8)

Run on `feature/US-020` at `7890307` plus the review documents, Node 24, JDK 25, Docker up.

## Results

| Suite | Result |
|---|---|
| Frontend unit (`npm run test:ci`) | 115 files, 1851 tests, 0 failed, 0 skipped. Coverage 95.57% statements, 90.59% branches |
| Frontend lint / format / build | pass; initial bundle 424.68 kB (budget warning 500 kB); built `index.html` has no inline script |
| e2e tools self-test | 49/49 (gzip-off pin, security-header include pin, PII scanner incl. non-ASCII, CSP index check, D-3 smoke rules) |
| Backend (`./mvnw -B clean verify -Dspring.profiles.active=dev`) | 2655 unit tests (2 skipped, both skipped before this branch and not examined here), 699 integration tests, 0 failures, coverage checks met |
| Live e2e (Playwright, local) | 113 of 114 passed; the one failure (`session-refresh` TS-1, US-004) passed when run alone and is outside this story. `E2E_MIN_TESTS` equals `playwright test --list` (114) |

Local e2e used a host-built jar with compose MySQL/Redis/MailHog and the preinstalled Chromium build because
the matching browser cannot be downloaded in the sandbox. **CI's own e2e job has not run on this branch**
(open item P-11). A PII scan of the reports found no persona address.

## Coverage against the design

Every FR group has unit tests at the pure layer (staging engine, affordances, ETag classification, draft
storage, hidden-character splitting, retry-once, retry-after), store tests (profile, roles, catalogue, role
detail, user detail, directory cache), component tests with axe checks, and e2e specs per area (console
entry/layout, roles list, role detail, role editor, role create/clone, catalogue, users, user detail, assign,
revoke, cold start, return URL). Threat-model controls RC-68..RC-77 and D-1..D-6 each have named tests
(table in `07-security-review.md`).

## Test-quality checks

- Mutation checks by the delta reviewer (about 30 reverts) showed all but three fix tests fail without their
  fix; the three gaps were closed (`b0022a9`) and re-verified by revert.
- Red-then-green evidence was kept for every task; most red runs are compile-level because the Angular test
  builder fails the whole bundle on a missing import, so tasks used export-only skeletons where useful.
- No `it.skip`, `only` or focused specs; `assert-executed.mjs` fails CI on any skipped e2e test.
- Fixes found by running the full live suite (not by unit tests): the area bar is a `tablist`, not a
  navigation landmark; the countdown regex ignored padding; the create spec matched a pathname regex against a
  full URL; the create page's error-summary link failed axe contrast (4.02:1). All fixed in `7890307`.

## Known gaps

- FR-F8 timings (role detail interactive within 1 s; 500 roles under 200 ms) are not measured.
- `RBAC_002` (last administrator) is covered by unit tests only; the live case needs a single-admin tenant.
- Safari / VoiceOver table semantics at 320 px and the manual WCAG checklist are manual.
- The edge (nginx) is checked with the repository config on nginx 1.24 and by the CI `edge-etag-smoke` job;
  the production edge itself is not tested from here (H-4).
- The CSP is verified by header and by the absence of inline scripts in the build; a browser run through the
  nginx edge that fails on any CSP violation is a recommended follow-up.
