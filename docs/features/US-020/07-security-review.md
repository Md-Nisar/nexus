# US-020 security review (Phase 7)

**Verdict: no open Blocker.** Scope: `git diff adda702...feature/US-020` (frontend console, test/seed-only
backend, CI workflows, nginx). Threat model: `03b-threat-model.md` (RC-68..RC-77, D-1..D-6, RES-x).
Two fresh-context reviews: the full audit, then a delta audit of the fix pass `77d03f6`.

## Full audit: 0 Blocker, 1 High, 2 Medium, 6 Low

| Finding | Severity | Status |
|---|---|---|
| App shell and static assets served without CSP, X-Frame-Options, nosniff, Referrer-Policy (nginx drops server-level headers in any location that sets its own); clickjacking of Assign/Remove | High (pre-existing, made exploitable by this console) | Fixed: one shared snippet `nexus-frontend/nginx/nexus-security-headers.conf` included at server level and in every location that sets a header; pinned by `tools.selftest.mjs`, checked by the edge smoke. **Ops must confirm the production edge (H-4).** |
| `assign.spec.ts` asserted that registering a U+202E address returns 201, pinning defect F-5 | Medium | Fixed: the target is seeded by the dev seeder (`hiddenCharacterTarget`, PENDING, `.invalid`, no role) |
| F-5 impact on the console | Medium | Contained in the console (email display mode with visible tokens and badge, no `innerHTML`, `DomSanitizer` banned in features, emails out of titles/toasts/logs/URLs). Registration now rejects the characters (below). Confusable / mixed-script look-alikes remain (RES-54) |
| PENDING warning and H-2 block keyed on `status === 'PENDING'` only | Low | Fixed: `targetNeedsVerification` (unknown, PENDING or `emailVerified` false) |
| Catalogue loader had no page cap | Low | Fixed (5 pages, then `CATALOGUE_TOO_LARGE`) |
| Edge smoke let a generic `CI` variable skip the D-3 rules | Low | Fixed: `NEXUS_SMOKE_CI=1` plus a loopback/compose base; negative control local only |
| Error handler put messages into log text | Low | Fixed: fixed messages; escaped HTTP errors log status and path only |
| Log redaction matches key names only | Low | Accepted (anchoring would stop redacting `userEmail`) |
| Profile response not checked against the signed-in user | Low | Fixed: `PROFILE_OWNER_MISMATCH` fails closed |

All of RC-68..RC-77, D-1..D-6, H-2 and D-5 are implemented with named tests. Verified clean: config-only
`canMatch` kill switch, no console call to `AuthService.refresh` (ADR-0028), strong-ETag handling (never
accepts or strips `W/`), `safeReturnUrl` (D-2), drafts and their sweep (D-6), self-revoke and last-admin
protection, dev seeders absent under `dev,prod`, workflow changes (read-only token, pinned actions, no
secrets), no dependency delta (`dependency:tree` identical, `npm audit --omit=dev` clean).

## Delta audit of `77d03f6`: all closures hold; one new High found and fixed

| Finding | Severity | Status |
|---|---|---|
| NEW-H1: the new CSP (`script-src 'self'`) blocked Angular's inline critical-CSS script, so the app loaded without its global stylesheet | High | Fixed `8c7788d`: `inlineCritical: false` for production; `e2e/tools/check-index-csp.mjs` fails CI on an inline script, handler or print-media swap in the built `index.html`. `unsafe-inline` for scripts was deliberately not added |
| F-5 probe removed rather than turned into an expected-failure test | Low | Replaced by a backend unit test that pins the rejection (`RegisterRequestValidationTest`) |
| `scan-pii` missed HTML-entity, double-percent and character-stripped forms | Low | Open (synthetic `.invalid` target only) |

## After the delta audit

- `RegisterRequest.email` now rejects control, format, private-use, unassigned and surrogate characters,
  space separators and known invisible fillers (F-5). An automated review noted a denylist can miss
  characters; it was widened (`3faa7c0`). It is still a denylist: an allowlist or NFKC plus
  confusable/mixed-script check is the identity owner's decision (see `14-pending-items.md`).
- Commits `3afbc02`, `3faa7c0`, `7890307` came after the delta audit and were not separately audited.

## Needs a human

Production edge headers and topology (H-4), Platform Security Owner acceptance (H-1), F-4 (takeover at
verification of PENDING accounts), the identity owner on confusables, and a green full-stack e2e run on CI.
This document records review only; it is not an approval.
