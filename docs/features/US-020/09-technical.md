# US-020 technical documentation (Phase 9)

RBAC Access Management console: a frontend feature (Angular 22, standalone, signals) over the existing RBAC
and user-directory APIs. No production backend code or schema changed except the registration address check
(F-5); backend changes otherwise are dev seed data and contract-fixture tests.

## Routes and access

| Route | Gate |
|---|---|
| `/admin/access` (redirects to the first area the caller can read) | `canMatch` kill switch (config only), `authGuard`, `anyPermissionGuard` with `role:read` or `user:directory:read` |
| `roles`, `roles/new` (`role:write`), `roles/:roleId` (+ `permissions`, `edit` with `role:write`) | permission guards per route; the server is final |
| `permissions` | `role:read` |
| `users`, `users/:userId` (+ `roles`) | `user:directory:read` / `user:read` / `role:read`, degrading read-only |
| `/unavailable` | public layout; shown when the cold-start refresh cannot reach Nexus |

Navigation and guards read the JWT-backed `AuthStore`; mutating controls follow the live authorization
profile (`GET /users/me/authorization`). The console never calls `AuthService.refresh()` (ADR-0028).

## Key behaviours

- **Permission replace:** `PUT /roles/{id}/permissions` with the strong ETag sent verbatim as `If-Match`
  (weak or missing tags disable saving). 412 re-reads and rebases staged intent; 428 is a defect banner;
  `RBAC_012` is retried once, only for replace and assign; 403 re-reads the profile; 429 honours `Retry-After`.
- **Propagation text:** revoke takes effect on the person's next request (permission epoch), grant at token
  refresh; "within about 30 minutes" is a ceiling derived from the two 900 s constants.
- **Drafts:** ids-only in `sessionStorage`, keyed by user and role id, rejected when malformed, stale (12 h)
  or from the future; swept on logout and user change; entries the user can no longer make are dropped on
  restore and rebase.
- **Assign / revoke:** the picker lists only roles the caller may grant, with a visible reason per disabled
  role. Unverified targets (PENDING, unknown or unverified email) get a warning and a typed confirm, and
  administrator-looking roles are blocked until backend F-4 (switch `PENDING_ADMIN_ROLE_BLOCK`). Revoking your
  own role uses the typed self-revoke variant chosen by user id, never by email.
- **User text:** names, descriptions and emails render only through interpolation inside `<bdi>`; hidden and
  direction characters in emails show as visible `U+XXXX` tokens with a badge (RC-68, D-1). User text never
  reaches titles, toasts, logs or URLs.
- **Logging:** structured, ids and codes only; the global error handler logs fixed messages.

## Configuration and operations

- `accessConsoleEnabled` (`src/environments/*`): `false` in production builds, `true` in development. It is a
  release control, not an access control; turning it off removes the nav item and the route (Not Found).
- Backend flags `us012`, `us015`, `us019` default to false; the console needs the APIs they enable.
- Edge: `nexus-frontend/nginx.conf` keeps `gzip off` for `/api/` (ADR-0029, so ETags stay strong) and includes
  `nginx/nexus-security-headers.conf` in every location that sets headers (CSP `frame-ancestors 'none'`,
  X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy). The CSP is `script-src 'self'`, so the
  production build must contain no inline script (`optimization.styles.inlineCritical: false`; CI runs
  `e2e/tools/check-index-csp.mjs`). The `edge-etag-smoke` CI job checks the headers and ETag on the compose stack.
- Dev personas (dev profile only, absent under `dev,prod`): a role-reader user manager, an auditor, two
  assignment targets and a hidden-character target, all non-administrators; assignments are made by the seeded
  administrator. Persona addresses never appear in specs, comments or reports (`scan-pii`).
- Registration (`RegisterRequest.email`) rejects control, format, private-use, unassigned and surrogate
  characters, space separators and known invisible fillers.

## Decisions and follow-ups

ADR-0028 (frontend authorization affordances) and ADR-0029 (edge must preserve strong ETags) are Proposed.
Open items, backend follow-ups F-1..F-4 and the human approvals are tracked in `14-pending-items.md`.
