# ADR 0029 — The Edge Must Preserve Strong ETags and `If-Match` on `/api/`

**Status:** Proposed 2026-10-23 with the US-020 design (Draft 2; threat model RC-72 folded in, 2026-10-23)
**Date:** 2026-10-23
**Author:** Principal Architect
**Feature:** EPIC-002, US-020 (RBAC Access Management console)
**Related:** ADR-0027 (optimistic concurrency for the role permission-set replace; accepted, so not edited), `docs/features/US-020/02-impact.md` risk 1, `03-design.md` §7.2, §15.4, §17, §19.6, §20.2 item 3, `03b-threat-model.md` (T-R20)

## Context

ADR-0027 makes `PUT /api/v1/roles/{roleId}/permissions` conditional on exactly one **strong** entity-tag in `If-Match`; a weak, missing or unparseable value gives 428. The tag is served on `GET /roles/{roleId}/permissions`.

nginx, which fronts the frontend and proxies `/api/`, has server-level gzip on. When nginx compresses a response it downgrades a strong `ETag` to a weak one (documented behaviour since 1.7.3; an inference for this deployment, US-020 AS-1). A browser would then echo `W/…`, and every save from the console would fail with 428. A CDN, load balancer or other proxy could do the same, or strip `If-Match`. ADR-0027 is accepted and cannot be edited, so this deployment constraint is recorded here.

## Decision

1. **Nothing between the browser and the backend may compress or otherwise transform `/api/` responses in a way that weakens or strips `ETag`, or strip `If-Match` from requests.**
2. **nginx:** `gzip off;` inside `location /api/` in `nexus-frontend/nginx.conf`. The auth location keeps server-level gzip (no ETags there); static assets keep gzip. If compression of API responses is wanted later, it must be applied by a component that preserves strong ETags, and this ADR is revised.
3. **Verification:**
   - a static config test in `frontend-ci` asserting the `location /api/` block contains `gzip off;`;
   - the `edge-etag-smoke` job, which runs real nginx with the real backend: it reads a large-enough permission set with `Accept-Encoding: gzip`, asserts the tag is present and strong, and sends a `PUT` with that tag expecting 409 `RBAC_003`, which proves the tag survived the edge without mutating anything.
4. **Negative control is CI-only (RC-72).** The weak-tag control (`If-Match: W/…`, expecting 428) runs only with `--negative-control`, which CI passes. Runs against staging or production omit it, so the release check never trips the `precondition_required` alert. The alert's note records that CI produces exactly one 428 per run and is not a scraped environment.
5. **Smoke identity outside CI (RC-72).** Against staging or production the script runs as a dedicated non-administrator identity holding only `role:read` and `role:write`, never an administrator credential. Credentials come from environment variables only (never argv), are never printed, and the script logs out at the end.
6. **Ops obligation.** Before the console is enabled in an environment, Ops confirms that no CDN, load balancer or proxy in front of `/api/` compresses, rewrites or strips these headers, and the smoke is green against that environment's real edge (US-020 release checklist item 3).

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Accept weak tags on the PUT | Contradicts ADR-0027 decision 2; a weak validator is not safe for a lost-update guard |
| Keep gzip and have the client strip `W/` before echoing | Turns a weak tag into a forged strong one; defeats the server's check and hides an edge defect |
| Rely on CI lacking nginx | Proves nothing about real edges; the smoke deliberately runs nginx and takes the base URL as a parameter |

## Consequences

- API responses through nginx are no longer compressed. A 100-role page is tens of kB, acceptable for an admin-only, low-traffic console.
- One new CI job (`edge-etag-smoke`) and one static test; one new alert on an existing backend counter.
- Ops must provision a non-administrator smoke identity per environment (US-020 threat model H-4), and confirm the production edge topology before enablement.
- Any future edge component in front of `/api/` must be checked against this ADR before it is introduced.
