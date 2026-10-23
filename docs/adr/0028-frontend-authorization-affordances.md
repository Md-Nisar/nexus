# ADR 0028 — Frontend Authorization Affordances: Live Profile for Actions, JWT for Navigation, Server Final

**Status:** Proposed 2026-10-23 with the US-020 design (Draft 2; threat model RC-71 and RC-76 folded in, 2026-10-23)
**Date:** 2026-10-23
**Author:** Principal Architect
**Feature:** EPIC-002, US-020 (RBAC Access Management console)
**Related:** `PROJECT.md` Key Constraints ("frontend gating is UX only"), US-019 `03-design.md` §12.2, §12.9, §12.10 (Amendment 8), RC-65 (one refresh path), RES-39 (`permissionGuard` fail-open), `docs/features/US-020/03-design.md` §2.2, §4.3 to §4.5, §6.3, §18, `03b-threat-model.md` (T-R19, T-E57, RES-55)

## Context

The access console is the first screen whose controls mutate authorization itself. Two client-side sources describe what the caller may do:
- the JWT in `AuthStore`, set at sign-in and refresh. Grants do not bump the permission epoch, so it can lag a grant by up to the token TTL (900 s);
- the live profile, `GET /api/v1/users/me/authorization`.

The console needs one rule for which source drives which UI, a guard for "any of these permissions" (nav and route entry for an area reachable through either of two permissions), and a defined behaviour when the cold-start refresh cannot reach an authoritative answer. RC-65 (US-019) forbids a second refresh path next to the interceptor's shared refresh.

## Decision

1. **The server is the authorization decision.** Every client rule below is a UX prediction. Every action handles a server refusal, and a 403 on an action the client predicted allowed re-reads the profile, keeps the user's work, and shows the reason.
2. **The live profile drives mutating affordances.** Every mutating control and disabled reason (create, edit, save, assign, revoke, clone) comes from a route-scoped `AuthorizationProfileStore`, loaded once per console entry and re-read after own-access events and after a predicted-allow 403. If the profile cannot be read, the console is read-only under a banner.
3. **The JWT (`AuthStore`) drives navigation and guards.** Nav items, the dashboard card and route guards read `AuthStore`, so routing needs no HTTP call. Nav may lag the profile by up to the token TTL after a grant; this is accepted.
4. **Any-of navigation and `anyPermissionGuard`.** `NavItem` carries `anyOf: readonly Permission[] | null`, tested with `some`. The new `anyPermissionGuard` reads `data.anyOf` and **fails closed**: a missing, empty or non-catalogue value denies. This deliberately differs from `permissionGuard`, whose fail-open on a missing value is pinned by RES-39; a new guard has no legacy callers. It composes only under an `authGuard` ancestor, enforced by a contract spec.
5. **The console never starts a session refresh of its own.** After a self-revoke it re-reads the profile; that request receives 401 on the stale epoch, and the interceptor's shared refresh runs once and replays it. `authGuard` still calls `AuthService.refresh()` exactly once per activation, on the shell's `canActivate` at cold start.
6. **`authGuard` navigates on unavailability.** When the cold-start refresh fails with `NETWORK_ERROR`, `HTTP_ERROR` (a non-problem response, so an intermediary answered) or `AUTH_005`, the guard returns a `UrlTree` to the public `/unavailable` view instead of leaving a blank shell. Every backend problem document still redirects to login. No branch grants access. This supersedes US-019 §12.10 for the guard and amends its Amendment 8.
7. **A lost refresh response followed by Retry is an accepted refresh-token reuse (RC-71).** If the backend committed a rotation but the response was lost (gateway 504, connection reset), the browser never stored the new cookie, and Retry presents the old one. The backend revokes the token family, records `TOKEN_REFRESH_REUSE`, and answers 401 `AUTH_004`; the guard sends the user to login, with no loop. This is fail-closed and is not changed. Two tabs cold-starting at once are the same pre-existing class. The `TOKEN_REFRESH_REUSE` runbook gains a triage step: check the window for gateway 5xx on the refresh endpoint and client `auth_guard_unavailable` reports before treating the event as theft.
8. **The console kill switch is a release control, not an authorization control (RC-76).** `AppConfig.accessConsoleEnabled` and its `canMatch` guard decide only whether the console UI ships. `canMatch` runs before the shell's `authGuard`, so any `canMatch` guard on a shell descendant must be config-only: a contract spec keeps an allow-list (initially `accessConsoleEnabledGuard`) and asserts that it injects neither `AuthStore`, `AuthService` nor `HttpClient`. The off switch for the APIs is the backend feature flags.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| JWT for everything | Lags grants by up to 900 s; a newly granted user would see disabled controls with no explanation |
| Live profile for everything, including guards | Every route entry would need an HTTP call before routing; a profile outage would lock users out of pages the JWT already admits |
| The console calls `AuthService.refresh()` after own-access changes (FR-G6/FR-C6 as first written) | A second refresh path next to the interceptor's reintroduces RC-65's double refresh and its reuse risk |
| `anyPermissionGuard` fail-open like `permissionGuard` | A configuration slip would admit; the new guard has no callers that depend on fail-open |
| Leave `authGuard` cancelling navigation on a network failure | A blank shell is the worst failure for the first gated route (Gate 1 Q4) |
| Retry the refresh automatically, or replay a lost rotation client-side | Automatic retries hammer nginx's auth zone, and a client cannot know whether the server rotated; the backend's reuse detection is the correct fail-closed answer |
| Runtime kill switch through a config endpoint | A new mechanism with its own failure modes for a switch expected to flip once |

## Consequences

- No backend change. Frontend gating stays UX only; the server's refusals are always handled and shown.
- Two client sources can disagree briefly; affordances follow the profile, nav follows the JWT. The lag is documented (US-020 SD-15).
- The public-route pin goes from three to four paths (`/unavailable`); formal acceptance sits with the Platform Security Owner (US-020 threat model H-1).
- During an outage, a user who presses Retry after a lost refresh response is signed out and a false `TOKEN_REFRESH_REUSE` signal is raised (RES-55, Low). The runbook triage step keeps it from being treated as theft.
- Turning the console off needs a frontend build and deploy; turning the APIs off needs the backend flags.
