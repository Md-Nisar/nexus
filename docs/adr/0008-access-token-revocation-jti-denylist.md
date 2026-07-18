# ADR 0008 — Access-Token Revocation Strategy: TTL-Only for GA, jti Denylist as Fast-Follow

**Status:** Accepted; Option B superseded by **ADR 0016** (Redis adopted as an infrastructure
dependency — see that ADR's D4 for the jti-denylist implementation).
**Date:** 2026-06-29
**Author:** Engineering Team

## Context

US-005 introduces user-initiated logout. Logout revokes all server-side **refresh** tokens for the
user (DB-backed `refresh_tokens`), so a captured refresh cookie cannot be replayed. However, the
**access token** is a stateless RS256 JWT (ADR-0007): it carries no server-side state and is accepted
by `JwtPort` verification until it expires. After logout, an already-issued access token therefore
remains technically valid for its residual TTL.

The access-token TTL is **900 s (15 min)** (`AuthConstants.AUTH_ACCESS_TOKEN_TTL` / US-003). The
question for US-005: do we need to invalidate access tokens **immediately** on logout, or is the
residual-TTL window acceptable for GA?

Three options:

**Option A — TTL-only (status quo).** Logout revokes refresh tokens; the access token expires
naturally within ≤15 min. No new infrastructure.

**Option B — `jti` denylist in a fast store (Redis).** Each access token carries a unique `jti`
claim. Logout writes the `jti` to a denylist with a TTL equal to the remaining access-token
lifetime. `JwtPort` verification consults the denylist on every request. Provides near-instant
revocation.

**Option C — `jti` denylist in MySQL.** Same as B but using the existing MySQL instance instead of
Redis, avoiding a new datastore at the cost of a per-request DB read on the auth hot path.

## Decision

**Adopt Option A (TTL-only) for GA. Defer Option B (Redis `jti` denylist) as a planned
fast-follow, not in this sprint.**

Rationale:

1. **The exposure window is bounded and short.** The worst case is a ≤15-min window during which a
   *previously legitimate, already-issued* access token still verifies after the user clicked
   logout. This is not new attack surface introduced by US-005 — it is the inherent property of
   stateless JWTs accepted in ADR-0007 ("revocation is handled by short TTL + refresh-token
   rotation").

2. **Refresh revocation closes the durable risk.** The dangerous, long-lived credential is the
   14-day refresh token. Logout revokes the entire refresh family for the user immediately and
   atomically (`LogoutUseCase`), so the session cannot be silently extended past the access-token
   window. After ≤15 min the user is fully locked out.

3. **No Redis in scope (consistent with ADR-0007).** ADR-0007 explicitly commits to "no Redis /
   external token store" for the current architecture. Adding Redis for a 15-min residual window is
   not justified by the current threat model and would introduce a new operational dependency,
   failure mode, and deployment surface. Option C (MySQL denylist) avoids new infra but adds a DB
   read to **every authenticated request** — an unacceptable hot-path cost for the same bounded
   benefit.

4. **The fast-follow path is already designed.** When revocation SLA tightens (see triggers below),
   Option B is the chosen implementation: `JwtPort` gains a denylist check keyed on `jti` with a
   TTL equal to the token's remaining lifetime, populated by `LogoutUseCase`. The access token
   already carries a `jti` claim, so no claims-contract change is required.

## Triggers for re-evaluation (adopting Option B)

- A compliance or security audit mandates a revocation SLA shorter than the access-token TTL.
- The access-token TTL is increased beyond 15 min for any reason.
- A "log out everywhere / kill session now" admin capability is introduced.
- Redis is adopted for another reason (lowering the marginal cost of the denylist). **— Triggered:
  Redis was adopted per ADR 0016 for the RBAC permission cache and rate-limiting store; Option B
  (`jti` denylist keyed by `nexus:identity:jwt:denylist:{jti}`, TTL = remaining access-token
  lifetime, fail-open on Redis outage) is now implemented as part of that ADR's rollout.**

## Consequences

- For GA, logout's user-visible contract is: refresh family revoked immediately; access token
  expires within ≤15 min. This is documented in the US-005 design and threat model (T-5.1 in
  `docs/features/US-005/03b-threat-model.md`).
- No code, schema, or dependency changes are made by this ADR — it records the deliberate decision
  and the fast-follow plan so the residual window is an *accepted, tracked* risk rather than an
  oversight.
- The frontend mitigates the *client-visible* window fully: `AuthStore.clearSession()` discards the
  in-memory access token on logout, so the SPA stops sending it immediately. The residual window
  only matters to an attacker who already exfiltrated the raw access token before logout.
