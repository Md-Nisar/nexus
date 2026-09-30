# ADR 0019 — Tenant Fairness: Per-Tenant Quotas and Noisy-Neighbour Protection

**Status:** Proposed
**Date:** 2026-09-28
**Feature:** Platform (no story yet — decide before the first multi-tenant GA)

---

## Context

Nexus is multi-tenant, but every current limit is per user or per IP and exists for abuse
prevention (login and password-reset throttling; `RateLimitRoleChangeThrottleAdapter` keyed
`{tenantId}:{actorUserId}`). Nothing bounds what one tenant as a whole can consume: request rate,
stored rows, or expensive operations. With a shared database and connection pool, one heavy tenant
can degrade latency and the availability SLO (`docs/observability-standards.md` → Service Level
Objectives) for every other tenant.

## Decision (to be made)

Open questions for product and architecture — none is decided yet:

1. **Which resources get a per-tenant limit?** Candidates: API request rate, concurrent expensive
   operations (exports, bulk writes), stored-entity counts (users, roles).
2. **Where limits live:** plan/tier configuration vs. per-tenant overrides; who can change them.
3. **Enforcement point:** a filter keyed on the token's `tenant_id` backed by the ADR 0016 Redis
   rate-limit store, versus per-use-case checks.
4. **Behaviour at the limit:** `429` with `Retry-After` (RFC 7807 body) for rate; `409`/`422` for
   hard quotas; fail-open or fail-closed when Redis is unavailable.
5. **Visibility:** per-tenant usage metrics — bounded cardinality, so tenant id is not a raw metric
   label (`observability-standards.md` → Cardinality discipline).

## Consequences

To be written when the decision is made. Until then, features that add an expensive or unbounded
per-tenant operation must name this ADR in their `03-design.md` and state how they bound it.
