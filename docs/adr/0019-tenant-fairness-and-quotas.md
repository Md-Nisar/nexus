# ADR 0019 — Tenant Fairness: Per-Tenant Quotas and Noisy-Neighbour Protection

**Status:** Accepted
**Date:** 2026-09-28 (proposed) · **Decided:** 2026-10-02
**Feature:** EPIC-003 (Tenant Management) — US-034 (seat limits), US-035 (per-tenant rate limits)
**Decided by:** the product owner delegated this decision; recorded here with the research behind it.
**Related:** `docs/adr/0016-redis-infrastructure-dependency.md` (D3 keyspace, D4 failure modes),
`docs/observability-standards.md` (Cardinality discipline, Service Level Objectives),
`docs/story/3-tenant-management/EPIC-003.md` (decision D10: plan tiers)

---

## Context

Nexus is multi-tenant, but every current limit is per user or per IP and exists for abuse
prevention (login and password-reset throttling; `RateLimitRoleChangeThrottleAdapter` keyed
`{tenantId}:{actorUserId}`). Nothing bounds what one tenant as a whole can consume: request rate,
stored rows, or expensive operations. With a shared database and connection pool, one heavy tenant
can degrade latency and the availability SLO (`docs/observability-standards.md` → Service Level
Objectives) for every other tenant.

EPIC-003 decision D10 has since fixed three plan tiers — **Free**, **Teams**, **Enterprise** —
with member limits of 5, 50 and 500 (Enterprise overridable per contract). This ADR answers the
five questions the proposal left open.

### What industry practice says (research, 2026-10-02)

- **Tier-based throttling is the baseline pattern.** The AWS Well-Architected SaaS Lens (PERF 1)
  and the AWS SaaS Factory guidance attach rate, burst and quota values to each tier, and give
  every tenant its own allocation from its tier's plan.
- **Reject early and cheaply.** Google's SRE book (ch. 21, "Handling Overload") sets per-customer
  quotas and has the backend reject over-quota requests quickly, because rejecting costs far less
  than serving. Quotas may add up to more than total capacity, because tenants rarely peak at
  the same time.
- **Signal to clients.** `429 Too Many Requests` with `Retry-After` is the established contract
  (RFC 6585, RFC 9110). GitHub returns 429 with `retry-after` and also caps concurrent requests
  (100). The IETF `RateLimit-Policy` / `RateLimit` header fields are still an Internet-Draft
  (draft-ietf-httpapi-ratelimit-headers-11, May 2026), not an RFC.
- **Separate rate limits from hard quotas.** Vendors keep "requests per window", which resets on
  its own, apart from "things you can own" (seats, stores, entities), which are enforced when the
  thing is created. Examples: Shopify Plus's store limit, Auth0's entity limits, Salesforce
  governor limits _(the latter three come from the EPIC-003 Appendix A research)_.

---

## Decision

### D1 — Three kinds of limit; no others for now

| Kind | Limited resource | Story |
|---|---|---|
| **Rate** | Authenticated API requests per tenant per minute | US-035 |
| **Concurrency** | Expensive operations running at once per tenant: tenant data export (US-038) and any future bulk operation | US-038 (and each future bulk feature) |
| **Hard quota** | Active members plus pending invitations (the D10 seat limit). Roles keep the existing global safety cap `nexus.rbac.max-roles-per-tenant` (500); it is **not** a plan limit | US-034 |

Stored-data size is **not** limited yet: Nexus stores no tenant files or large records today. A
feature that adds unbounded per-tenant storage must amend this ADR (follow-on rule 1).

### D2 — Limits live in tier configuration; operators override per tenant

- Tier defaults live in configuration under `nexus.tenancy.plans.{free|teams|enterprise}.*`, so
  changing a default needs a config change, not a code change (EPIC-003 D10).
- A tenant may have per-tenant overrides, stored as nullable columns on `tenants`. An override
  replaces the tier default for that tenant only.
- Only a Platform Operator holding `platform_tenant:write` can change a tenant's tier or
  overrides (EPIC-003 US-023). Every change writes a `TENANT_LIMIT_CHANGED` audit event with old
  and new values.
- Tenant admins can see their limits and usage but never change them.

Initial values. These are **starting points, to be re-checked by a load test before GA**. The
seat limits come from D10. The rate limits are sized at about 60, 24 and 12 requests per minute
per seat, so normal use never hits them and only runaway clients or scripts do:

| Tier | Seats (members + pending invites) | API requests / tenant / minute | Concurrent exports |
|---|---|---|---|
| Free | 5 | 300 | 1 |
| Teams | 50 | 1,200 | 1 |
| Enterprise | 500 (override per contract) | 6,000 (override per contract) | 1 |

The operator tenant uses Enterprise rate limits and has no seat limit.

### D3 — Enforcement point: a tenant filter for rate, the use case for everything else

- **Rate:** a `TenantRateLimitFilter` runs **after** JWT authentication, keyed on the token's
  `tenant_id`. It reuses the ADR 0016 `RateLimitStore` port and sliding-window-log Lua script.
  - Key: `nexus:tenant:ratelimit:{tenant_id}`, per ADR 0016 D3.
  - The existing per-user and per-IP limits stay and run first.
  - Unauthenticated endpoints (login, registration, reset) are not tenant-limited: they have no
    trusted tenant yet and are already IP- and user-limited.
  - `/actuator/**` is excluded.
- **Store in production:** the in-memory store counts per JVM, so with N instances a tenant would
  get N times its limit. The production profile must set
  `nexus.security.rate-limit.store-type: redis`. The in-memory store stays for dev and test only.
- **Concurrency and hard quotas:** checked inside the use case's transaction against MySQL, the
  system of record. Not in Redis, and not in a filter.
  - **Seats:** count active members plus pending invitations in the tenant, holding a lock on the
    tenant row so two concurrent invitations cannot both take the last seat.
  - **Concurrency:** count the tenant's `RUNNING` job rows before starting a new job.

### D4 — Behaviour at the limit

| Kind | HTTP | Body (RFC 7807, `GlobalExceptionHandler`) | Headers | When the store is unavailable |
|---|---|---|---|---|
| Rate | `429` | new `TENANT_0xx` code, "rate limited" | `Retry-After` (seconds) | **Fail open**, as ADR 0016 D4 already decides for rate limiting, with an alert. Per-user and per-IP limits keep working against their own buckets |
| Concurrency | `409` | new `TENANT_0xx` code, "too many running" | — | Not applicable: MySQL-backed, so it fails closed with the database |
| Hard quota (seats) | `409` | new `TENANT_0xx` code, "seat limit reached" | — | Not applicable: MySQL-backed |

- The body never reveals another tenant's usage.
- The IETF `RateLimit` / `RateLimit-Policy` headers are **not** sent yet. Adopt them when the
  draft becomes an RFC (follow-on rule 3).
- Error codes follow the existing `GlobalExceptionHandler` scheme (`AUTH_001`, `RBAC_001`, …), in
  a new `TENANT_` family. US-034 and US-035 design assign the numbers.

### D5 — Visibility without a tenant-id metric label

- Metrics carry the **tier**, not the tenant id, so cardinality stays bounded at 3, per
  `observability-standards.md` → Cardinality discipline:
  - `nexus_tenant_ratelimit_rejections_total{tier}`;
  - `nexus_tenant_quota_rejections_total{tier,kind}`, where `kind` is `seat` or `concurrency`.
- **Which tenant** is in the structured log event `TENANT_RATE_LIMITED` / `TENANT_QUOTA_REJECTED`,
  with `tenant_id` in MDC. On-call finds the noisy tenant with a log query, not a metric.
- Alert when one tier's rejection rate is sustained. The threshold is set in US-035 design.
- Tenant admins see "seats used / allowed" on the members page (US-034 AC3). Operators see each
  tenant's usage in the operator console (US-037).

---

## Consequences

**Positive**
- One tenant can no longer use up the shared API capacity. Over-limit requests are rejected
  before any database work.
- Seat limits are enforced at the database, so they cannot be raced past and hold with any number
  of instances.
- Limits are data. Sales can change a tenant's limits through an operator without a release.

**Negative / accepted**
- During a Redis outage, tenant rate limits are not enforced (fail open). This is the same
  trade-off ADR 0016 D4 accepted for all rate limiting, and it must page.
- The request rate limit does not measure cost: a cheap and an expensive request count the same.
  Concurrency caps on expensive operations cover the worst cases. Cost-weighted limits are
  deferred until metrics show a need.
- Tenant-level rate limits need Redis in production, which becomes a deployment requirement for
  multi-instance setups.

## Alternatives considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D1 | Limit stored rows per table per tenant | No unbounded per-tenant storage exists yet; seat and role caps already bound the only tables that grow per tenant |
| D2 | Limits only per tier, no per-tenant override | Enterprise contracts negotiate their own numbers (Microsoft, GitHub and Atlassian all sell per-seat contracts) |
| D3 | Enforce rate limits at an API gateway | Nexus has no gateway; the filter reuses an existing, tested store and keeps the tenant read from the verified JWT |
| D3 | Hard quotas in Redis counters | Redis is not a system of record (ADR 0016 D5); a lost counter would let a tenant exceed its paid seats |
| D4 | Fail closed on rate limiting | Would block every tenant on a Redis blip; contradicts ADR 0016 D4 |
| D4 | Send the IETF `RateLimit` headers now | Still a draft whose field syntax has changed between versions; `Retry-After` is enough for well-behaved clients |
| D5 | `tenant_id` as a metric label | Unbounded cardinality, forbidden by `observability-standards.md` |

## Follow-on rules

1. A feature that adds unbounded per-tenant storage or a new expensive operation must say in its
   `03-design.md` which D1 kind bounds it, and amend D1/D2 if it needs a new limit.
2. The D2 numbers are re-checked by a load test before GA. Changing them only needs a config
   change and an entry in this ADR's history, not a new ADR.
3. Re-evaluate sending `RateLimit` / `RateLimit-Policy` headers when
   draft-ietf-httpapi-ratelimit-headers becomes an RFC.

## Sources

- AWS Well-Architected SaaS Lens, PERF 1: https://wa.aws.amazon.com/saas.question.PERF_1.en.html
- AWS APN blog, tiering and throttling with API Gateway usage plans:
  https://aws.amazon.com/blogs/apn/enabling-tiering-and-throttling-in-a-multi-tenant-amazon-eks-saas-solution-using-amazon-api-gateway/
- Google SRE book, ch. 21 "Handling Overload": https://sre.google/sre-book/handling-overload/
- IETF draft-ietf-httpapi-ratelimit-headers-11: https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html
- GitHub REST API rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
