# ADR 0023 — Object-Level (Ownership) Authorization Is Out of Scope for GA; the Risk Is Accepted

**Status:** Proposed
**Date:** 2026-09-26
**Feature:** EPIC-002 (RBAC Foundation), US-018 B4 (Gate 1 OQ7: ADR-only, not built)
**Related:** ADR-0013 (flat tenant RBAC), ADR-0021 (grant-subset)

---

## Context

Nexus authorization is flat and tenant-scoped. A permission such as `user:write` or `user:role:assign` applies to **every** user in the caller's tenant. No ownership, org-unit, manager or resource-group scoping exists, and ABAC and hierarchical roles are outside EPIC-002's scope boundary. The principal-architect review (finding M4) asked for this to be decided explicitly, so that it is not later mistaken for "solved".

## Decision

Object-level authorization is **not built for GA**. The following risk is **accepted**:

> Any holder of a tenant-scoped write permission can act on any user or role in that tenant. In particular, a holder of `user:role:assign` can assign or revoke, within the limits of ADR-0021's grant-subset rules, for **any** user in the tenant, including administrators (subject to revoke-subset), and a holder of `user:write` can edit any user's account.

Mitigations that exist today and bound the risk:
- Tenant isolation, enforced in the service layer and, from US-018 M8, by a composite FK.
- ADR-0021's grant-subset, revoke-subset and role-subset rules, and the no-self-assignment rule for non-administrators.
- Atomic audit of every RBAC mutation (ADR-0024).
- Access-review endpoints (US-018 C3) for quarterly review.

## Triggers for re-evaluation

- A customer or compliance requirement for delegated administration below tenant level (for example, a department administrator).
- Introduction of an org hierarchy, groups or resource ownership in any epic.
- A penetration-test finding that exploits intra-tenant scope.
- Epic 3's Tenant Admin UI introducing any per-object management surface.

## Consequences

**Benefits:** no new model or schema for GA, and the scope boundary is stated rather than implied.

**Trade-offs:** tenant administrators must be trusted across the whole tenant. Least privilege is achievable only by withholding permissions, not by scoping them.

**Follow-on rule:** any feature that introduces per-object ownership must revisit this ADR before adding a permission that implies an ownership check.
