# ADR 0027 — Optimistic Concurrency for the Role Permission-Set Replace

**Status:** Proposed (2026-10-19; US-019 threat-model RC-55, RC-56, RC-57, RC-58 folded in, 2026-10-19; delta review RC-64 folded in, 2026-10-19)
**Date:** 2026-10-19
**Author:** Principal Architect
**Feature:** EPIC-002, US-019 B8
**Related:** ADR-0018 D5–D7 (set lock), ADR-0021 (grant-subset; Revision 3), ADR-0024 (atomic audit), US-018 `03-design.md` §11.1 (RC-46 lock order), `docs/features/US-019/03-design.md` §10, `03b-threat-model.md` (T-T22, T-E48, T-E49, T-I20, T-T24)

## Context

`PUT /api/v1/roles/{roleId}/permissions` replaces a role's whole permission set. Gate 1 chose `ETag`/`If-Match` (428 missing, 412 stale). Neither `roles` nor `role_permissions` has a version column, writes are targeted statements (no load-and-save entity), and permission migrations and operators write `role_permissions` out of band. Under REPEATABLE READ, two requests carrying the same `If-Match` both pass a compare-then-write on a snapshot. The project skill suggests `@Version` for optimistic locking; this ADR records why the design deviates.

## Decision

1. **The ETag is a content hash**, `"rp1-" + base64url(SHA-256(roleId ‖ ascending permission ids))`, a strong validator over the permission set, served on `GET /roles/{roleId}/permissions` and on the PUT's 200. **It is a concurrency validator, not a capability or a secret:** anyone who knows the ids can compute it. No authorization decision may depend on knowing it.
2. **`If-Match` takes exactly one strong entity-tag.** A list, `*`, a weak-only value, an empty or an unparseable header gives 428 `PRECONDITION_REQUIRED`.
3. **Authorize before revealing or locking.** Every 403 (live `role:read` and `role:write`, A3 on adds, role-subset on removes, the administrator rule on a demotion) is decided on the snapshot before the snapshot 412, before the no-op 200 and before any lock. 412 and 428 bodies carry no ETag, ids or counts.
4. **Lock, then compare against the authorised snapshot.** After authorization: set lock when the role is admin-defining now (then the role row), otherwise the role row (then the set lock on a promotion), the role row being an X lock taken by `SELECT … FOR UPDATE` under the column-scoped `UPDATE` grant. Then a **current** `FOR SHARE` read of the role's `role_permissions`; the request proceeds only if that state's version **equals the snapshot version `v0`** used for every earlier decision. Equality, not membership in `If-Match`, is what makes the snapshot-based classification apply to the locked state.
5. **Under the set lock, admin-defining classification is current:** derived from a `FOR SHARE` read of `role_permissions` for the locked role ids (ADR-0021 R3-4).
6. **Lock order** follows US-018 RC-46 by the role's current class and ends with `role_permissions`; no verb holds a `role_permissions` lock while waiting on `roles` or `user_roles`. Assign and attach, which can queue behind B8's role-row lock, re-classify after their insert (ADR-0021 R3-3). **Attach takes the role-row X lock (`SELECT … FOR UPDATE` on `roles`) before its insert** (US-019 RC-64), so concurrent attaches on one role queue instead of deadlocking on their post-insert current reads.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Version column on `roles`, conditional `UPDATE … WHERE version = ?` | Needs V-next DDL, a grant change in three artifacts and a health-indicator change; attach/detach must bump it; a migration footer or operator SQL changes the set without bumping it, so an old ETag would match and a PUT could silently undo the footer |
| Compare under no lock | TOCTOU: two PUTs with one ETag both win |
| `FOR UPDATE` on `role_permissions` only | Empty ranges take compatible gap locks: two PUTs then deadlock on insert |
| Accept a list of ETags (RFC 9110 permits it) | Lets a caller pass the versions of two states and bypass classification (T-T22), and turns 412 into a multi-guess composition oracle (T-I20) |
| Last-write-wins | Contradicts Gate 1 Q4 |

## Consequences

- No migration and no grant change. `RolesPrivilegeIT` and `RolePermissionsPrivilegeIT` must prove the locking reads as `nexus_app` (merge-blocking).
- One new verb in the lock family, and attach joins the role-row lock; RES-45 (classification flip, one 1213 victim) extends to B8. Attach ∥ attach on one role serialises on the role row and does not deadlock, whether or not either completes the catalogue (corrected by the US-019 delta review, RC-64: an earlier text scoped a deadlock to catalogue-completing attaches; without the row lock every concurrent pair would have deadlocked).
- The descriptive fields of the representation are not hashed; a deploy that changes a description does not change the ETag. Documented in the API.
- `If-None-Match`/304 is not supported (responses are `no-store`).
