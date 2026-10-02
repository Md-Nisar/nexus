# ADR 0024 — RBAC Mutation Audit Events Are Written in the Mutation's Transaction

**Status:** Proposed (Revision 1: threat-model RC-39 and RC-40.5 folded in, 2026-09-26; Revision 2: delta review RC-50(c) folded in, 2026-09-30)
**Date:** 2026-09-26
**Feature:** EPIC-002 (RBAC Foundation), US-018 A6 (Gate 1 OQ3: same-transaction insert, no outbox)
**Supersedes in part:** the scope of ADR-0011 (in-process retry buffer) for the RBAC success events listed below; the "MUST NEVER throw" contract in `RbacAuditPort`'s Javadoc for those methods
**Related:** ADR-0009 (`REQUIRES_NEW` for events that must survive rollback), ADR-0011, `docs/features/US-018/03-design.md` §6

---

## Context

`ROLE_ASSIGNED`, `ROLE_REVOKED`, `ROLE_CREATED`, `ROLE_PERMISSION_GRANTED` and `ROLE_PERMISSION_REVOKED` are written after commit, through a port whose contract is "never throw". On failure the adapter swallows the error or buffers the event (ADR-0011). A mutation can therefore commit with no audit row, which contradicts EPIC-002 goal #3 (100% of events audited). `auth_events` is in the same MySQL database as the RBAC tables.

## Decision

1. **Success events join the mutation's transaction and fail it.**
   - `SecureEventService` gains `recordEventInCurrentTransaction(AuthEvent)` with `Propagation.MANDATORY`. It calls `AuthEventPort.recordOrThrow`, which uses `saveAndFlush` and bypasses the retry buffer.
   - The flush is mandatory: `AuthEvent` has an assigned id, so a deferred INSERT would fail at commit as an unmapped exception.
   - An audit failure rolls back the mutation, and the request returns 500 `INTERNAL_ERROR`, logged as `RBAC_AUDIT_WRITE_FAILED`, which pages.
2. **`RbacAuditPort` stays one interface with two documented contract groups.**
   - **Atomic:** the five events above, plus US-018's `ROLE_UPDATED` and `ROLE_DELETED`.
   - **Independent:** `recordRoleAssignmentDenied` keeps `REQUIRES_NEW`, never throws, and may be buffered (ADR-0009, unchanged).
   - A second port was rejected: it would be one more abstraction with the same single implementation.
3. **Post-commit work that is not audit** (cache eviction, epoch bumps, INFO logs, timers) stays after commit.
4. **No outbox.** There is no off-box consumer, and an outbox adds a relay and a second failure mode.
5. **Ordering rule (Revision 1, RC-40.5).** In one transaction, no independent-group (`REQUIRES_NEW`) audit call follows an atomic-group audit call. Otherwise the `REQUIRES_NEW` insert could wait on locks held by its own suspended outer transaction's audit row. A unit test (MC-4) asserts the order in each service method that can emit both.
6. **The retry buffer is not a primary path for cross-tenant evidence (Revision 1, RC-39 decision).** US-018 B1 drops the synchronous `REQUIRES_NEW` denial row for cross-tenant targets, to remove a timing oracle. Security offered an alternative: enqueue that row through `AuthEventRetryBuffer.enqueue`, which is already non-blocking (`offer()`) and has a scheduled drain, so no new executor is needed. **It is not adopted.** The buffer's standard lane is a shared, bounded failure-recovery resource: 800 slots, a 10 s drain, and a `depth-warn` alert at 250 (`application.yml:175-189`). It also carries `LOGIN_FAILURE` retries. Making it the primary path for an event any authenticated prober can trigger would let roughly 80 probes per second per instance fill the lane. Because the lane drops the newest arrival when full, genuine failure-path audit events would then be dropped, and the buffer's own depth alerts would fire on attacker traffic. The cross-tenant evidence is the `RBAC_CROSS_TENANT_TARGET` WARN, retained for at least 1 year (Ops sign-off on M8), plus a rate ticket alert on `permission_denied{reason="CROSS_TENANT_TARGET"}` (RES-34, Low). The alert fires at **`max(5 × 7-day baseline, 20 per 15 min)`** (Revision 2, RC-50(c)). Without the absolute floor, a near-zero baseline would make it fire on any single event, or never.

## Consequences

**Benefits:**
- No RBAC mutation can commit without its audit row.
- The success path stops using a second pooled connection.

**Trade-offs:**
- An `auth_events` write failure now blocks RBAC mutations. This is accepted because the table shares the database whose outage would block the mutation anyway.
- The audit INSERT lengthens the privileged lock-hold time, which is re-baselined.
- `PRIORITY` lane membership becomes irrelevant for these events on this path.

**Follow-on rule:** any new RBAC mutation's audit event belongs to the atomic group unless it must survive rollback, in which case it belongs to the independent group and says why.
