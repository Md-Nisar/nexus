# ADR 0025 — Break-Glass First-Administrator CLI

**Status:** Proposed (Revision 1: threat-model RC-37 folded in, 2026-09-26; Revision 2: delta review RC-47 and RC-50(d) folded in, 2026-09-30; Revision 3: spot-check RC-54(a) folded in, 2026-10-01; Revision 4: M5 implementation facts and open O-7 recorded, 2026-10-15; Revision 5: O-7 resolved, security review L-1 and L-2 fixed, 2026-10-15)
**Date:** 2026-09-26
**Feature:** EPIC-002 (RBAC Foundation), US-018 A7 (Gate 1 OQ4: operator-run CLI)
**Related:** ADR-0014 (bootstrap tenant, `nexus_app` grants), ADR-0021 D3/D4, ADR-0024, `docs/features/US-018/03-design.md` §7

---

## Context

A tenant with zero administrators can be recovered today only by a manual production `INSERT` (the US-012 runbook, step 4). The story requires an audited, supported mechanism that fires an alert and needs no manual SQL. This is the platform's first privileged entry point that is not HTTP.

## Decision

1. **Packaging.**
   - The service jar is run with profile `break-glass`: an `ApplicationRunner` in `rbac.interfaces.cli`.
   - The web server is off and Flyway is off (the tool must never migrate a schema); `ddl-auto=validate` still checks the schema.
   - It uses the service's `nexus_app` credentials, so no grant change is needed.
   - Arguments: the target user id and a required change reference. Distinct exit codes signal success and each refusal.
   - **Failed grant transaction (T-008; exit codes 7 and 1 confirmed by the user).** If the grant transaction throws, it rolls back, and the refusal is then audited (FAILURE row with the tenant) and paged like any other: **exit 7** (`CONCURRENT_INVOCATION`) for a lock failure (MySQL 1213 or 1205; two runs on one zero-admin tenant can deadlock on the insert), **exit 1** (`UNEXPECTED_ERROR`) for anything else. No retry and no extra lock (ADR-0018); the runbook allows one invocation per tenant at a time. Exit 1 is also what a crash before or outside the grant transaction reports, with no row and no page. Runbook (T-008 review Low 3): exit 1 with no `RBAC_BREAK_GLASS_USED` in the pod log, page Platform Security manually; exit 1 with one, verify `user_roles` / `auth_events` before re-running.
   - **The change reference admits ticket-id shapes only, in one canonical form** (`^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$`; Revision 1, RC-37.1; revised in Revision 2, RC-47). The number has no leading zeros, so a re-padded reference cannot pass as a new string for the same ticket. No free text, so no name or email can reach audit metadata.
   - **Argument-validation refusal (Revision 3, RC-54(a)).** An invalid target user id or change reference exits with **code 2** (`INVALID_ARGUMENT`). It writes a `ROLE_BREAK_GLASS_GRANT` FAILURE row with reason `INVALID_ARGUMENT` and a null `tenant_id`, and emits the paging ERROR. **The rejected argument values never appear** in audit metadata or logs, so the refusal path cannot carry free text either.
   - **Web-context guard (Revision 1, RC-37.6; revised in Revision 2, RC-50(d)):** a bean-initialization check in the `break-glass` profile throws unless `spring.main.web-application-type` is `none`. It logs the paging ERROR and **fails the context refresh** before the embedded server starts, so the profile cannot be activated in a serving pod. (It does not run "before any DB access": `ddl-auto=validate` reads the schema during the refresh.)
   - No CLI framework dependency.
2. **Trust anchor.** Infra access (Kubernetes or SSH, audited by the platform). The application adds no secret, no token and no endpoint. A bootstrap bearer token was rejected at Gate 1, because it is a new escalation primitive.
   - **Requester verification (Revision 1, RC-37.1).** Self-registration makes it trivial for an attacker to hold an ACTIVE account in the default tenant, and the realistic abuse is social ("our only admin left; make my account admin"). The runbook therefore requires that the requester's authority is verified against the tenant's **contractual contact of record**, never against the target account, and that a **second person from Platform Security approves**, recorded under the change reference.
   - **Infra audit is a prerequisite (Revision 1, RC-37.3).** Kubernetes API audit logging (pod create and exec, with user identity), retained for at least 1 year, is a deployment prerequisite with Ops sign-off on the M5 merge checklist. Without it the change reference joins to nothing.
3. **Containment.**
   - `BootstrapAdminService` is callable only from `rbac.interfaces.cli`, and CLI beans must be profile-gated (ArchUnit).
   - The service never calls `RoleAssignmentService.assign()`, so the no-self-assignment rule needs no exemption.
4. **Preconditions.** The tenant must have **zero** administrators (ADR-0021 D3), evaluated under the same set lock as assign and revoke. The tenant must have a seeded system `TENANT_ADMIN`; the CLI does not create roles, because per-tenant seeding is Epic 3. The target user must be ACTIVE. Otherwise the CLI refuses. It is therefore naturally idempotent and can never grant administration to a tenant that still has an administrator.
   - **Who counts as an administrator (Revision 5, O-7 resolved; security review M-1).** Decision of the user (2026-10-15): for break-glass, an administrator is a holder of the caller-qualifying population (literal `TENANT_ADMIN`, or a role carrying all three dangerous permissions; ADR-0018) **whose user status is not DISABLED**. A tenant whose only administrators are DISABLED is recoverable: the CLI grants a new `TENANT_ADMIN` (exit 0). ACTIVE, PENDING and LOCKED holders still count (a LOCKED lockout recovers by itself), and so does a holder whose status the read does not return (fail closed). **Scope: A7 only.** The last-admin lockout, the assign and revoke guards and `RbacZeroActiveAdminsHealthIndicator` keep the ADR-0018 definition (every active holder, whatever the user status); this is a deliberate narrowing of M-1's option (b), not a redefinition for the whole platform. The DISABLED holder's assignment is left in place; the runbook has the new administrator revoke it through the normal API. No CLI override flag.
   - **Statuses read under the lock (Revision 5, O-7 and L-2).** Inside the grant transaction, after the set lock, one statement reads the `users` rows of the target and of every caller-qualifying holder with `FOR SHARE`, in ascending primary-key order, through a new `UserDirectoryPort.lockUserStatuses` (implemented in `identity.infrastructure`; `rbac` sees a port-local status enum). A locking read returns the latest committed status rather than the transaction's snapshot, and a concurrent status change waits for the grant to end. The target's ACTIVE check is repeated there (L-2), so a target disabled while the tool runs is refused (exit 3), never granted; the earlier non-locking check stays as a pre-filter. This is the one lock this path adds to ADR-0018 D6's set lock. It is taken after the set lock, in the same order as the shared lock that the insert's foreign-key check already takes on the target's `users` row, and only by break-glass. No retry.
   - **No replay of an old approval (Revision 1, RC-37.2).** The CLI refuses, with its own exit code (6), a change reference that already appears on a SUCCESS `ROLE_BREAK_GLASS_GRANT` row: one non-locking read of `auth_events` through an `rbac` outbound port. The refusal is audited and paged like every other refusal. Without it, a re-run after the tenant falls to zero administrators again would succeed under the old approval.
   - **Lookup shape (Revision 2, RC-47).** The lookup is **global** across tenants. It filters on `event_type = 'ROLE_BREAK_GLASS_GRANT'` and `outcome = 'SUCCESS'`, and compares the unquoted `metadata.changeRef` with a **bound parameter**. The runbook allows one invocation at a time per reference, because two concurrent runs can both pass the non-locking lookup (in two different zero-admin tenants only).
5. **Actor.**
   - `user_roles.assigned_by` is set to the target user. This needs no migration and no synthetic system user (which would be a new principal type), and does not link an operator's identity into tenant data.
   - Operator attribution is the required change reference, stored in the audit metadata and joined to the infra access log.
   - **Reviewer note (Revision 1, RC-37.5).** A break-glass grant appears as `assigned_by = target` in `user_roles`, in the assignment list and in the US-018 C3 access-review holders, which looks like a self-granted administrator. The access-review runbook tells reviewers to join such rows to `ROLE_BREAK_GLASS_GRANT` before raising a finding.
6. **Audit and alert.**
   - **Every page is best effort (Revision 5, security review L-1).** A failure of the alert port, on a grant or on a refusal, is logged as ERROR `RBAC_BREAK_GLASS_ALERT_FAILED` (tenant and reason only, no argument value) and never changes the outcome: a grant stays exit 0, a refusal keeps its own exit code. The FAILURE row is written before the page, so it is unaffected.
   - Every invocation writes `ROLE_BREAK_GLASS_GRANT` (SUCCESS atomically with the grant, per ADR-0024; FAILURE independently), including an argument-validation refusal (1 above), whose row carries no argument values.
   - Every invocation emits ERROR `RBAC_BREAK_GLASS_USED`, which triggers a **page through a log-based alert**. The process is too short-lived to be scraped, so a metric would never reach Prometheus.
   - **Page capture (Revision 1, RC-37.4).** A pod removed by `kubectl run --rm`, or a Job with a short TTL, can disappear before the node's log shipper reads it. The runner waits one log-shipper flush interval (configured, default 15 s) before exiting, and before the web-context guard throws, and the runbook forbids `--rm` unless the drill proves capture without it. The M5 staging drill passes only when **the page is received from a Job run exactly as the runbook specifies**. Backstop: a daily reconciliation alert on new `ROLE_BREAK_GLASS_GRANT` rows, so a lost page is found from the durable row within a day.

## Consequences

**Benefits:**
- Removes manual production SQL.
- Every use is durable, attributable and paged.
- The tool cannot be used while a tenant still has an administrator.

**Trade-offs:**
- Recovery needs an engineer with infra access; there is no self-service.
- Tenants without a seeded `TENANT_ADMIN` cannot be recovered by this tool until Epic 3.
- An `assigned_by` that points at the target user looks like a self-assignment unless it is read together with the break-glass audit row (reviewer note under 5).
- Every use needs two people (the operator and a Platform Security approver) and a contact-of-record check, which slows recovery by design.
- Residual social engineering remains, anchored in infra access (RES-35, Low).
- **O-7 resolved (Revision 5).** A tenant whose only administrators are DISABLED is recoverable with this tool (4 above). Trade-off: break-glass and the rest of the platform now use two definitions of "administrator". `RbacZeroActiveAdminsHealthIndicator` does not flag a tenant whose administrators are all DISABLED, and the last-admin guard still counts a DISABLED holder; both are deliberate (the decision is scoped to A7) and are noted in the runbook.
- **Implementation facts (T-007, T-008).** Every refusal row and page is written after the grant transaction has ended, which commits at most one row per invocation; the break-glass Hikari pool is 4; a failed GRANTED page is logged as `RBAC_BREAK_GLASS_ALERT_FAILED` and the exit stays 0. Revision 5: a failed refusal page is handled the same way (L-1 fixed), and the target's ACTIVE check is repeated under the lock (L-2 fixed).

**Follow-on rule:** any future non-HTTP privileged entry point follows this pattern (profile-gated, callers restricted by ArchUnit, audited on every invocation including refusals, log-based paging) or supersedes this ADR.
