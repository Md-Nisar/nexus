# ADR 0025 — Break-Glass First-Administrator CLI

**Status:** Proposed (Revision 1: threat-model RC-37 folded in, 2026-09-26; Revision 2: delta review RC-47 and RC-50(d) folded in, 2026-09-30; Revision 3: spot-check RC-54(a) folded in, 2026-10-01)
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
   - **No replay of an old approval (Revision 1, RC-37.2).** The CLI refuses, with its own exit code (6), a change reference that already appears on a SUCCESS `ROLE_BREAK_GLASS_GRANT` row: one non-locking read of `auth_events` through an `rbac` outbound port. The refusal is audited and paged like every other refusal. Without it, a re-run after the tenant falls to zero administrators again would succeed under the old approval.
   - **Lookup shape (Revision 2, RC-47).** The lookup is **global** across tenants. It filters on `event_type = 'ROLE_BREAK_GLASS_GRANT'` and `outcome = 'SUCCESS'`, and compares the unquoted `metadata.changeRef` with a **bound parameter**. The runbook allows one invocation at a time per reference, because two concurrent runs can both pass the non-locking lookup (in two different zero-admin tenants only).
5. **Actor.**
   - `user_roles.assigned_by` is set to the target user. This needs no migration and no synthetic system user (which would be a new principal type), and does not link an operator's identity into tenant data.
   - Operator attribution is the required change reference, stored in the audit metadata and joined to the infra access log.
   - **Reviewer note (Revision 1, RC-37.5).** A break-glass grant appears as `assigned_by = target` in `user_roles`, in the assignment list and in the US-018 C3 access-review holders, which looks like a self-granted administrator. The access-review runbook tells reviewers to join such rows to `ROLE_BREAK_GLASS_GRANT` before raising a finding.
6. **Audit and alert.**
   - Every invocation writes `ROLE_BREAK_GLASS_GRANT` (SUCCESS atomically with the grant, per ADR-0024; FAILURE independently), including an argument-validation refusal (1 above), whose row carries no argument values.
   - Every invocation emits ERROR `RBAC_BREAK_GLASS_USED`, which triggers a **page through a log-based alert**. The process is too short-lived to be scraped, so a metric would never reach Prometheus.
   - **Page capture (Revision 1, RC-37.4).** A pod removed by `kubectl run --rm`, or a Job with a short TTL, can disappear before the node's log shipper reads it. The runner waits one log-shipper flush interval before exiting, and the runbook forbids `--rm` unless the drill proves capture without it. The M5 staging drill passes only when **the page is received from a Job run exactly as the runbook specifies**. Backstop: a daily reconciliation alert on new `ROLE_BREAK_GLASS_GRANT` rows, so a lost page is found from the durable row within a day.

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

**Follow-on rule:** any future non-HTTP privileged entry point follows this pattern (profile-gated, callers restricted by ArchUnit, audited on every invocation including refusals, log-based paging) or supersedes this ADR.
