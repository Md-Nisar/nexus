# ADR 0012 — Least-Privilege Runtime DB User for `auth_events`

**Status:** Accepted
**Date:** 2026-07-01
**Feature:** US-008 (Emit audit events for all authentication actions)

---

## Context

The application currently connects to MySQL as `root` (`docker-compose.yml:29`, `application.yml` `spring.datasource.username: ${DB_USERNAME:root}`). `auth_events` already has an append-only guarantee at the trigger level: `BEFORE UPDATE`/`BEFORE DELETE` triggers `SIGNAL SQLSTATE '45000'` on any attempt to mutate a committed row (`V2__identity_schema.sql:76-110`). That trigger-based control works, but it is the *only* control — anything that can open a connection as the app (including an attacker who reaches the app's own credential via RCE/SSRF) is, today, a full DB superuser: it can `DROP TRIGGER`, `GRANT`, or otherwise widen its own privileges before touching `auth_events`.

`03-design.md` §6 (Open Unknown #2) frames this as a defense-in-depth question layered on top of the existing triggers, not a replacement for them, and resolves two sub-decisions: (a) whether the audit write path should get its own dedicated `DataSource`, and (b) where and how the restrictive grant is provisioned across environments. `03b-threat-model.md` surfaces the concrete threats this ADR must answer for:

- **T-T3 / T-E1** — a leaked app credential today confers DB-superuser capability; the append-only guarantee needs a privilege-level backstop independent of the trigger, and that backstop must not itself grant more than the app needs.
- **T-T4** — even with a privilege-level backstop, a separately obtained `root`/DBA credential is unconstrained by anything this story can do in-app; the guarantee's boundary must be stated explicitly rather than over-claimed.
- **T-E2** — grants are necessarily provisioned out-of-band (not via Flyway, since grant DDL is environment/credential-topology-specific); that creates a real risk of "grant drift" — an environment silently staying on `root` while CI, which does provision the restricted user, passes.
- **T-E3** — if an operator "fixes" a Flyway failure by widening the runtime user's grant to include DDL, the entire privilege-level guarantee is silently undone.

---

## Decision

### 1. Single least-privilege `nexus_app` user; single `DataSource` (second-DataSource alternative rejected)

The whole application — not just the audit write path — connects as **one** non-root, least-privilege user, `nexus_app`. It replaces `root` as the runtime credential (`docker-compose.yml` `DB_USERNAME`, `application.yml`).

Grant shape:

```sql
-- auth_events: append + read only -- privilege-level backstop to the existing triggers
GRANT INSERT, SELECT ON nexus.auth_events TO 'nexus_app'@'%';

-- other identity tables: normal DML, no DDL
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users          TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.refresh_tokens TO 'nexus_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_tokens    TO 'nexus_app'@'%';
```

`nexus_app` never receives `UPDATE`/`DELETE` on `auth_events`, and never receives `DROP`, `ALTER`, `CREATE`, or `GRANT` on anything.

**Rejected alternative: a second, dedicated `DataSource` for the audit write path.** A second `DataSource` implies a second connection pool and a second `PlatformTransactionManager`, plus routing logic to decide which manager a given write joins. That collides directly with the existing `REQUIRES_NEW` pattern established in ADR 0009: `SecureEventService`'s counter and audit writes rely on a single, well-understood transaction manager, and a second pool/manager would force every REQUIRES_NEW call site to reason about which manager it is joining. This is a large structural change to buy a guarantee — "the app cannot UPDATE/DELETE `auth_events`" — that a single least-privilege user already delivers with zero impact on transaction plumbing. Rejected in favor of one pool, one TX manager, one user with a narrower grant on one table.

The existing append-only triggers are retained unchanged as belt-and-suspenders defense-in-depth; this decision adds a second, independent layer, it does not replace the first.

### 2. Grants are provisioned out-of-band per environment, NOT via a Flyway migration

Flyway (ADR 0003) owns the schema, but grant DDL is not schema: it is environment- and credential-topology-specific (Testcontainers, dev, and prod each use different host specs and credential-issuance mechanisms). Encoding `CREATE USER`/`GRANT` into a versioned `V<N>__*.sql` migration would couple the append-only schema history to a concern that varies per environment and per deploy target, and would run under whichever credential executes Flyway — which is exactly the credential this decision is trying to keep separate from the runtime credential (see §3). Grants are therefore provisioned out-of-band, per environment:

| Environment | Mechanism |
|-------------|-----------|
| Testcontainers (`*IT`) | `withInitScript(...)` or `@DynamicPropertyRegistrar`-time `CREATE USER`/`GRANT`, executed against the container so integration tests can open a connection as `nexus_app`. Flyway still runs as `root` inside the same container. |
| Local dev (docker-compose) | `mysql/init/01-grants.sql` mounted into `/docker-entrypoint-initdb.d`; `docker-compose.yml`'s `DB_USERNAME` flips from `root` to `nexus_app` for the app's own connection. |
| Prod | Ops runbook step (credential creation + rotation), handed to ops. `application-prod.*` is hook-denied to Claude Code (`CLAUDE.md`) — this wiring is explicitly out-of-band and not something this story's tooling touches. |

(The concrete init-script/docker-compose/runbook artifacts are T-08-10's deliverables, not this ADR's; this ADR records the *decision*, not the scripts.)

### 3. Migration credential and runtime credential are separate — `nexus_app` never receives DDL

Flyway needs a DDL-capable credential to apply migrations (`root` in dev/Testcontainers today; a dedicated migration user in prod). `nexus_app` is a runtime-only credential and must never be granted `CREATE`, `ALTER`, `DROP`, `GRANT`, or any other DDL privilege, under any circumstance — including "just to get Flyway working" during an incident. This rule exists specifically to close T-E3: an operator who widens `nexus_app`'s grant to unblock a failing migration silently undoes the entire privilege-level guarantee this ADR establishes, without necessarily realizing it. If a migration cannot run under `nexus_app`, the correct fix is to run it under the (already-distinct) migration credential, not to grant DDL to the runtime user.

### 4. Accepted residual: this guarantee binds the application principal + trigger path, not root/DBA (T-T4)

This decision constrains what an application-reachable credential (`nexus_app`) can do. It does **not**, and cannot, constrain a separately obtained `root` or other DBA-level credential — such a principal can still `DROP TRIGGER` and directly `UPDATE`/`DELETE` `auth_events`, bypassing both layers of defense-in-depth described above. This is an explicit, accepted residual: privileged-access management, root-credential lockdown, and DBA governance are DB-server/operations concerns, not something an application-layer ADR can resolve. The mitigations available to this story are recorded here as expectations handed to ops, not as code:

- The DDL-capable migration credential should be distinct from, and more tightly held than, any other credential (never reused as a general-purpose admin login).
- Both the migration credential and prod `root` should be rotated on a defined cadence.
- Prod `root` access should be locked down (network-restricted, audited, not used for routine operations) — this ADR's guarantee is meaningful only if `root` itself is not casually reachable.

The threat model (`03b-threat-model.md`, T-T4) frames this the same way: WS-2's value is real (it removes the largest, most commonly RCE/SSRF-reachable principal — the app itself — from the set that can tamper audit rows) but bounded (it says nothing about a compromised superuser). This ADR does not claim full immutability against a DB superuser; it claims removal of the application connection from that risk set.

### 5. CI-provisioning requirement — the guarantee must actually be exercised, not merely declared (T-E2)

Because grants live in out-of-band scripts rather than a Flyway-tracked migration, there is a real risk that some environment (most dangerously, prod) never receives the `nexus_app` credential and quietly keeps running as `root`, while CI — which does provision `nexus_app` for its own tests — passes and gives false confidence that the control is live everywhere. Two operational conditions close this window, and this ADR records them as binding on this story even though their implementation lives in separate tasks:

- The privilege-level append-only integration test (T-08-11) **must** run its assertions as an actual `nexus_app` connection, provisioned fresh in every CI build (T-08-10) — not as a aspirational grant script that is authored but never exercised. If CI ever silently falls back to `root` for that test, the test is validating nothing.
- A runtime self-check (T-08-12) must detect, at application startup/via actuator, whether the live connection is `root` or otherwise able to `UPDATE`/`DELETE` `auth_events`, and log a `WARN` if so — making an un-provisioned environment observable rather than a silent gap discovered only during an incident.

Without both of these, the privilege-level guarantee described in §1 is a claim about what *should* be true in an environment, not a verified property of that environment.

---

## Consequences

**Benefits:**
- A leaked or RCE/SSRF-obtained application credential no longer confers DB-superuser capability. Today (`root`), a leaked app credential means `DROP`, `GRANT`, cross-database access, and unrestricted `auth_events` mutation. After this decision (`nexus_app`), the same leak yields `INSERT`/`SELECT` on `auth_events` and scoped DML elsewhere — no DDL, no `GRANT`, no way to tamper with or delete a committed audit row. This reduces T-E1 from High to Medium.
- The privilege-level guarantee is independent of, and additive to, the existing trigger guarantee (T-T3): even if a future change accidentally dropped or disabled a trigger, `nexus_app` still could not `UPDATE`/`DELETE` `auth_events` at the grant level.
- Zero structural impact on the existing transaction model: one connection pool, one `PlatformTransactionManager`, `REQUIRES_NEW` (ADR 0009) unaffected.

**Trade-offs:**
- Provisioning is now a manual, per-environment, out-of-band step rather than something Flyway tracks and applies automatically — this reintroduces a class of "did every environment actually get configured" risk (T-E2) that a migration-based approach would not have. This ADR does not eliminate that risk by itself; it is mitigated operationally by the CI-provisioning requirement and runtime self-check described in §5 (T-08-10/11/12), not by the grant alone.
- Does not stop a DB superuser (`root`/DBA) — explicitly accepted (§4), not a gap this story can close in-app.
- One more credential (`nexus_app`) for ops to manage and rotate, in addition to the migration credential.

---

## Alternatives Considered

| Option | Rejected because |
|--------|-------------------|
| Second dedicated `DataSource`/connection pool for the audit write path | Requires a second `PlatformTransactionManager` and routing logic; collides with the existing `REQUIRES_NEW` pattern (ADR 0009), which assumes a single transaction manager. Disproportionate structural cost for a guarantee a single least-privilege user already provides. |
| Provision grants via a Flyway migration | Grant DDL is environment/credential-topology-specific (different host specs and credential issuance per environment) and would run under whichever credential executes Flyway — coupling schema history to a concern that must stay separate from it, and undermining the migration-vs-runtime credential split in §3. |
| Rely on the append-only triggers alone; no DB-role change | Leaves the application connection as a full DB superuser (`root`) — a leaked app credential could `DROP TRIGGER` and then freely tamper with `auth_events`, i.e., exactly T-E1's unmitigated form. The triggers alone are a single layer with no privilege-level backstop. |
| Constrain `root` itself (network-restrict, revoke, disable) as the primary control | Out of scope for an application-layer decision — this is DB-server hardening / privileged-access management and belongs to ops, not this ADR. Recorded as an expectation on ops (§4) rather than a decision this ADR can enforce. |

---

### Cross-references
- `docs/features/US-008/03-design.md` §6 (WS-2 design), §11 (ADR summary row)
- `docs/features/US-008/03b-threat-model.md` — T-T3, T-T4, T-E1, T-E2, T-E3
- `docs/features/US-008/04-tasks.md` — T-08-09 (this ADR), T-08-10 (`nexus_app` provisioning), T-08-11 (privilege-level append-only `*IT`), T-08-12 (runtime self-check)
- ADR 0003 — Flyway owns the schema (basis for keeping grant DDL out of Flyway's migration history)
- ADR 0009 — REQUIRES_NEW transaction pattern (basis for rejecting the second-`DataSource` alternative)
