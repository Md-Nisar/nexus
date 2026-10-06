# ADR 0020 — Tenant Data Lifecycle: Retention, Offboarding, and Erasure

**Status:** Accepted
**Date:** 2026-09-28 (proposed) · **Decided:** 2026-10-02
**Feature:** EPIC-003 (Tenant Management): US-036 (audit viewer), US-038 (export), US-039 (purge and erasure;
absorbed US-040 on 2026-10-04), US-046 (retention jobs), US-021 (`auth_events` partitioning, moved from US-046)
**Decided by:** the product owner delegated this decision; recorded here with the research behind
it. The retention periods in D1 are engineering defaults chosen against the standards cited. Legal
should confirm them before GA (follow-on rule 1).
**Related:** ADR 0006 (email encryption and blind index), ADR 0011 (audit writes), ADR 0012 (least-privilege
`nexus_app`: no DDL, append-only `auth_events`), ADR 0016 (Redis keyspace),
`docs/story/3-tenant-management/EPIC-003.md` (decision D6: 30-day grace period)

---

## Context

Nexus stores tenant-owned and personal data: users with an encrypted email and a blind index
(ADR 0006), and auth and RBAC audit events (ADR 0011/0012). Apart from ADR 0006's note on erasure
and the audit-retention remarks in `SECURITY.md` and `observability-standards.md` (audit log
"retention ≥ 1 year", "never deleted by application code"), there is no platform-wide rule for:
- how long data is kept;
- what happens when a tenant leaves;
- how a data-subject erasure request is fulfilled.

For a SaaS product these are contractual and regulatory commitments. Retrofitting them onto
existing tables is far harder than designing for them.

Three facts in the current schema shape every option:
- `auth_events` blocks `UPDATE` and `DELETE` with triggers (`V2__identity_schema.sql`).
- `user_roles` blocks `DELETE` with a trigger, and `user_roles.assigned_by` is a NOT NULL foreign
  key to `users` (`V5__rbac_schema.sql`). Deleting a user who ever assigned a role therefore
  fails.
- The personal data held about a user is: `users.email_cipher`, `users.email_hmac` and
  `consent_accepted_at`, plus `auth_events.ip_address`, `user_agent` and `metadata`.

EPIC-003 has already approved a 30-day grace period between a tenant being scheduled for deletion
and being purged (D6), during which the tenant can be restored.

### What standards and industry practice say (research, 2026-10-02)

- **Audit-log retention.**
  - PCI DSS v4.0 requirement 10.5.1: keep audit logs for at least 12 months, the last 3 months
    immediately available. This is the most specific widely used benchmark, and many SOC 2
    auditors apply the same 12-month expectation _(the SOC 2 point is inferred from common
    practice, not quoted from a standard)_.
  - `SECURITY.md` already requires at least 1 year.
- **Deletion is a controlled process.** ISO/IEC 27001:2022 Annex A 8.10 ("Information deletion")
  requires:
  - a retention schedule per information category;
  - scheduled deletion when retention ends;
  - methods that make data unrecoverable;
  - verification that deletion happened.
- **Offboarding grace periods.**
  - Atlassian Cloud keeps data 60 days after a paid subscription ends (15 for free).
  - Microsoft 365 keeps it 90 days in a limited-function state for extraction, and deletes it
    within 180 days.
  - EPIC-003's 30 days (D6) is shorter but within the range. Export is offered before deletion
    is scheduled, as Microsoft's limited-function period is used for.
- **GDPR erasure.**
  - Art. 12(3): answer within one month, extendable by two months for complex cases.
  - Art. 17(3)(b) and (e): erasure may be refused where processing is needed for a legal
    obligation or for legal claims.
  - EDPB Guidelines 01/2025: pseudonymised data is **still personal data** while anyone can
    re-identify it. Pseudonymising an audit row is therefore not erasure; it only lowers risk.
- **Backups.** ICO guidance accepts that data in backups cannot always be erased at once. It may
  be put "beyond use":
  - it is not used to make decisions about the person and not shared;
  - it is kept secure;
  - it is deleted when the backup expires on its normal schedule;
  - and people are told this.
- **Removing old audit rows without weakening append-only.** In MySQL,
  `ALTER TABLE … DROP PARTITION` removes a whole time range and does **not** fire `DELETE`
  triggers. Dropping time partitions with a separate DDL-capable account keeps
  `UPDATE`/`DELETE` blocked for the application.

### Roles under GDPR

For tenant data, the **customer (tenant) is the controller** and Nexus is the **processor**
(Art. 28). Data-subject requests are therefore made to the tenant, and Nexus gives the tenant
admin the tools to fulfil them (US-039). Nexus is controller only for its own operator accounts
and platform security logs. _(This is the standard B2B SaaS model; contracts must say so — inferred,
not reviewed by legal.)_

---

## Decision

### D1 — Retention schedule per data class

| Data class | Where | Kept for | Then |
|---|---|---|---|
| Account data | `users`, `user_roles`, `roles`, tenant profile, invitations | While the tenant exists, unless erased earlier (D3) | Removed by tenant purge (D2) |
| Deactivated members | `users` with status `DISABLED` | While the tenant exists. The tenant admin decides whether to erase (D3) | Removed by purge or erasure |
| Login and one-time tokens | `refresh_tokens`, `auth_tokens`, invitation tokens (all stored as hashes) | 30 days after expiry, revocation or use | Batch-deleted by the retention job |
| Audit and security events | `auth_events` | **13 months.** Covers PCI DSS's 12 months plus one monthly partition of slack; all of it stays online, beyond the 3-month "immediately available" rule | Monthly partition dropped (D5) |
| Application logs | Log pipeline | 30 days. The logging standards allow only masked emails (`a***@example.com`) and no secrets | Expire in the log store |
| Metrics | Prometheus / monitoring stack | 13 months (no personal data) | Expire in the store |
| Backups | Database backups | Rolling 35 days | Expire; erased data is "beyond use" until then (D3) |
| Cache and coordination data | Redis | Existing TTLs (at most 7 days, via refresh) | Tenant keys deleted at purge (D2) |

Every new table holding tenant-owned or personal data must name its row in this table, or add
one, in its `03-design.md`. That replaces the interim rule of the proposed ADR.

### D2 — Tenant offboarding

1. **Export before scheduling.**
   - A tenant admin can request a full export at any time while the tenant is `ACTIVE` (US-038).
   - Once the tenant is `PENDING_DELETION`, its users cannot sign in, so an operator produces the
     export on request.
   - Format: a ZIP with one JSON Lines file per entity type, plus a `manifest.json` listing
     files, row counts, export time and a schema version.
     - Emails are decrypted, since this is the tenant's own data.
     - Password hashes, token hashes, MFA secrets and blind-index values are never exported.
     - The tenant's `auth_events` for the retention window are included.
2. **Grace period:** 30 days in `PENDING_DELETION` (EPIC-003 D6), restorable by an operator.
3. **Purge (US-039)** when the grace period ends:
   - **Hard-delete** every tenant-owned row: users, roles, user roles, tokens, invitations and
     profile data.
   - **Delete** the tenant's Redis keys by their `{tenant_id}` discriminator (ADR 0016 D3).
   - **Keep the `tenants` row as a tombstone:** status `DELETED`, contact fields cleared, slug
     reserved permanently so it cannot be reused to impersonate the old tenant.
4. **Audit events are not deleted at purge.**
   - They age out with their 13-month partition (D1).
   - They are kept for security and legal claims (Art. 17(3)(e)).
   - Once the `users` rows are gone, their user ids no longer resolve to an account.
5. **Deletion confirmation:** purge writes one `TENANT_PURGED` audit event with row counts per
   table. Operators can send the customer a deletion confirmation on request.
6. **Backups** keep the purged data for at most 35 days and are not used for anything in that
   time (beyond use). If a backup is ever restored, the restore runbook re-applies the deletion
   log (D4) before the database is put back into service.

### D3 — Data-subject erasure (Art. 17)

1. **Who:**
   - A tenant admin, acting for the person, erases a deactivated member (US-039).
   - Nexus completes the technical erasure within **7 days** of the admin's request, so the tenant
     can meet its one-month Art. 12(3) deadline.
2. **Anonymise the `users` row instead of deleting it.** Deletion is impossible while
   `user_roles.assigned_by` references the user, and the row is needed so role history stays
   consistent.
   - Overwrite `email_cipher` and `email_hmac` with non-identifying values (a fixed marker and
     a per-row value that is unique and cannot be reversed).
   - Clear `consent_accepted_at` and set status `DISABLED`.
   - Record `erased_at`. An erased user can never be reactivated (US-030's reactivation refuses
     it).
3. **Delete** the person's refresh and auth tokens, pending invitations and Redis keys
   (permission set, lockout counter). Revoke any active role assignments by setting
   `revoked_at`, which `UPDATE` permits.
4. **Audit events stay** until their 13-month expiry.
   - They hold the person's user id, IP address and user agent.
   - That is still personal data (EDPB 01/2025), kept under Art. 17(3)(e) and legitimate interest
     in security (Recital 49).
   - The tenant's privacy notice must say so. The tenant audit view (US-036) shows the account as
     "erased user", not as an email address.
5. **Backups:** as D2.6 — beyond use for at most 35 days, and erasure re-applied after any restore.
6. **Record:** a `MEMBER_ERASED` audit event with requester, time and user id, and no erased data.

### D4 — Deletion log for backup restores

Every purge (D2) and erasure (D3) appends the affected tenant id or user id to a `deletion_log`
table.
- It holds no personal data beyond the id.
- It is append-only, like `auth_events`.
- It is kept for 35 days plus a margin, i.e. as long as any backup could contain the data.

The restore runbook replays it, so restoring a backup never brings back erased data.

### D5 — Enforcement: scheduled jobs, a separate retention account, and proof

**Jobs**
- One scheduled job per data class: token cleanup, audit partition rotation, tenant purge,
  deletion-log expiry.
- Each job is idempotent and works in batches (at most 1,000 rows per transaction).
- Only one instance runs a job at a time, through a database lease (a row lock taken with
  `SELECT … FOR UPDATE SKIP LOCKED`). This is used instead of Redisson, which ADR 0016 D2 keeps
  evidence-gated.

**Audit partitions**
- `auth_events` becomes `RANGE`-partitioned by month on `created_at`. MySQL requires the primary
  key to include the partition column, so the key becomes `(id, created_at)`.
- The rotation job adds next month's partition ahead of time and drops partitions older than
  13 months.

**A separate retention account**
- `DROP PARTITION`, and the deletes on trigger-protected tables needed by purge (`user_roles`),
  run under a separate database account, `nexus_retention`, used only by the retention jobs.
- `nexus_app` keeps no `DELETE` on protected tables and no DDL (ADR 0012).
- The `user_roles` delete trigger lets only that account's session through. How the trigger
  identifies the session account (`USER()` versus `CURRENT_USER()`, which returns the trigger's
  definer) is **verified at US-039 design**, with a test that `nexus_app` is still refused.

**Proof (ISO 27001 A.8.10 verification)**
- Every job run writes a `RETENTION_PURGE` audit event with its data class and row count.
- Metrics, with the bounded label `data_class`:
  - `nexus_retention_purged_rows_total{data_class}`;
  - `nexus_retention_job_last_success_timestamp{data_class}`.
- An alert fires if any job has not succeeded for 48 hours.

### D6 — Data residency

- **One region for MVP.** The region and the sub-processors are named in the customer DPA.
- No tenant is pinned to a region.
- When a contract needs residency, the path is a **separate regional deployment** of the whole
  stack: a regional "bridge"/"silo" in AWS SaaS Lens terms. It is not per-tenant databases inside
  one deployment.
- A future ADR records that decision when the first such contract appears.

---

## Consequences

**Positive**
- Every data class has a retention period, an owner job and a measurable proof of deletion, which
  covers ISO 27001 A.8.10's control intent.
- Audit history stays append-only to the application; old data leaves only as whole partitions
  through a separate account.
- Tenant purge and personal erasure are both possible despite the trigger and foreign-key
  constraints, without giving `nexus_app` new powers.

**Negative / accepted**
- An erased person's user id, IP address and user agent stay in audit events for up to 13 months.
  This is lawful under Art. 17(3)(e) and Recital 49 but must be disclosed.
- Backups hold purged or erased data for up to 35 days ("beyond use").
- Partitioning `auth_events` changes its primary key: a migration on an append-only table. It is
  cheap now because no environment holds data yet (EPIC-003 open question 5).
- A new database account (`nexus_retention`) must be added to the three grant artifacts (dev init
  SQL, Testcontainers callback, prod runbook) and to the DB-grant health check.

## Alternatives considered

| Decision | Alternative | Rejected because |
|---|---|---|
| D1 | Keep audit events forever | No purpose justifies it (GDPR storage limitation, Art. 5(1)(e)); unbounded table growth |
| D1 | 6 months of audit (GitHub's 180-day audit log) | Below PCI DSS 12 months and `SECURITY.md`'s ≥ 1 year |
| D2 | Anonymise tenant rows instead of deleting them | Leaves a large pseudonymised dataset with no purpose; deletion is simpler to prove |
| D2 | Delete the `tenants` row too | Frees the slug for impersonation and loses the record that the tenant existed |
| D3 | Delete the `users` row | Blocked by `user_roles.assigned_by` and would break role history |
| D3 | Rewrite audit rows to remove the IP | `UPDATE` on `auth_events` is blocked by design (`V2__identity_schema.sql` triggers, ADR 0012); weakening that for erasure would weaken it for attackers too |
| D3 | Crypto-shredding: a per-user key for audit fields | Sound but heavy; revisit if audit events start holding richer personal data |
| D5 | Batch `DELETE` on `auth_events` with a trigger exemption | Slower, fragments the table, and needs a trigger hole on the most security-critical table; partition drop needs none |
| D6 | Per-tenant region pinning inside one deployment | Multiplies operational complexity before any customer needs it |

## Follow-on rules

1. Legal confirms the D1 periods and the controller/processor wording before GA. Changing a period
   only updates D1's table; the mechanism stays.
2. Every new table holding personal or tenant-owned data names its D1 row in `03-design.md`, and
   US-039's purge and erasure are extended to cover it in the same change.
3. A backup-restore drill, including the `deletion_log` replay, runs before GA and then yearly.
4. If audit events start storing richer personal data (names, free text), reopen D3 and consider
   crypto-shredding.

## Sources

- PCI DSS v4.0 requirement 10.5.1 (summary): https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0/10/05/01
- ISO/IEC 27001:2022 Annex A 8.10 (summary): https://www.isms.online/iso-27001/annex-a/8-10-information-deletion-2022/
- ICO, right to erasure (backups, "beyond use"): https://ico.org.uk/for-organisations/guide-to-dp/guide-to-the-uk-gdpr/individual-rights/right-to-erasure
- EDPB Guidelines 01/2025 on pseudonymisation (summary): https://www.hunton.com/insights/publications/edpb-advises-on-pseudonymisation-for-gdpr-compliance
- GDPR Art. 12(3) and 17(3) (summary): https://www.legiscope.com/blog/right-to-erasure-gdpr.html
- Microsoft 365 data retention after a subscription ends: https://learn.microsoft.com/en-us/compliance/assurance/assurance-data-retention-deletion-and-destruction-overview
- Atlassian Cloud data retention after cancellation: https://support.atlassian.com/subscriptions-and-billing/docs/reactivate-a-subscription/
- MySQL: dropping a partition does not fire DELETE triggers: https://bugs.mysql.com/bug.php?id=14351
