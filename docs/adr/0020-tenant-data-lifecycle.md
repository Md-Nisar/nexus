# ADR 0020 — Tenant Data Lifecycle: Retention, Offboarding, and Erasure

**Status:** Proposed
**Date:** 2026-09-28
**Feature:** Platform (no story yet — decide before the first customer-facing data feature)

---

## Context

Nexus stores tenant-owned and personal data (users with encrypted email and a blind index —
ADR 0006; auth and RBAC audit events — ADR 0011/0012). Apart from ADR 0006's note on erasure and
the audit-retention remarks in `SECURITY.md` and `observability-standards.md`, there is no
platform-wide rule for how long data is kept, what happens when a tenant leaves, or how a
data-subject erasure request is fulfilled. For a SaaS product these are contractual and regulatory
commitments, and retrofitting them onto existing tables is far harder than designing for them.

## Decision (to be made)

Open questions for product, legal and architecture — none is decided yet:

1. **Retention periods** per data class: account data, audit/security events, operational logs,
   backups.
2. **Tenant offboarding:** export format, grace period, then hard delete vs. anonymise; how deletion
   reaches backups and Redis.
3. **Data-subject erasure (GDPR Art. 17):** which rows are deleted vs. pseudonymised, and how that
   squares with append-only audit events that must survive (ADR 0009, ADR 0011).
4. **Data residency:** whether any tenant needs region-pinned storage.
5. **Enforcement:** a scheduled purge job per data class, with metrics and an audit event per purge.

## Consequences

To be written when the decision is made. Until then, every new table holding tenant-owned or
personal data must state its retention class in `03-design.md` (DB design section).
