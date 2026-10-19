# ADR 0026 — User Directory Permission, PII Transport and Delegation

**Status:** Proposed (2026-10-19; US-019 threat-model RC-60, RC-61 and RC-63(e) folded in, 2026-10-19)
**Date:** 2026-10-19
**Author:** Principal Architect
**Feature:** EPIC-002, US-019 B1/B2 and B5
**Related:** ADR-0006 (email blind index; this ADR is the draft of the addendum D5 must sign), ADR-0013 D1 (naming), ADR-0021 (grant-subset), `docs/features/US-019/03-design.md` §3, §4, §7, `03b-threat-model.md` (T-E50, T-R16, T-S12, T-I21)

## Context

US-020's console must show tenant users with their email addresses. Every `MEMBER` holds `user:read` (V5), so gating a directory on `user:read` would expose every email in a tenant to every user and make an email lookup a tenant-wide existence oracle (US-019 requirements R1). Email is PII under GDPR and is stored encrypted with a keyed blind index (ADR-0006). URLs are logged by proxies, browsers and APM tools that the application does not control. Under grant-subset (ADR-0021), any holder of a permission can pass it on.

## Decision

1. **New permission `user:directory:read`** (V11, id `019f6839-1808-7000-8000-000000000009`), the only gate for the directory endpoints (list, batch, by-id, lookup). `user:read` is unchanged. V11's footer gives it to system `TENANT_ADMIN` roles and to live full-catalogue roles only; `MEMBER` never receives it.
2. **Exact field allow-list:** `userId, email, status, emailVerified, createdAt`. Never `tenant_id`, `email_hmac`, password hash, lockout counters.
3. **Email never in a URL.** Exact-email lookup is `POST /api/v1/users/lookup` with the email in the body (body capped at 1 KiB before parsing). `GET /api/v1/users?email=` is rejected with 400. Validation and body-parse errors never echo the value, and the exception handler never logs a parse error's message.
4. **No email or blind index** in any log, metric tag, audit metadata, exception message or trace attribute. Directory reads are audited as `USER_DIRECTORY_READ` (operation, result count, lookup outcome, resolved id on a hit) on the best-effort path.
5. **Cross-tenant ids and emails** behave exactly like missing ones (same status, body and statements). Lookup normalisation is `EmailBlindIndexService`'s only.
6. **Abuse controls are detective plus rate bounds, not prevention of enumeration by a holder.** A holder can list the directory. Bounds: 30 lookups per minute per actor, and a per-actor ceiling across all directory operations; both fail open with the rate-limit store (ADR-0016). Detection: a row-volume alert per actor across all operations, a cross-tenant WARN for by-id and batch, a lookup-volume alert.
7. **Delegation (RC-60).** Under grant-subset, a holder of `user:directory:read` with `user:role:assign` or `role:write` could otherwise grant tenant-wide email access onward, including to a self-registered second account (the RES-26 shape applied to PII). Decided, pending explicit D5 confirmation:
   - **Preventive (default ON):** attaching `user:directory:read` to a role, or assigning a role that carries it, requires the caller to be an administrator (ADR-0021 D3). The rule is keyed by permission id, never by `isSensitive`, and is evaluated with A2/A3; a denial is 403 `RBAC_001` with reason `ADMINISTRATOR_REQUIRED`.
   - **Detective:** any grant of the permission by a non-administrator that nonetheless succeeds (for example if D5 turns the preventive rule off) emits WARN `RBAC_PII_PERMISSION_DELEGATED` (ids only, ≥ 1-year retention) and a ticket-level counter.
8. **`isSensitive` (B5)** is a static partition of the catalogue in `Permissions` (`SENSITIVE`, `NON_SENSITIVE`), UX only: no server rule may read it (ArchUnit). Sensitive means: holding it confers control over identities, role assignments, role definitions or the tenant, or read access to personal data or the audit trail. Membership is a Security decision.
9. **Emails are self-asserted until verified** (anonymous registration into the default tenant; PENDING rows). The console shows `status` and `emailVerified` next to every email, and any CSV export escapes formula-leading characters.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Gate on `user:read` | Every member would see every email (R1) |
| Remove `user:read` from `MEMBER` | Changes existing behaviour for every tenant; out of scope |
| `GET ?email=` with log redaction | Every proxy, ingress, browser and APM sink would need its own rule; prod ingress is not in the repo |
| Store the blind index in audit rows | A long-lived pseudonymous identifier with no detection purpose |
| Fail-closed directory audit | Needs a writable transaction on a read path; D5 may still choose it |
| No delegation rule, detective only | Leaves RES-51 at Medium with PII payload |

## Consequences

- One more catalogue row: V11 changes the administrator threshold (nine permissions); the B7 footer and the runbook flush handle it.
- Delegated directory access needs an administrator. A "user manager" holding the permission can use it but cannot pass it on.
- A holder can still read the whole directory; detection, not prevention, is the control (RES-49, escalated to D5).
- Residuals: RES-49 (enumeration by holder), RES-50 (best-effort audit), RES-51 (delegation; Low with the preventive rule).
