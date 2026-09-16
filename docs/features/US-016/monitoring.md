# US-016 — Monitoring

**Feature:** Privilege-based role-assignment gate on `assign()`/`revoke()` (`POST/DELETE /api/v1/users/{userId}/roles[/{roleId}]`), the denial throttle (D14), the composed lock-hold timer (D18), and the mint-side holder-count signal (D13, in `RoleManagementService.attachPermission`).
**Audience:** on-call engineer
**Source of truth:** this document describes what T-002–T-018 actually shipped, verified against the code below (`RoleAssignmentService.java`, `RoleManagementService.java`) on `feature/US-016` — not `03-design.md`'s plan. Every metric name, tag, and log field below was re-grepped against source, not copied from design prose.
**Companion edits (T-020, T-021, already landed):** `docs/features/US-012/monitoring.md` and `docs/features/US-015/monitoring.md` carry the parts of this story's observability surface that extend *pre-existing* US-012/US-015 signals (`permission_denied`'s widened population, the renamed/demoted `nexus_rbac_role_change_denied_not_admin`, `self_role_assignment`'s `privileged`/`callerIsAdmin` tags, `dangerous_permission_granted`'s `holders` tag). This document covers only the signals that are new in this story. Read all three together for the full picture.

---

## 1. Metrics — new in this story

| Metric | Type | Tags | Emitted by | Notes |
|---|---|---|---|---|
| **`nexus.rbac.privileged_role_change_blocked`** *(D15)* | Counter | `operation` ∈ `{assign, revoke}`, `matchedOn` ∈ `{ROLE_NAME, DANGEROUS_PERMISSION}` | `RoleAssignmentService#requireActiveTenantAdmin`, the gate's single throw site (`RoleAssignmentService.java:552-556`) | The precise counterpart to `permission_denied{reason="NOT_TENANT_ADMIN"}` (US-012's coarse floor, unchanged by D6). Bounded at **2×2 = 4 series**; no tenant tag (the paired WARN below carries `tenantId`). Zero new queries — both tags are values the gate already computed. **Not incremented for throttle-suppressed requests** — the throttle (D14) short-circuits above this code entirely. Prometheus name: `nexus_rbac_privileged_role_change_blocked_total`. |
| **`nexus.rbac.denial_throttled`** *(D14)* | Counter | `operation` | `RoleAssignmentService#requireNotThrottled`, the throttle's throw site (`RoleAssignmentService.java:467-470`) | One increment per request *suppressed* — short-circuited to 403 before M1's lock, before M7/M8/M5, before the audit write — because the actor already produced `max-denials` gate denials inside `window-seconds` (see §3 below for the values). Bounded at 2 series. Prometheus name: `nexus_rbac_denial_throttled_total`. **Detection blind spot (M-1, `07-security-review.md`):** a suppressed request produces **no** `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` WARN, **no** `privileged_role_change_blocked{matchedOn}` increment, and **no** durable `ROLE_ASSIGNMENT_DENIED` audit row — so the page-severity `nexus_rbac_privileged_role_change_blocked_dangerous` alert (`docs/features/US-012/monitoring.md` §2) cannot fire on it. Because the throttle key `(tenantId, actorUserId)` is the attacker's own identity, the attacker chooses when to enter suppression — e.g. by burning a few cheap `matchedOn="ROLE_NAME"` denials first — and every `DANGEROUS_PERMISSION` attempt for the rest of the window is invisible to that alert and leaves no durable forensic row. This is adversarially reachable, not a theoretical edge case; recorded in `03b-threat-model.md` §5 RES-11. **Mitigated, not eliminated:** `nexus_rbac_denial_throttle_engaged` (§2 below) was promoted ticket → page specifically so that *entering* the suppressed state always pages, even though the suppressed attempts' own `matchedOn` shape is lost and must be reconstructed by hand from the preceding durable rows. |
| **`nexus.rbac.privileged_revoke_lock_hold`** *(D18)* | Timer | `outcome` ∈ `{denied, lockout, revoked, error}` | `RoleAssignmentService#stopLockHoldTimer` (`RoleAssignmentService.java:389-397`); sample started immediately after M1 returns (`RoleAssignmentService.java:309`) | Measures the **composed** interval `revoke()` holds M1's `FOR UPDATE` lock over the tenant's active admin rows: M8 + M5 + the `REQUIRES_NEW` denial-audit write + M6 — the whole window in which every *other* privileged role change in the tenant is blocked. Bounded 4-value `outcome` tag, no tenant tag (unbounded — correlate via the WARN). **Verified emission caveat:** the sample is started only when `nameMatch` is true (`RoleAssignmentService.java:306-309`); a dangerous-custom-role (non-name-match) revocation never takes M1 and never participates in this timer. Prometheus names: `nexus_rbac_privileged_revoke_lock_hold_seconds_count` / `_sum` / `_max`. **No `_bucket` series exists** — see §4 below and the alerting prerequisite already recorded in `docs/features/US-012/monitoring.md` §2. |
| **`nexus.rbac.dangerous_permission_granted{..., holders}`** *(D13)* | Counter tag addition | `holders` ∈ `{"0", "1", "2-10", ">10"}` | `RoleManagementService#attachPermission`, post-commit block, dangerous path only (`RoleManagementService.java:232-239`); count computed at `:190-191` via `UserRoleAssignmentPort.findActiveUserIdsForRole` | This is the metric layer half of US-016's answer to RES-1(b)/T-E21 (the attach-after-assign escalation path). It is **signal, not a gate** — the attach is never blocked. Fully specified (base metric, `permission`/`tenantId` tags) in `docs/features/US-015/monitoring.md` §1; this row exists here only to record that this story is the one that added `holders`. |

**No PII.** Every field above is a UUID, an integer, or a bounded enum-like string.

**Cardinality budget (re-verified against §9.2):** +4 series for `privileged_role_change_blocked`, +2 for `denial_throttled`, +4 for the lock-hold timer's `outcome`, ≤4× multiplier on the already tenant-keyed `dangerous_permission_granted`, ≤2× multiplier on the already tenant-keyed `self_role_assignment`. No unbounded dimension.

---

## 2. Alerts (Prometheus)

**The gate-bypass canary** (fully specified in `docs/features/US-015/monitoring.md` §2, restated here because it is this story's central alerting deliverable):

| Alert | Expression | Severity |
|---|---|---|
| `nexus_rbac_gate_bypass_canary` *(retargeted from `nexus_rbac_self_role_assignment`)* | `increase(nexus_rbac_self_role_assignment_total{privileged="true", callerIsAdmin="false"}[5m]) > 0` | **page** |

**Mandatory caveat (RC-11.2), stated in full:** this canary can only ever detect a bypass **inside** the gate's own logic — `hasActiveAdminAssignment` (M5) answering the wrong question (T-E22's fail-open axes, or an M8 resolution bug). It **cannot** detect a bypass **around** the gate, because on the success path `privileged="true"` already implies the gate ran and passed. It must not be sold as more than that.

**A second caveat that used to live here, now fixed (M-2, `docs/features/US-016/07-security-review.md`):** `callerIsAdmin` used to be set to `privileged ? "true" : "n_a"` at its emission site — inferred from control flow, not independently re-derived from M5's own result, making `"false"` unreachable by construction. As shipped now, `callerIsAdmin` on the `privileged="true"` series is `Boolean.toString(callerHoldsActiveTenantAdmin(actor))` (`RoleAssignmentService.java:228-241`) — a non-locking M4 projection over the caller's own active role names, deliberately a **different mechanism** than M5's locking read (`hasActiveAdminAssignment`, keyed off an M8-resolved role id). A T-E22-class bug that makes M5 answer the wrong question and still let the gate pass now surfaces as a disagreement between the two mechanisms — `callerIsAdmin="false"` while `privileged="true"` — which is precisely what this alert's expression watches for. **Practical consequence for on-call, unchanged from before the fix:** still treat any firing as maximally anomalous and follow the first response step below — the fix makes the signal *reachable*, it does not make a firing routine. First response step, unchanged: query `auth_events` for whether the actor held an active `TENANT_ADMIN` assignment at that instant; if not, flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` and page Security.

**Every other alert this story adds** is fully specified in `docs/features/US-012/monitoring.md` §2 (`nexus_rbac_privileged_role_change_blocked_dangerous` — page; `nexus_rbac_privileged_role_change_blocked_byname` — ticket; `nexus_rbac_denial_throttle_engaged` — **page**, promoted from ticket per M-1 above; `nexus_rbac_privileged_revoke_lock_hold_slow` — ticket, with the histogram-bucket prerequisite noted there) and `docs/features/US-015/monitoring.md` §2 (`nexus_rbac_dangerous_permission_granted_to_holders` — ticket; `nexus_rbac_admin_privileged_self_assignment` — ticket, the demoted happy path). This document does not repeat those rows to avoid drift between three copies of the same expression; it points at the one place each lives.

**PRIORITY-lane exclusion note (§9.1, load-bearing, claimed for the first time in this story):** `ROLE_ASSIGNMENT_DENIED` is deliberately **excluded** from `AuthEventType.PRIORITY` (`identity/domain/AuthEventType.java:48-49`). This means a denial flood — including one the throttle has not yet caught up to suppressing — **cannot displace `ROLE_ASSIGNED`/`ROLE_REVOKED`** from the priority audit lane; it lands on STANDARD instead. This bounds part of T-D10 for free, without any code in this story. **Any future story that moves `ROLE_ASSIGNMENT_DENIED` into the PRIORITY lane must re-open T-D10 first** — re-run the flood-cost analysis against the priority lane's tighter capacity (200 vs. 800) before making that change.

---

## 3. Configuration — the denial throttle (D14)

| Property | Default | Rationale |
|---|---|---|
| `nexus.rbac.denial-throttle.max-denials` | **5** (`NEXUS_RBAC_DENIAL_THROTTLE_MAX_DENIALS`, `application.yml:149`) | A legitimate operator learns from the first 403; five in a window is already anomalous, low enough to bound a flood, high enough that a confused-but-honest helpdesk operator is not throttled mid-task. |
| `nexus.rbac.denial-throttle.window-seconds` | **60** (`NEXUS_RBAC_DENIAL_THROTTLE_WINDOW_SECONDS`, `application.yml:152`) | Matches `nexus.security.rate-limit.ip-window-seconds` (`application.yml:200`), so operators reason about one window length platform-wide. |

Values confirmed directly in `application.yml:148-152` and threaded through `RoleAssignmentService`'s constructor via `@Value` (`RoleAssignmentService.java:104-105`, `:112-113`). Setting `max-denials` to a very large value effectively disables the throttle; there is deliberately **no `enabled` flag** (D10 — a boolean whose "off" position removes a DoS bound would repeat the mistake D10 rejects for the two feature flags themselves).

**Bound is per replica, not cluster-wide, under the default store (M-3, `07-security-review.md`).** The figures above (5 denials / 60 s) are enforced by `RateLimitStore`, which defaults to `InMemoryRateLimitStore` (`nexus.security.rate-limit.store-type` unset). That store is per-JVM, so in an **N-replica deployment the effective bound is `max-denials × N` fully processed denials per window**, not the single-replica figure stated above — each of which costs a durable `auth_events` row, a `REQUIRES_NEW` connection borrow, and, on the revoke name-match path, M1's `FOR UPDATE` lock over every active `TENANT_ADMIN` row in the tenant. Setting `nexus.security.rate-limit.store-type=redis` makes the **denial count** cluster-wide, but the *throttled-until transition map* the adapter layers on top of `RateLimitStore` (RES-11) stays per-replica either way. Any multi-replica environment must either set `store-type=redis` or divide `max-denials` by the replica count to hold the single-replica bound this section documents.

---

## 4. Lock-hold baseline (§7.5, D18/RC-9.5)

**Published ceiling (design, not yet measured):**

| Figure | Value | Basis |
|---|---|---|
| Expected p99, `outcome="denied"` | < 50 ms | Four indexed statements plus one pooled-connection borrow on a non-hot path |
| Alert threshold (ticket, `nexus_rbac_privileged_revoke_lock_hold_slow`) | p99 > 250 ms over 10 m | 5× headroom over the expected p99 |
| Hard ceiling on a victim's wait | `innodb_lock_wait_timeout` = 50 s (MySQL default) | Not a mitigation — the ceiling on how long a legitimate admin's request can hang; D14's rate bound is the real control |

**⚠ MEASURED FIGURE — PENDING.** This section's own design requirement (§7.5, §10.3 step 2) is that the p50/p95/p99 of `nexus.rbac.privileged_revoke_lock_hold{outcome="denied"}` be **captured from an actual staging soak** and published here as the real baseline, replacing the "expected p99 < 50 ms" estimate above with a measured number. **That soak has not yet run** — flags are `false` in every environment but `dev`/`test` (§10.2), and Phase 8 (test-validate) has not started as of this task (T-022, 2026-09-16). Do not treat the "< 50 ms" figure above as measured; it is the design's pre-implementation estimate only.

**Action required before production rollout (§10.3 step 3's exit criterion depends on this):** run the staging soak per §10.3 step 2 — including the RC-11.2 acceptance scenario (deliberately exercising the Epic-3 bootstrap sequence to confirm the canary does *not* fire on it) and a scripted denial flood to confirm the throttle engages and self-clears — then replace this section with the measured p50/p95/p99 and re-validate the alert threshold above against real numbers. **Do not sign off Gate 2/rollout step 3 (`docs/features/US-016/03-design.md` §10.3) on the basis of this document alone until this section has been updated with real figures.**

**What *was* verified for this task, locally, not in staging (see §5 below for the SQL, run the same way):** the `nexus.rbac.privileged_revoke_lock_hold` timer's code path, tag set, and start/stop instrumentation were confirmed present and correctly wired by direct source inspection (`RoleAssignmentService.java:67-73`, `:306-309`, `:366-380`, `:389-397`) — what is missing is production-shaped *load*, not the instrumentation itself.

---

## 5. Exposure-audit SQL — validated locally, not against staging

The four statements from `03-design.md` §10.4 (reproduced in full in `docs/features/US-016/runbook.md` §5, which is the operational copy) were each executed once against a local MySQL 8.4 instance provisioned via this repo's `docker-compose.yml` (`mysql` service) with `V1`–`V5` migrations applied via the `flyway-migrate` pattern, using literal placeholder UUIDs in place of the `?` JDBC parameters. All four ran without SQL error (syntax, type, or join validity) against the shipped schema. This is **not** the staging soak the design's testing requirement asks for ("each SQL statement executed once against a staging database") — it confirms the statements are executable against the real shipped schema, not that they were run against an actual staging environment with real data. Flagged per this task's own risk #1 (writing from design intent instead of verified behaviour) rather than silently claimed as the staging run.

---

## 6. Pointers

- `docs/features/US-012/monitoring.md` — T-020 edits: `permission_denied`'s widened population, `nexus_rbac_role_change_denied_not_admin` (renamed/demoted), `privileged_role_change_blocked` + its two alerts, `denial_throttled` + its alert, `privileged_revoke_lock_hold` + its alert (and the histogram-bucket prerequisite gap), the two new log rows, `nexus_rbac_tenant_lockout_blocked`'s narrowed meaning.
- `docs/features/US-015/monitoring.md` — T-021 edits: `self_role_assignment`'s `privileged`/`callerIsAdmin` tags and the canary split (the alert this document's §2 restates), `dangerous_permission_granted`'s `holders` tag and its new alert, the new log row, the RC-7 panel group-by.
- `docs/features/US-016/03-design.md` §7.5, §9.1–§9.3, §10.3, §10.4, §12.3 — the design this document verifies against.
- `docs/adr/0017-privilege-based-role-assignment-gate.md` — the accepted decision record.
