# US-018 pending items (backlog): M7 (P-1, P-2) and M5 (O-7, merge conditions, L-1, L-2)

**Recorded:** 2026-10-11. Open decisions from the pre-PR security re-review (`13-security-review-pre-PR-rereview.md`) that were not closed on branch `ccr-4e9e7cbe-4vl9v6`. They are tracked here for later; they do not block opening the M7 PR as a draft, but each is a decision needed before the M7 PR merges unless the PR author or approver explicitly defers it.

## P-1 RES-46: acceptance of the write-refusal residual (RR-M1)

- **What:** while Redis refuses writes but serves reads (`maxmemory` under `noeviction`, a slow bump, a read-only replica), a revoke or detach is enforced at once only on the instance that issued the bump. Tokens already issued stay valid on the other instances for up to 900 s (the access-token TTL), while every instance reports Healthy.
- **Already done:** a failed bump evicts the affected users' cached permission sets, so a detached permission cannot be re-minted (`FailedBumpCacheEvictionTest`). `bump_failed{reason=redis}` pages immediately.
- **Open decision, one of:**
  - Accept the residual. Owner: the author of the M7 PR (named 2026-10-09; Redis capacity input from SRE). Acceptance is **pending**; it is not recorded as accepted anywhere.
  - Build a per-instance write canary that moves write refusal under the 15-minute fail-open window. Cost: a Redis out-of-memory condition becomes a platform-wide 503 after 15 minutes. That is an availability decision for SRE and PM.
- **References:** `03b-threat-model.md` (RES-46), `13-security-review-pre-PR-rereview.md` (Resolution), ADR-0022 Revision 4.

## P-2 RR-M3: client IP handling behind the proxy (DF-1)

- **What:** `server.forward-headers-strategy: none`, with the repository's nginx in front, makes every per-IP limit (`REFRESH_IP`, `REFRESH_IP_FAIL`, the login limits) one shared bucket keyed on the proxy address. Existed before this branch; the branch only makes the setting explicit.
- **Open decision:** keep `none`, or switch to `native` with pinned `internal-proxies`. Owner: the DF-1 owner. Related: HSTS is absent from both nginx and the application, and `SECURITY.md` §9 is stale about nginx's CSP.
- **References:** `13-security-review-pre-PR-rereview.md` (RR-M3), `application.yml` comment on `server.forward-headers-strategy`.

## Not tracked here

By decision on 2026-10-11, the repeat `/security-review` and the Docker-only checks (ITs, e2e, the three k6 gates, OpenAPI export) are not tracked in this file. RR-L1 to RR-L3 remain in the re-review report.

---

# M5 (A7 break-glass CLI): merge conditions and open items

**Recorded:** 2026-10-15, from `07-security-review-M5.md` (APPROVED with conditions) and `08-test-audit-M5.md`. T-007 and T-008 are implemented, code-reviewed, security-reviewed and test-validated on `ccr-047fcb60-fqvz6w`; the M5 PR is not merged. The items below are what stands between that and a merge.

## Merge conditions

- **M5-C1 O-7 / security review M-1: owner decision.** A DISABLED sole administrator gets exit 5 (`TENANT_HAS_ADMIN`), so break-glass cannot recover that tenant and in-app recovery is blocked too. Owners: Architect + Platform Security Owner. Either (a) a named residual with an owner and a documented, audited manual procedure, or (b) define "administrator" as holders whose user is not DISABLED, consistently in the last-admin lockout, `RbacZeroActiveAdminsHealthIndicator` and A7 (read holder status under the lock, keep LOCKED holders counted, add an IT). Do not add a CLI override flag. **Not decided; must be recorded before the M5 PR merges.** Interim operator guidance (runbook 11.5): escalate, no manual SQL. `BreakGlassAdminIT.should_refuseWithExit5_when_theSoleAdministratorIsDisabled_pendingO7Decision` pins today's behaviour.
- **M5-C2 Kubernetes API audit logging (RC-37.3):** Ops sign-off that pod create and exec, with user identity, is logged and retained for at least 1 year.
- **M5-C3 Page-capture drill (RC-37.4):** a zero-admin tenant recovered in staging, with the page received from a Job run exactly as the runbook specifies (no `--rm`).
- **M5-C4 Daily reconciliation alert:** ticket-severity alert on new `ROLE_BREAK_GLASS_GRANT` rows live (backstop for a lost page). Also needs a decision on alerting an unpaged exit 1 (monitoring.md 7.1).
- **M5-C5 RES-6:** Ops retention sign-off for `RBAC_BREAK_GLASS_USED`.
- **M5-C6 CI dependency-check (A06):** OWASP dependency-check passes in CI (it could not run offline; the diff changes no `pom.xml`).
- Also on the `04-tasks.md` M5 checklist: zero-admin recovery demonstrated in an operational drill. The runbook-content item is written (runbook section 11, US-012 runbook step 4 note) and awaits review.

No environment exists (STATUS.md, decision 2026-10-05), so C2 to C5 can only be completed at the first deployment. Each therefore needs the PR author and approver to either defer it explicitly or hold the merge.

## Open, optional

- **L-1:** the refusal page is not best effort; if `BreakGlassAlertPort.alert` threw, the specific refusal exit code would be hidden behind exit 1. Fix: wrap it like the GRANTED page (`RBAC_BREAK_GLASS_ALERT_FAILED`), or record the asymmetry in the Javadoc and design 7.1. Very low probability (the only implementation is a Logback call).
- **L-2:** the target's ACTIVE check is outside the grant transaction (TOCTOU). Accept and note in design 7.1, or re-read the status under the lock and refuse `TARGET_USER_NOT_ACTIVE`; do it as part of M5-C1 option (b).
- Closed since the security review: L-3 (global lookup port and query are now ArchUnit-contained, `08-test-audit-M5.md`).

