# US-018 pending items (backlog): M7 (P-1, P-2: both decided 2026-10-18, see 18-closure-record.md) and M5 (merge conditions; O-7, L-1, L-2 closed)

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

**Recorded:** 2026-10-15 (M5 merged as PR #91 on 2026-10-16), from `07-security-review-M5.md` (APPROVED with conditions) and `08-test-audit-M5.md`. T-007 and T-008 are implemented, code-reviewed, security-reviewed and test-validated on `ccr-047fcb60-fqvz6w`; the M5 PR is not merged. The items below are what stands between that and a merge.

## Merge conditions

- **M5-C1 O-7 / security review M-1: CLOSED 2026-10-15 (decision by the user).** For break-glass only, an administrator holder whose user is DISABLED does not count, so a tenant whose only administrators are DISABLED is recoverable by the CLI (grants `TENANT_ADMIN`, exit 0). LOCKED holders still count (a lockout recovers by itself), as do ACTIVE and PENDING ones. The statuses are read under the set lock, in the grant transaction (one `FOR SHARE` statement on the `users` rows). Scoped to A7: the last-admin lockout, the assign and revoke guards and `RbacZeroActiveAdminsHealthIndicator` are unchanged. No CLI override flag. Recorded in ADR-0025 Revision 5, `03-design.md` §7 and runbook 11.5. Tests: `BreakGlassAdminIT.should_grantExit0_writeSuccessRow_andPage_when_theSoleAdministratorIsDisabled` (replaces the characterization IT `..._pendingO7Decision`), `..._when_theSoleAdministratorIsLocked` (exit 5, kept), `..._when_oneAdministratorIsDisabledAndAnotherIsActive` (exit 5), `..._when_theDisabledSoleAdministratorIsReEnabledConcurrently` (exit 5, locking read), and unit tests in `BootstrapAdminServiceTest`.
- **M5-C2 Kubernetes API audit logging (RC-37.3):** Ops sign-off that pod create and exec, with user identity, is logged and retained for at least 1 year.
- **M5-C3 Page-capture drill (RC-37.4):** a zero-admin tenant recovered in staging, with the page received from a Job run exactly as the runbook specifies (no `--rm`).
- **M5-C4 Daily reconciliation alert:** ticket-severity alert on new `ROLE_BREAK_GLASS_GRANT` rows live (backstop for a lost page). Also needs a decision on alerting an unpaged exit 1 (monitoring.md 7.1).
- **M5-C5 RES-6:** Ops retention sign-off for `RBAC_BREAK_GLASS_USED`.
- **M5-C6 CI dependency-check (A06):** OWASP dependency-check passes in CI (it could not run offline; the diff changes no `pom.xml`).
- Also on the `04-tasks.md` M5 checklist: zero-admin recovery demonstrated in an operational drill. The runbook-content item is written (runbook section 11, US-012 runbook step 4 note) and awaits review.

No environment exists (STATUS.md, decision 2026-10-05), so C2 to C5 can only be completed at the first deployment. Each therefore needs the PR author and approver to either defer it explicitly or hold the merge.

## Closed since the security review

- **L-1: CLOSED 2026-10-15.** A throwing refusal page is now best effort, like the GRANTED page: ERROR `RBAC_BREAK_GLASS_ALERT_FAILED` (tenant and reason, no argument value), and the refusal keeps its own exit code. Unit test over every refusal reason in `BootstrapAdminServiceTest`.
- **L-2: CLOSED 2026-10-15.** The target's ACTIVE check is repeated inside the grant transaction, after the set lock, on the same locking read as O-7; a target disabled concurrently is refused (exit 3). IT `BreakGlassAdminIT.should_refuseWithExit3_andGrantNothing_when_theTargetIsDisabledConcurrently` and unit tests.
- **L-3:** global lookup port and query are now ArchUnit-contained (`08-test-audit-M5.md`).
