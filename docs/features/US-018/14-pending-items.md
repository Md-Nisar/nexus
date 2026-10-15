# US-018: pending items (backlog)

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

## M5 break-glass: items deferred to the first deployment

**Recorded:** 2026-10-15. **Owner of all five:** the US-018 story owner. They need a real environment, which does not exist yet (Decision 2026-10-05), so they are not merge-blocking for M5; each stays **required before any production traffic**. Runbook: `runbook.md` §11. Decided on 2026-10-15 and already in the runbook: the second approver is the Platform Security on-call engineer, the Job keeps `ttlSecondsAfterFinished: 3600`, and the log-flush wait stays at 15 s.

- **P-3 RC-37.3: Kubernetes API audit logging.** Ops names the audit-log location and confirms pod create and exec are logged with user identity and retained for at least 1 year (`runbook.md` §11.2 step 6).
- **P-4 Log-shipper flush interval.** SRE states the node log shipper's flush interval and confirms the 15 s `nexus.rbac.break-glass.log-flush-interval` default is at least that (§11.3).
- **P-5 Page routing and RES-6.** Name the alert channel and the on-call rota that receive `RBAC_BREAK_GLASS_USED`, and Ops signs off its log retention (RES-6) (§11.3).
- **P-6 Daily reconciliation alert.** Choose the alerting platform, write the alert rule on new `ROLE_BREAK_GLASS_GRANT` rows, and name who reviews it each day (§11.6).
- **P-7 RC-37.4 staging drill.** Recover a zero-administrator tenant from a Job run exactly as §11.3 specifies, receive the page, and record the result and date in §11.7. This also proves the command override and the "no `--rm`" rule.

## Not tracked here

By decision on 2026-10-11, the repeat `/security-review` and the Docker-only checks (ITs, e2e, the three k6 gates, OpenAPI export) are not tracked in this file. RR-L1 to RR-L3 remain in the re-review report.
