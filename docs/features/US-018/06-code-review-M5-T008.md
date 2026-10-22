# Code review: US-018 M5 / T-008 (commit d5b50c8, parent 4dee024)

**Verdict: APPROVE WITH NITS.** 0 Blocker, 0 High, 0 Medium, 3 Low, 3 Nit.

Tests run by the reviewer: 117 unit/architecture tests, 0 failures; `BreakGlassAdminIT` 17/17; `SecurityConfigWebTest` 18 and `RequiresPermissionWebTest` 10 pass with `@ConditionalOnWebApplication(SERVLET)`.

## Confirmed sound
- Runner exit codes 0-7 pinned in `BreakGlassRefusalReason`; `exitCode` starts at 1; flush wait in `finally`; strict argument parsing; no argument echo on INVALID_ARGUMENT (L-6).
- Web-context guard checks the actual context type and fails before the connector binds.
- `TransactionTemplate` orchestration; `PessimisticLockingFailureException` -> exit 7 (proved with a SIGNAL 1213 trigger); other RuntimeException -> exit 1 after rollback.
- Replay lookup uses a bound parameter (no injection), exact case-sensitive match, bounded by the `event_type` index, no lock, global by design. Allowlist entry justified; needs security-reviewer sign-off.
- `@ConditionalOnWebApplication(SERVLET)`: no risk of security being silently off in the serving app, `@SpringBootTest` or `@WebMvcTest` contexts.

## Findings

**[Low 1] Catch-all also covers post-commit and post-refusal failures** - `BootstrapAdminService.java:114-131` (with 155, 168, 178).
`execute(...)` also covers the commit, the `afterCommit` GRANTED alert and refusals already written in the callback. (a) A failure after a successful commit writes an UNEXPECTED_ERROR FAILURE row, pages and exits 1 although the grant is committed; contradicts the Javadoc "A refusal never follows a committed SUCCESS write". (b) A TENANT_HAS_ADMIN refusal followed by a failed commit gives two FAILURE rows and pages, exit 1 instead of 5.
Fix: make the callback side-effect-free (return the outcome), then audit/page after `execute` returns; the GRANTED alert is then post-commit by construction, and `runAfterCommit` and the Hikari >= 2 reason disappear. Otherwise soften the two Javadoc claims and add a runbook line: "exit 1: verify `user_roles` / `auth_events` before re-running".

**[Low 2] Web-context guard pages without the flush wait (RC-37.4)** - `BreakGlassAdminRunner.java:85-95`.
`afterPropertiesSet` logs `RBAC_BREAK_GLASS_USED {reason=WEB_CONTEXT}` and throws with no capture window. Fix: call `waitForLogFlush()` before the throw (+ unit test with 50 ms wait), or record in design §7.2 that this page relies on crash-loop log retention.

**[Low 3] Exit 1 is ambiguous (audited+paged vs. crashed before/outside the grant)** - `BreakGlassRefusalReason.java:4-11`, design §7.1. The unpaged branch is not covered by the daily reconciliation (SUCCESS rows only). Fix: runbook line "exit 1 with no `RBAC_BREAK_GLASS_USED` in the pod log: page Platform Security manually", or use a distinct code for UNEXPECTED_ERROR.

**[Nit 1]** `BreakGlassAdminIT.java:596-597`: race IT `noneSatisfy` checks `RBAC_AUDIT_WRITE_FAILED` only; also add `RBAC_AUDIT_WRITE_LOST` (loser's Group B refusal).

**[Nit 2]** `BreakGlassAdminRunner.java:61,105`: reset `exitCode = UNEXPECTED_ERROR.exitCode()` at the start of `run()` (reused instance in `BreakGlassAdminRunnerTest`).

**[Nit 3]** `BreakGlassAdminIT.java`: fixed change refs (`ABC-1`, `OPS-100`..`OPS-108`) make a rerun against a reused container return exit 6 now that the lookup is global. Use `freshChangeRef()`; randomise the prefix of the padded `ABC-1`/`ABC-0001` pair.
