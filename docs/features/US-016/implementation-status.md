# US-016 — Implementation status

Moved verbatim from `docs/story/2-rbac/EPIC-002.md` on 2026-10-18 (US-018 M11, D1). The epic keeps a one-line summary and a link here.

### Implementation Status (2026-09-16)
Gate 2 (`docs/features/US-016/03-design.md`, `03b-threat-model.md` — conditional pass, all required changes discharged per design §14) and Gate 3 (`docs/features/US-016/04-tasks.md`, 23 tasks) are both complete and approved. All 18 code tasks (T-001–T-018) and the four documentation tasks (T-019 ADR-0017, T-020 US-012 monitoring amendment, T-021 US-015 monitoring/threat-model correction, T-022 US-016 `monitoring.md`/`runbook.md`) are implemented, independently re-verified against the shipped code, and reported.

**Closure is partial, not full — recorded precisely so this entry is never misread as "R-3 resolved":**
- **T-E9 / T-E17 (revoke-side admin stripping): closed outright.** `revoke()` now carries the identical privilege-based gate as `assign()`.
- **T-E16 (propagate-side self-escalation via `assign()`): closed for the direct propagate path only.** The attach-after-assign sequence (self-assign a benign custom role, then have an administrator later attach a dangerous permission to it) is **not** covered by this gate — no race, no collusion, no gate evaluation applies to that sequence, by design — and survives as **US-016 RES-1(b) / T-E21**, mitigated (not closed) by D13's holder-count detective signal (`docs/features/US-016/03-design.md` §4.7, §12.3).
- RES-1(b) carries forward US-015's original owner (Md Nisar Ahmed), the 2026-11-27 review date, and the Epic-3-kickoff hard expiry, unchanged.

**Outstanding before this story is fully landed:** Phase 8 (`/test-validate`) has not yet run. The staging soak that produces the measured p50/p95/p99 lock-hold baseline (`docs/features/US-016/monitoring.md` §4, currently marked `⚠ PENDING`) and the staging execution of the exposure-audit SQL (`runbook.md` §6, currently validated only against a local Docker/Flyway MySQL instance, explicitly labeled as such) are both still pending. `/review`, `/security-review`, `/test-validate`, and `/pre-pr-check` have not yet been run.
