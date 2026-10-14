---
name: feature-discovery
description: Use at the very start of any new feature or non-trivial change to Nexus, before designing or writing code. A reuse-first discovery procedure that surfaces what already exists, what's impacted, and the open questions to resolve at the requirements gate.
---

# Feature Discovery

Run this **before** design or implementation. Goal: understand the problem and the existing system well enough that the design phase has no surprises. Output feeds `docs/features/<FEATURE-ID>/01-requirements.md`.

## 1. Frame the problem
- Restate the requirement in one or two sentences. What user outcome, what business rule?
- Identify the **bounded context** it belongs to (existing or new — see `docs/ARCHITECTURE.md`).
- List explicit non-goals — what this change will *not* do.

## 2. Reuse-first survey (do not skip)
Before proposing anything new, search the codebase for what already exists:
- Grep for related domain terms, endpoints, entities, services, components.
- Check existing bounded contexts, `common/` utilities, `shared/` frontend types.
- Read relevant ADRs in `docs/adr/` — has this decision already been made?
- Note what can be **reused**, **extended**, or must be **created**. Prefer the first two.

## 3. Impact map
- Backend layers touched (domain / application / infrastructure / interfaces).
- Frontend features/components/services touched.
- **Data**: new tables/columns → Flyway migration (additive vs non-additive → expand/contract, ADR 0003).
- **API**: new/changed endpoints, versioning, breaking-change risk.
- Cross-context effects; upstream/downstream dependencies.

## 4. Non-functional & risk
- Security: authn/authz, PII, tenant isolation, new trust boundaries (flag for threat model).
- Scale & performance: expected RPS, data volume, N+1 risk, hot paths.
- Observability: what metrics/logs/audit events this feature must emit (`docs/observability-standards.md`).
- Feature-flag and rollout implications (`docs/deployment-process.md`).

## 4a. Design triggers
Design or algorithmic analysis is justified only where one of these fires. Record the result as `Design triggers:` in `01-requirements.md`:
- List each trigger that fires, with one line of evidence.
- If none fires, write `none`.

| # | Fires when the change involves… | Example in this codebase |
|---|---|---|
| T1 | Concurrent actors on the same state: DB rows, check-then-act, refresh across tabs, a shared in-flight request | Refresh-token rotation, lockout counter, registration, role cap |
| T2 | An invariant spanning several rows or tables | Last tenant administrator |
| T3 | A hot path: every request, or peak > 10 RPS | JWT filter, rate-limit filter, login |
| T4 | Unbounded growth: a table with no retention, an in-memory map keyed by user input, a queue | `refresh_tokens`, `InMemoryRateLimitStore`, audit retry buffer |
| T5 | New shared infrastructure or cross-instance state: cache, Redis, scheduler | Permission cache, rate-limit store |
| T6 | A transaction-boundary change, or I/O / CPU-heavy work inside a transaction | `REQUIRES_NEW` in `SecureEventService`, Argon2 in `LoginUseCase` |
| T7 | A staleness or revocation promise to users | Permission freshness, logout |
| T8 | One operation over more than ~10³ items, or a large lookup corpus | `user_roles` lock set, password denylist |
| T9 | Timing or account-enumeration sensitivity | Login, forgot-password |

**A trigger is not a mandate for heavy analysis.** It obliges the design (Phase 3, `critical-decisions` skill) to name, for each fired trigger, two things:
- the mechanism that keeps the guarantee;
- the test that proves it (`docs/TESTING.md` → *Tests that prove a guarantee*).

One line that cites an existing proven pattern is enough. Examples: the conditional UPDATE used by RBAC revoke, or the O(1) claim lookup used by the permission check.

**When nothing fires, no extra analysis is needed.** Typical cases: UI-only changes, simple reads, collections bounded by small caps, configuration, docs.

## 5. Open questions & assumptions
- List ambiguities that block design. Each becomes a clarification question at **Gate 1**.
- State assumptions explicitly so a reviewer can challenge them.

## Output
A requirements/discovery note covering: problem statement, domain/context, reuse findings, impact map, NFR/risk flags, and open questions. **Stop at the requirements gate** — do not design or code until it is approved.
