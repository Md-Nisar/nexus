# System Design & DSA in the Nexus Operating Model — Recommendation

**Status:** Approved (2026-10-14) · **Basis:** [2026-10-14 review](./2026-10-14-review.md) of US-001..US-018 at `main` @ `19f4c7c`

**Goal:** apply the right engineering discipline at the right time. This document does not require system-design or DSA analysis, or new agent skills, on every epic or story.

---

## 1. Current-state assessment

### The process is already heavy

| What | Size |
|---|---|
| Feature documents (18 story folders) | About 53,000 lines |
| Production Java | About 14,000 lines |
| US-018 alone | 20 files, 6,842 lines |
| US-016 `03-design.md` | 1,272 lines |
| ADRs | 25 |
| Epic files | 3 files, about 2,900 lines, each with its own architecture section |

### Most of the needed pieces already exist

- `/new-feature` has three approval gates and a high/low risk tier.
- The architect agent covers database design, caching and performance impact.
- The code-reviewer agent checks concurrency, scalability and indexes.
- The requirements template asks for RPS, p95 latency and whether the feature is on a hot path (`docs/features/_TEMPLATE/01-requirements.md:30-31`).
- `/implement` switches to opus for tasks involving locking or concurrency.
- `spring-boot-standards` already says to keep external calls out of transactions (`:70`) and to set SMTP timeouts (`:122`).
- The engineer and QA agents load the standards skills automatically through their frontmatter.

### Why serious defects still shipped

| Gap | Evidence |
|---|---|
| Design claims were never checked against code or tests | `docs/features/US-004/03-design.md:295-297` says the grace window (AC-3) is satisfied, but no grace window exists in the code. ADR 0009:51 calls the cost of a second connection "negligible", which stops being true once virtual threads are enabled. US-006's design defines a 15-minute window (`:105`) that the code never uses. EPIC-002 `[ARC]` says role changes take effect "within 7 days", which does not match the 14-day refresh token or the 15-minute cache. |
| Framework pitfalls are not written down anywhere | Most defects come from how JPA flushes and versions entities, how Redis handles multiple commands, and how Angular runs guards and caches `computed` values. They are not algorithmic. A reviewer who only reads the diff will miss them. |
| Standards were not applied to code written before them | The resilience standards were added on 2026-09-28 (`61a9636`). The SMTP adapter was last changed on 2026-08-12 and still has no timeouts. |
| Tests pass without proving anything | One integration test accepts any exception. The lockout "concurrency" test uses only mocks. The audit-outage test injects its fault at the wrong layer. The QA guidance only says "Concurrent access (where relevant)". |
| Cross-story definitions were decided one story at a time | "Administrator" has four different definitions across US-016, US-017 and US-018. Capacity and revocation were never decided for the epic as a whole. |
| No feedback loop | None of the 18 feature folders has a `retrospective.md`. |

Over-engineering has the same cause: no step ever asks "what is the simplest mechanism that keeps the guarantee?" That is how the permission cache, success-path audits running in their own transactions, and the ADR-0022 state machine all came in.

---

## 2. Whether and where these practices add value

**Verdict:** yes, but only in a targeted way. Focus on the few decisions the review found to be defect-prone, require a test that proves each one, and write fewer pages overall.

### Epic level

Add these decisions to the epic's existing `[ARC]` / architecture section:

| Decision | Evidence from this repo |
|---|---|
| Shared definitions and invariants | Four different "admin" definitions |
| How stale data may be, and how revocation works | The "7 days" and "≈30 min" claims; revoking individual token IDs (jti) versus revoking everything for a user |
| Capacity model: connections per request, CPU-heavy work, concurrency limits | Virtual threads combined with a 10-connection pool and `REQUIRES_NEW` |
| Shared infrastructure and state shared across instances | The permission cache; the in-memory rate-limit store used in production |
| Data growth and retention | The token tables are never purged |
| Session and tenancy model | Two tabs refreshing at the same time; one refresh cookie per browser in EPIC-003 |

### Story level (only when a trigger fires)

- The mechanism that keeps the invariant: an atomic conditional `UPDATE`, a locking read, a tenant lock, or a unique constraint.
- The indexes and size bounds that the story's own queries and collections need.
- An algorithm choice, but only when the data sizes are actually large.

### Implementation level

- Placement details where framework behaviour matters: `flush()` inside the `try`, `catchError` before `switchMap`, Argon2 outside the transaction.
- Size limits on local data structures.
- Escalating to design when a trigger appears that the design did not plan for.

### When no analysis is needed

No analysis is needed when no trigger fires, or when a trigger fires and one line citing an already-proven pattern answers it.

| Example | Why no analysis is needed |
|---|---|
| US-011 permission check | It is on the hot path, but it is an O(1) set lookup on JWT claims |
| US-013 `Array.includes` over about 8 permissions | The list is tiny; DSA adds nothing |
| US-018 M1 endpoint classification | Enforced when the code is built |
| JWKS endpoint and `/users/me` | Simple reads |
| Role lists | Capped at 500 roles |
| UI-only changes, lint/ArchUnit rules, configuration, documentation | No runtime decision is being made |

Also not justified here:
- A token bucket instead of the sliding log for login limits.
- ShedLock, while every scheduled job is per-node.
- Microservices, CQRS or event sourcing.

---

## 3. Operating model and decision criteria

### Design triggers

Phase 0 records which triggers fire. Each trigger that fires needs one row in the critical-decisions table.

| # | Trigger | Examples from this repo |
|---|---|---|
| T1 | Several actors changing the same state at once: DB rows, check-then-act logic, refresh from several tabs, shared in-flight requests | Refresh rotation, lockout counter, registration, role cap, frontend refresh |
| T2 | An invariant that spans several rows or tables | Last admin; the tenant on a `user_roles` row matching the role's tenant |
| T3 | Hot path: runs on every request, or above 10 RPS (already in the template) | JWT filter, rate-limit filter, login |
| T4 | Unbounded growth: tables, in-memory maps keyed by user input, queues | `refresh_tokens`, rate-limit store, retry buffer |
| T5 | New shared infrastructure, or state shared across instances | Redis cache, rate-limit store, schedulers |
| T6 | A transaction boundary changes, or I/O or CPU-heavy work runs inside a transaction | `SecureEventService`, Argon2 inside `LoginUseCase` |
| T7 | A promise about staleness or revocation | Permission freshness, logout |
| T8 | One operation touches more than about 10³ items, or looks up a large data set | The `user_roles` lock set, the password denylist |
| T9 | Timing or enumeration sensitivity | Login, forgot-password |

How triggers relate to existing rules:
- They are separate from the existing risk tier, which stays unchanged.
- When T1, T2 or T6 fires, `/implement` switches to opus. This matches the existing escalation for locking and concurrency.
- When T1, T2 or T6 fires, the story is excluded from `/autonomous-feature`. This matches the existing exclusion of lockout and data-integrity work.

### Critical-decisions table

The table lives in `03-design.md` and replaces design prose. Example row:

| Invariant | Mechanism | Why it is the simplest that works | Rejected alternative | Proof test and exact assertion |
|---|---|---|---|---|
| A refresh token rotates at most once, and a revoked token never rotates | `UPDATE … WHERE id=? AND revoked_at IS NULL`; 0 rows → `AUTH_004` | A single statement | `@Version` with `save()`: the conflict only appears at commit, outside the catch | `concurrentRotation_exactlyOneSucceeds_loserGets401_noSuccessAudit` |

- A one-line row that cites an existing pattern is acceptable.
- If no trigger fires, the design says so in one line.

### Workflow integration

There are no new phases, gates or meetings.

| Phase | What changes |
|---|---|
| Epic discovery | Fill in the epic checklist inside the existing `[ARC]` section, about one page. It is reviewed at the epic's first Gate 2. |
| 0 Discovery | Add a `Design triggers:` line to `01-requirements.md`. |
| 3 Design | Add the critical-decisions table. |
| 4 Breakdown | Add a third traceability table (decision → proof test → task) next to the existing threat → task and AC → task tables. |
| 5 Implement | Engineers follow the pitfall lists. If they hit a trigger the design did not plan for, they stop and escalate. |
| 6 Review | The code reviewer checks each row against the code and its proof test, and asks whether a simpler mechanism would work. |
| 8 Test validation | Reject proof tests that assert nothing specific. |
| 11 Retro | Make it short and required. Each lesson becomes one pitfall line or one trigger change. |
| ADRs | Only for epic-level or cross-story decisions. Each new ADR states its assumptions and when it should be revisited. |

### Responsibilities

| Role | Responsible for |
|---|---|
| Architect | The epic checklist and the critical-decisions table |
| Security reviewer | Unchanged, plus the T9 rows |
| Engineers | Following the pitfall lists and escalating unplanned triggers |
| Code reviewer | Checking invariants and simplicity |
| QA | The quality of proof tests |
| Humans | The existing gates only |

---

## 4. Skills and supporting documentation

### One new skill: `critical-decisions`

**Purpose:** decide *when* design or DSA analysis is needed, and record it in the smallest form that can be checked.

**Modes:**

| Mode | When it runs | Who uses it | Where the output goes |
|---|---|---|---|
| Epic | Once at epic discovery, and again whenever a story changes an epic invariant | Architect | The existing `[ARC]` section |
| Story | `feature-discovery` evaluates the triggers. In Phase 3 the architect fills the table, only if a trigger fired. In Phase 5 engineers consult it when they hit a trigger the design did not plan for. | Architect, engineers | `03-design.md` |

**Files:**

- `SKILL.md` (about 80 lines): the triggers, the table format, the "no analysis needed" rule with repo examples, and the simplest-that-works rule.
- `references/epic-checklist.md`: shared definitions, staleness limits, capacity model, shared infrastructure, growth and retention, assumptions about running multiple instances, session and tenancy.
- `references/concurrency-patterns.md`:
  - Conditional `UPDATE` with a row-count check (proven in the RBAC revoke).
  - `flush()` inside the `try` (proven in `VerifyEmailUseCase.java:85`).
  - A unique constraint as the guard, with `saveAndFlush` (proven by `active_key`).
  - What locking reads actually lock under REPEATABLE READ.
  - A per-tenant lock row.
  - Write skew.
- `references/data-structure-choices.md`:
  - Rate limiting: a sliding log for limits up to about 100; a sliding-window counter or GCRA above that.
  - Revocation: a per-user watermark instead of a denylist of individual token IDs (jti).
  - Large lookups: move from `HashSet` to a sorted `long[]` to a Bloom filter as the data grows.
  - Subset and set-difference checks: `HashSet`.
  - Do not optimise below about 10³ items.
- `references/capacity-model.md`: a worked example of sizing the connection pool with virtual threads, limits on CPU-heavy work, and timeouts on paths that fail open.

**Deliberately not added:**
- A standalone DSA skill: it would rarely be used and would go stale.
- A design-review agent or meeting: Gate 2 already does this.
- A separate epic-architecture command.

### Changes to existing assets

| Asset | Change |
|---|---|
| `spring-boot-standards` | Add a "Pitfalls" section of about 15 lines, each with a repo example. It reaches the engineers and QA automatically through their frontmatter. |
| `angular-standards` | Add about 5 pitfall lines. Leave the vendored `angular-developer` skill alone, since it is pinned by hash. |
| `feature-discovery`, `_TEMPLATE/01-requirements.md` | Add the `Design triggers:` field, reusing the existing non-functional requirement fields. |
| `architect.md` | Load `critical-decisions`. Add the anti-pattern "claiming a requirement is satisfied without naming its proof test". Ask for short designs when no trigger fires. |
| `/design`, `/breakdown` | Add the critical-decisions table and the decision → proof test → task table. |
| `/autonomous-feature` | The Gate 2 and Gate 3 conditions include a complete table. Exclude stories where T1, T2 or T6 fires. |
| `code-reviewer.md` | Add steps that check invariants and simplicity. |
| `qa-engineer.md`, `/test-validate` | Add concrete rules for rejecting weak proof tests. |
| `docs/ARCHITECTURE.md` → "When to write an ADR" | Require an "Assumptions / revisit when" section in new ADRs. ADR 0001 stays untouched because accepted ADRs are append-only. |
| `docs/DEVELOPMENT_GUIDE.md`, `.claude/README.md` | Describe the trigger step, the table and the third traceability table. The guide is the single source of truth. |
| `/retro` | Add a step that turns each lesson into a pitfall line or a trigger change. |

---

## 5. Adoption plan

| Priority | Work | Size | Benefit |
|---|---|---|---|
| P1 (now) | Pitfall sections; rules for rejecting weak proof tests in QA and review; the `Design triggers` field | S | Catches the defect classes behind the refresh, lockout, audit-rollback and frontend bugs during implementation and review, which is the cheapest point to catch them |
| P2 (before US-019) | The `critical-decisions` skill in story mode, with its references; updates to the architect, `/design`, `/breakdown`, `/autonomous-feature` and `DEVELOPMENT_GUIDE` | M | Every claim about concurrency or growth gets a test that proves it; new infrastructure needs a stated justification |
| P3 (before US-019/020 and EPIC-003) | Epic mode applied to EPIC-002 `[ARC]`: one admin predicate, a correct staleness claim, a tenant lock. Applied to EPIC-003 §3: tenant rate-limit algorithm, cookie scoping, tenant-status cache, capacity. Retrofit the EPIC-001 capacity and transaction model. | M | Unblocks US-019 B4. Keeps EPIC-003 from basing per-tenant rate limits on a data structure whose memory grows with each tenant's limit. |
| P4 (ongoing) | "Revisit when" sections in ADRs; short required retros | S | Assumptions like the one in ADR 0009 get re-checked when the platform changes |

### How to tell whether it is working

- Escaped defects in the trigger categories should trend toward zero.
- Design lines per story should **go down**.
- Cycle time should not go up.
- Watch the share of stories where no trigger fires. Expect it to be low for auth/RBAC-style work and higher for EPIC-003 profile and member-list stories.

### Guardrail

Treat these as signs of process drift, and trim them at the gate:
- A story with no fired triggers grows a critical-decisions table.
- An epic checklist runs longer than about one page.
