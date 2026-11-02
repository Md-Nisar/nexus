---
name: test-audit
description: >
  Repository-wide and module-scoped test-suite auditing, test-quality hardening,
  flakiness investigation, cross-boundary isolation verification, and
  mutation-informed refinement. Detects weak oracles, mock tautologies,
  persistence-boundary gaps, tenant/authz leakage risks, and high-impact
  coverage gaps across supported languages and frameworks without changing
  production behavior.
version: 1.0.0
triggers:
  - "audit tests"
  - "test-audit"
  - "refine tests"
  - "fix flaky tests"
  - "review test quality"
  - "test suite audit"
  - "test quality review"
---

# `test-audit`: Principal-Grade Test Suite Audit & Refinement Skill

## 1. Mission and Operating Contract

Evaluate whether a test suite detects meaningful defects, protects observable contracts, remains deterministic, and verifies important boundaries. When explicitly requested, improve tests in small, reviewable batches while preserving production code and all pre-existing user changes.

This skill evaluates test quality. It does **not** treat line coverage, assertion count, or a passing test run as sufficient evidence of correctness.

### 1.1 Operating modes

Choose the mode from the user's explicit intent. **If the user does not explicitly authorize changes, default to `AUDIT`.** A request to review, assess, inspect, explain, or score tests is read-only even when it names a single file.

1. **`AUDIT` — Read-only diagnostic (default):** Execute the safe preflight, baseline tests when safe, and Phases 1–4. Do not create, edit, delete, format, move, or rename files. Produce the Deterministic Audit Report. A reported production defect is documented with evidence and a proposed regression-test shape; no test file is created in this mode.
2. **`REFINE` — Test-only changes:** Use only when the user explicitly asks to fix, improve, refactor, or harden tests. Execute Phases 1–5 in batches of 1–3 test files. Modify test code and test-only configuration only when necessary and in scope. Never modify production source code. Preserve all unrelated user work.
3. **`DIFF` — Pull-request / working-tree gate:** Use only when the user explicitly requests a diff, PR, or uncommitted-changes audit. Execute a reduced Phase 1 preflight, then Phases 2–5 strictly against changed files and their directly affected tests. Include staged, unstaged, and untracked changes in scope discovery. In `DIFF`, test edits are permitted only when the user explicitly asks to fix or remediate the diff; otherwise behave as read-only `AUDIT` on the diff.

**Mode precedence:** explicit mode named by the user > clearly requested action (review vs. modify) > `AUDIT`. Do not infer permission to edit from the fact that a request names one file or module.

### 1.2 Scope and evidence rules

- State the exact repository, module, test paths, and production paths in scope.
- Distinguish observed defects from plausible risks and from missing evidence.
- Every finding must include evidence: file and line, relevant test or production behavior, and why it matters.
- Do not claim a test is flaky, a production bug is confirmed, or a mutation is killed without execution evidence supporting that claim.
- If a command, plugin, runner feature, database, or external dependency is unavailable, report the limitation rather than silently substituting an unsupported command.
- Do not invent test counts, coverage percentages, line numbers, mutation results, or execution outcomes.

---

## 2. Non-Negotiable Invariants

1. **Production-code immutability.** Never edit production source code to make tests pass or to make it easier to test. If a test exposes a likely production defect, report it and preserve the production code. A production fix requires a separate, explicit user request and is outside this skill's normal refinement scope.
2. **Public contracts first.** Test observable behavior: returned values, externally visible state changes, emitted events, persisted effects, API responses, and documented errors. Do not invoke private methods or assert on hidden implementation details unless a narrowly justified legacy constraint is documented.
3. **State verification over interaction mocking.** Prefer real domain objects, contract-verified fakes, and realistic boundaries. Mock only genuine external or nondeterministic boundaries when needed (for example, third-party HTTP, clocks, randomness, or external brokers). Do not mock the SUT or pure value objects.
4. **Fake-drift guardrail.** Do not introduce an ad-hoc in-memory fake for a stateful repository or adapter unless it is backed by a shared contract test or faithfully enforces the relevant production semantics (uniqueness, filtering, ordering, pagination, transactions, and concurrency where applicable). Prefer test data builders and production-like integration resources when persistence behavior is the subject of the test.
5. **Readable tests, not mechanical bans.** Favor explicit Arrange–Act–Assert structure and self-contained behavioral examples. Flag control flow inside a test only when it obscures the scenario or weakens the oracle. Do not automatically reject loops, `try/catch`, property-based tests, parameterized tests, concurrency harnesses, or callback assertions when they are the clearest correct expression of the behavior.
6. **Empirical execution proof.** Never claim that a refinement is verified without running the relevant test runner and reporting the exact commands and outcomes. Passing tests alone do not prove fault sensitivity.
7. **Preserve user work.** Never use destructive Git commands (`reset --hard`, `clean`, `checkout` over user files, force restore, or equivalent). Never overwrite, discard, stash, or reformat unrelated pre-existing changes. Capture the initial Git state and compare it after refinement.
8. **Safe test execution.** Before running tests, inspect scripts, configuration, environment assumptions, fixtures, and setup/teardown for destructive actions or live integrations. Do not run tests against production services, real customer data, shared environments, or externally billable services. Do not execute migrations, destructive cleanup, deployment, or infrastructure commands as part of an audit.
9. **No hidden dependency installation.** Do not install packages, plugins, containers, services, or global tools without explicit authorization. Detect what is already available and report optional tooling that is missing.
10. **Honest defect handling.** A disabled test is not an executed regression test. Do not describe `@Disabled`, `it.skip`, or an unconditional skip as proof that a defect is reproduced or guarded against.

### 2.1 Production defect and regression-test policy

- In `AUDIT`, document the suspected/confirmed defect, evidence, impact, and a precise regression scenario. Do not modify files.
- In `REFINE`, do not change production code. Add a regression test only when it can be done safely within the requested test scope.
- If a production defect makes the new test fail, report it as a **known failing regression test**, distinguish it from failures introduced by the refinement, and do not claim a 100% pass rate.
- Use a framework-native expected-failure facility only when its semantics are understood and verified. For example, `pytest.mark.xfail(strict=True)` can make an unexpected pass visible; it is not equivalent to a skipped test. Do not assume every framework has an equivalent feature.
- Where no reliable expected-failure mechanism exists, prefer documenting the test case or placing a clearly labelled regression test in an explicitly opt-in suite over silently disabling it. Explain that the defect remains unfixed.
- Do not add `@Disabled`, `.skip()`, or equivalent merely to make the suite green.

---

## 3. Execution Workflow

## Phase 0: Safety and Repository-State Preflight

Perform this phase before executing test commands or making changes.

1. **Identify repository root and user intent.** Confirm the requested mode and the intended scope. Do not expand into unrelated packages merely because they are easy to discover.
2. **Capture the initial working-tree state.** Record:
   - `git status --short --branch`;
   - staged diff summary and names (`git diff --cached --stat`, `git diff --cached --name-only`);
   - unstaged diff summary and names (`git diff --stat`, `git diff --name-only`);
   - untracked paths (`git ls-files --others --exclude-standard`).
   If Git is unavailable, state that a reliable before/after integrity comparison cannot be performed.
3. **Inspect execution safety.** Review package scripts, Makefile targets, build tasks, test configuration, environment variables (names only; never print secret values), fixtures, hooks, and setup/teardown for:
   - live API or production database URLs;
   - destructive database reset, truncate, delete, migration, or cleanup operations;
   - shared message brokers, queues, buckets, caches, ports, or filesystem paths;
   - external billing, email, SMS, deployment, or cloud side effects;
   - reliance on real credentials or customer data.
4. **Set a safe execution boundary.** Run only commands that are reasonably isolated and non-destructive. If safety cannot be established, do static analysis only and explain why tests were not run. Do not ask the user to expose secrets; request safe test configuration only when essential.
5. **Protect dirty worktrees.** If user changes overlap the target files, do not rewrite or reset those files. Make the smallest possible patch and verify it against the captured baseline. If a mutation tool cannot guarantee preservation, do not run it on the live worktree.

## Phase 1: Fast CLI Triage and Baseline Inventory

Avoid reading dozens of files blindly. Use targeted discovery to rank likely risks before opening source files.

### 1. Detect stack, test runners, and tooling

Inspect the relevant manifests and CI configuration, such as `package.json`, lockfiles, `pyproject.toml`, `pytest.ini`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`, `Makefile`, and workflow files. Identify the actual configured runner and version. Do not assume Jest when the project uses Vitest, or assume optional plugins are installed.

If stack-specific reference files exist under `references/`, load only the matching reference.

### 2. Correlate high-churn production paths with tests

When Git history is available, identify frequently changed production files over the last six months:

```bash
git log --format=format: --name-only --since="6 months ago" |
  sort | uniq -c | sort -nr | head -n 30
```

Treat this as a prioritization signal, not proof that a file is risky. Confirm whether relevant tests exist and whether the tests exercise the changed public behavior.

### 3. Run targeted smell discovery

Use `rg` when available; otherwise use an equivalent repository search tool. Scope searches to test directories and exclude generated/vendor output.

- Hard-coded sleeps and waits:
  ```bash
  rg -n '(Thread\.sleep|time\.sleep|setTimeout|waitForTimeout|asyncio\.sleep)' <test_dir>
  ```
- Skipped/ignored tests:
  ```bash
  rg -n '(@Disabled|@Ignore|pytest\.mark\.skip|\.skip\(|t\.Skip)' <test_dir>
  ```
- Mock density (a triage signal only; not a defect by itself):
  ```bash
  rg -c '(mock\(|Mock\(|@Mock|@MockBean|@MockitoBean|jest\.fn|vi\.fn|unittest\.mock|gomock)' <test_dir>
  ```
- Weak-oracle candidates (review context before classifying):
  ```bash
  rg -n '(toBeDefined\(|toBeTruthy\(|isNotNull\(|assertIsNotNone\()' <test_dir>
  ```
- Test declarations and likely mega-tests: use runner listing/reporting when available; otherwise inspect targeted test files.

These searches generate candidates only. A match is not automatically a defect.

### 4. Establish the baseline

When safe, execute the smallest relevant existing test suite before making changes. Record:

- exact command, working directory, and relevant runner/version;
- tests discovered, passed, failed, skipped, and pending (only when the runner reports them);
- duration and relevant environment constraints;
- pre-existing failures and known flaky outcomes;
- whether the run was complete, filtered, or partially blocked.

If the runner does not report a count, do not invent one. If safe execution is not possible, mark the baseline as **not run** and proceed with static analysis only.

## Phase 2: The Seven-Pillar Deep Audit Rubric

Evaluate the target tests and their corresponding production contracts against the following pillars. Findings must be contextual: do not flag a pattern solely because a search expression matched it.

### Pillar A: Oracle Strength and Hollowness

- **[A1] Zero-oracle / smoke-only test:** Production code executes, but the test makes no meaningful assertion about output, state, event, or externally visible effect.
- **[A2] Weak / partial oracle:** Assertions such as `isNotNull`, `toBeTruthy`, `len > 0`, or HTTP `200 OK` are used where critical payload fields, domain mutations, exact status/error semantics, or persistence effects should be verified.
- **[A3] Swallowed async / exception failure:** Missing `await` on asynchronous assertions; an exception assertion is caught or swallowed; a callback assertion can pass without proving the callback ran; or the test can pass when the expected rejection/exception never occurs.
- **[A4] Opaque snapshot bloat:** Large snapshots obscure important behavior or make irrelevant representation changes dominate review. Snapshots are acceptable for stable, focused, intentionally reviewed contracts.

### Pillar B: Mock Abuse and Refactoring Brittleness

- **[B1] Mirror / tautology test:** A mock is configured to return `X`, the SUT merely returns that value, and the test asserts `X` without proving meaningful orchestration or transformation.
- **[B2] Over-specified interaction verification:** Tests assert internal helper call counts or argument shapes when the public outcome or state transition is the actual contract. Interaction assertions remain valid when the interaction itself is contractual (for example, an externally visible message delivery or idempotency guarantee).
- **[B3] Partial SUT mocking:** A spy or partial mock stubs the behavior of the same SUT being tested, undermining the test's ability to exercise the real behavior.
- **[B4] White-box coupling:** Reflection, friend-access hacks, private-method invocation, or assertions on hidden implementation state are used without a compelling, documented boundary-testing reason.

### Pillar C: Determinism and Hermeticity

- **[C1] Uncontrolled time and entropy:** Tests rely on wall-clock time, expiring hard-coded timestamps, unseeded randomness, UUIDs, or nondeterministic ordering without controlling or asserting the relevant contract.
- **[C2] Shared mutable state / order dependency:** Leaked globals, environment mutations, singleton/cache state, shared databases, or residual rows cause tests to depend on execution order or previous runs.
- **[C3] Sleep-based synchronization:** Fixed delays are used where deterministic synchronization, fake timers, condition polling, latches, or framework-native wait utilities can express the condition. A sleep used intentionally for a timing contract is not automatically defective.
- **[C4] Resource collision / external dependency:** Tests use fixed ports, shared temp paths, live external HTTP calls, or shared external resources in ways that make isolation or repeatability unreliable.

### Pillar D: Boundary, Negative, Isolation, and Concurrency Coverage

- **[D1] Happy-path monoculture:** Important invalid, malformed, unauthorized, or state-invalid inputs are not tested for a behavior where they are material to the contract.
- **[D2] Off-by-one / domain boundary gap:** Exact relational boundaries (`<` vs. `<=`), zero/negative values, empty collections, nullability, maximum limits, Unicode, locale, timezone, or pagination edges are omitted where they affect behavior.
- **[D3] Failure recovery / idempotency gap:** Relevant downstream timeouts, partial batch failures, duplicate deliveries/requests, retries, rollback, compensation, or recovery paths are not validated.
- **[D4] Concurrency / race gap:** Stateful services, caches, rate limiters, unique constraints, or locking paths lack concurrency tests where concurrent behavior is part of the contract or risk profile.
- **[D5] Decoy / cross-boundary isolation gap:** A query, filter, update, delete, or authorization test uses only matching/authorized fixture records and therefore does not prove that a non-matching, another-tenant, another-user, or otherwise excluded record remains inaccessible or untouched. Apply this check to scoped-data and authorization behavior, not indiscriminately to unrelated tests.

### Pillar E: Diagnostic Clarity and Structural Hygiene

- **[E1] Opaque naming / unexplained literals:** Test names do not communicate scenario, condition, and expected outcome; magic values obscure input-to-output causation.
- **[E2] Obscuring control flow:** Branching, loops, exception handling, or nested callbacks make the test's behavior difficult to follow or allow a path to pass without asserting the intended outcome. Do not flag valid parameterized, property-based, concurrency, or callback patterns simply for using control flow.
- **[E3] Mega-test / multiple behaviors:** One test verifies several independent behaviors sequentially, so an early failure masks later scenarios or the test name does not describe what it covers.

### Pillar F: Execution Cost and Test-Pyramid Balance

- **[F1] Context / container thrashing:** Heavy application contexts or containers are repeatedly started for logic that could be tested at a smaller, appropriate boundary. Do not downgrade integration tests merely because they are slower; evaluate whether the integration boundary is necessary.
- **[F2] Fixture over-creation:** Expensive immutable setup is rebuilt unnecessarily, or fixture structure makes tests slow and difficult to understand. Never share mutable fixtures in a way that compromises isolation just to improve speed.

### Pillar G: Persistence and Integration Fidelity

- **[G1] Commit / rollback masking trap:** Test-managed transactions or unflushed ORM sessions cause tests to pass without exercising the real commit boundary, deferred constraints, lazy-loading boundary, or persistence effects that matter in production. `@Transactional` is not inherently a defect; verify what boundary the test actually covers.
- **[G2] Dialect / fake drift:** An in-memory database or simplistic fake differs materially from the production database/adapter in constraints, JSON operators, collation/case sensitivity, isolation, locking, sorting, pagination, or transaction behavior.

---

## Phase 3: Polyglot Stack-Specific Routing

Use only the checks and commands supported by the detected project's actual runner, version, configuration, and installed plugins. First inspect the runner's help/version output. Do not install missing tools or assume optional flags exist.

| Stack | High-priority audit checks | Preferred verification/remediation |
|---|---|---|
| **Java / Kotlin (Spring, JUnit 5)** | Excessive `@SpringBootTest`; unnecessary context variants; test-managed transactions masking commit behavior; `Thread.sleep`; reflection-based testing. | Plain JUnit tests for domain behavior; appropriate MVC/data slices; Testcontainers when production database semantics matter; explicit flush/clear and a real commit-boundary test when required; Awaitility or deterministic synchronization for async behavior. Use randomized ordering only when the configured runner supports it. |
| **Python (pytest, FastAPI, asyncio)** | Fragile patch targets; mutable session-scoped fixtures; non-strict xfail; unawaited coroutines; uncontrolled event-loop or environment state. | Explicit dependency overrides; factory fixtures; `pytest.mark.parametrize`; `pytest.raises` with exact exception/type/message expectations where contractual. Use `pytest-randomly`, `pytest-repeat`, or `pytest-xdist` only if already installed and their flags are confirmed by the runner. |
| **TypeScript / JavaScript (Jest, Vitest, Playwright, React/Angular)** | Incorrect mock restoration; fake-timer leakage; unawaited `.rejects`; internal component-state assertions; brittle snapshots; test runner confusion. | Use the project's actual runner. Jest and Vitest commands are not interchangeable. Prefer user-visible roles and public outputs for UI behavior. Verify runner-specific randomization and parallelism flags from the installed version's help/configuration. |
| **Go** | Missing race checks for concurrent code; unsafe `t.Parallel` loop-variable capture; shared mock/state; weak `err != nil` assertions. | Use targeted `go test -race` when supported and safe; `-shuffle=on` and `-count` when supported by the Go version; table-driven tests with isolated state; check `errors.Is`, `errors.As`, or concrete error contracts. |
| **Rust** | Shared state between tests; overly broad integration setup; weak error-variant checks; concurrency behavior without an appropriate model. | Use `cargo test` with project-appropriate filters and thread settings; use an already-installed runner such as `cargo-nextest` only when present. For concurrency algorithms, consider existing Loom tests where appropriate. Do not claim a Go-style race detector exists for standard Rust tests. |
| **Other / mixed stacks** | Identify the actual runner and build boundaries before selecting checks. | Use the project's documented commands and supported tooling. If the stack cannot be identified confidently, limit the audit to static review and clearly state the limitation. |

### Runner command policy

- Use project scripts and CI commands as the source of truth where they are safe and relevant.
- Run the narrowest relevant test target first; run a broader suite only when the scope and time/risk justify it.
- Verify flags against the installed runner (`--help`, version output, or project configuration) before using them.
- Randomized order, repetition, parallel execution, race detection, and mutation testing are separate checks. Do not imply that one proves the others.
- If optional capabilities are unavailable, report **not run — capability unavailable** rather than silently omitting the limitation.

---

## Phase 4: Deterministic Audit Report

Produce this report at the end of `AUDIT`, or as the execution blueprint before editing in `REFINE` / authorized `DIFF` mode.

### 4.1 Scope and execution summary

Include:

- Mode and exact scope (repository/module/test files/related production paths).
- Stack, runner, and relevant versions.
- Baseline command and outcome, or reason it was not run.
- Whether the assessment is static, execution-backed, mutation-backed, or a combination.
- Initial working-tree state and any pre-existing changes relevant to the scope.

### 4.2 Suite health scorecard

The score is a **heuristic risk index**, not a standardized industry benchmark, test-coverage percentage, or guarantee of correctness. Always show the underlying counts and deductions so the reader can reproduce the arithmetic.

#### Default severity weights

| Priority | Deduction per distinct finding | Meaning |
|---|---:|---|
| **P0** | 15 points | Critical false confidence, demonstrated isolation breach, or a defect that invalidates a high-risk test boundary |
| **P1** | 8 points | Material weakness likely to miss a meaningful defect or produce unreliable behavior |
| **P2** | 3 points | Moderate weakness, brittleness, fidelity risk, or maintainability issue |
| **P3** | 1 point | Low-impact clarity or structural issue |

#### Default rubric-to-priority mapping

Use the mapping below as the default. Escalate or downgrade only when the impact is supported by evidence; record the reason and the adjusted priority in the report. Do not score a mere search hit or an unverified suspicion as a confirmed finding.

| Rubric ID | Default priority | Scoring note |
|---|---|---|
| A1 | P0 | A test with no meaningful oracle provides no demonstrated protection. |
| A2 | P1 | Escalate only when the weak assertion covers a critical contract. |
| A3 | P0 | The test may pass when the expected async/exception behavior does not occur. |
| A4 | P2 | Score only when snapshot opacity materially weakens review or diagnosis. |
| B1 | P1 | A mirror assertion does not establish meaningful SUT behavior. |
| B2 | P2 | Do not score interaction verification that is itself contractual. |
| B3 | P1 | Partial SUT mocking undermines execution of the real behavior. |
| B4 | P2 | Escalate when private-state coupling hides a material contract gap. |
| C1 | P1 | Use when uncontrolled time/entropy makes results materially non-repeatable; otherwise P2 for a contained risk. |
| C2 | P0 | Use when shared state causes demonstrated order dependence or data leakage; otherwise P1 for a concrete isolation risk. |
| C3 | P1 | Use when sleep-based synchronization creates demonstrated or credible flakiness; otherwise P2. |
| C4 | P1 | Use for live/shared external dependencies that materially compromise hermeticity; otherwise P2 for contained collision risk. |
| D1 | P1 | Escalate when omitted negative behavior is security-, money-, or safety-critical; otherwise P2. |
| D2 | P1 | Use for a material domain boundary; otherwise P2. |
| D3 | P1 | Use when recovery/idempotency is a material reliability contract; otherwise P2. |
| D4 | P1 | Use when concurrency correctness is part of the service contract or risk; otherwise P2. |
| D5 | P0 | Use for tenant/authz or sensitive scoped-data boundaries; otherwise P1 for material filtering/update isolation. |
| E1 | P3 | Clarity issue unless it conceals a more serious oracle problem. |
| E2 | P3 | Score only when control flow obscures the assertion or permits false success. |
| E3 | P3 | Split or restructure only when independent behaviors are obscured. |
| F1 | P2 | Score only when setup cost is avoidable without weakening the tested boundary. |
| F2 | P2 | Do not trade away isolation to share mutable fixtures. |
| G1 | P0 | Use when the test demonstrably masks a production commit/persistence failure; otherwise P1 for a concrete boundary gap. |
| G2 | P1 | Use for demonstrated production-semantic mismatch; otherwise P2 for an unverified but material drift risk. |

#### Exact score calculation

Calculate scores **per audited module** and per score category. Assign each distinct finding to exactly one primary category to prevent double-counting:

- **Fault Detection & Isolation:** A, D, G
- **Determinism & Hermeticity:** C
- **Refactoring Resilience:** B
- **Execution & Structural Hygiene:** E, F

Let:

- `T` = number of test cases in the audited module, using runner-reported discovered cases when available. If the runner count is unavailable, state the counting method and mark the count as estimated.
- `w(f)` = deduction for finding `f` (P0=15, P1=8, P2=3, P3=1).
- `N` = normalization factor: `1` when `T <= 20`; otherwise `10 / T`.
- `F_c` = distinct findings assigned to category `c`.

Then:

`CategoryScore(c) = max(0, 100 - N * sum(w(f) for f in F_c))`

Round the displayed category score to one decimal place using ordinary nearest rounding. Keep full precision for the repository aggregation.

The module score is the unweighted arithmetic mean of its four category scores:

`ModuleScore = (FaultDetection + Determinism + RefactoringResilience + ExecutionHygiene) / 4`

The repository score is the test-count-weighted mean of the audited module scores:

`RepositoryScore = sum(ModuleScore(m) * T(m)) / sum(T(m))`

If test counts are unavailable or any audited module has no discoverable tests, do not manufacture a repository score; report the module/category findings and state why aggregation is unavailable.

**Counting rules:**

- Count distinct test-level root causes, not every assertion affected by the same cause.
- The same underlying cause may be counted separately in independent tests when it creates separate test failures or false-confidence paths.
- A finding may have one primary category only. Mention secondary implications in prose without duplicating the deduction.
- Do not count a pre-existing test failure as a refinement-introduced defect. Report it separately.
- Report estimated counts, partial scopes, and severity adjustments explicitly.

Display the exact score breakdown, for example:

| Category | Score | Finding deductions | Calculation |
|---|---:|---|---|
| Fault Detection & Isolation | XX.X/100 | P0: n, P1: n, P2: n, P3: n | `max(0, 100 - N × deductions)` |
| Determinism & Hermeticity | XX.X/100 | P0: n, P1: n, P2: n, P3: n | `max(0, 100 - N × deductions)` |
| Refactoring Resilience | XX.X/100 | P0: n, P1: n, P2: n, P3: n | `max(0, 100 - N × deductions)` |
| Execution & Structural Hygiene | XX.X/100 | P0: n, P1: n, P2: n, P3: n | `max(0, 100 - N × deductions)` |
| **Module score** | **XX.X/100** | | Arithmetic mean of four categories |

### 4.3 Prioritized defect ledger

| Priority | Pillar ID | File:Line | Evidence and root cause | Impact / confidence | Concrete remediation |
|---|---|---|---|---|---|
| P0 / P1 / P2 / P3 | `[ID]` | `path/file:line` | Exact observed behavior or missing proof | Confirmed / likely / possible; explain impact | Specific test-only change or follow-up |

Use **confirmed**, **likely**, or **possible** consistently:

- **Confirmed:** directly demonstrated by source behavior or execution evidence.
- **Likely:** strong evidence supports the issue, but a required execution or production-boundary check was unavailable.
- **Possible:** a risk indicator needs further validation; do not present it as a defect.

### 4.4 Production defects and seam-debt log

For a production defect, include the affected contract, evidence, reproduction steps, impact, and proposed regression test. In read-only mode, do not create the test.

For `[SEAM_DEBT]`, identify the hardwired dependency or missing injection boundary, explain why the public boundary is the best available test seam, and describe the smallest production refactor that would improve testability. Do not make that production change.

### 4.5 Coverage and confidence limitations

State which paths were not inspected or executed, unavailable services/tools, estimated counts, and any assumptions. Do not imply exhaustive repository coverage when the audit was scoped or sampled.

---

## Phase 5: Surgical Refinement and Verification Loop

Execute only in `REFINE` or in `DIFF` when the user explicitly authorized remediation. Work in batches of 1–3 test files and keep the patch narrowly scoped.

### 5.1 Plan each batch

Before editing, state:

- the target test files and behavior under refinement;
- the specific findings being addressed;
- the intended observable contract and assertions;
- any production defect or baseline failure that will remain unresolved;
- the verification commands available in this environment.

### 5.2 Apply test-only refinements

Preferred improvements include:

- Clear Arrange–Act–Assert separation where it improves comprehension.
- Test data builders that expose only scenario-relevant properties.
- Decoy/poison records in scoped filtering, persistence, and authorization tests.
- Parameterized/table-driven cases for related boundaries, without hiding important scenario names.
- Strong assertions on payload fields, persisted state, emitted events, and exact error contracts.
- Clock/randomness injection or framework-native fakes at genuine nondeterministic boundaries.
- Deterministic synchronization instead of arbitrary sleep-based waiting.
- Contract tests for fakes and production-like persistence tests where adapter semantics matter.
- Consolidation of truly redundant tests only when all unique behavior coverage is preserved and the resulting suite remains easier to diagnose.

Do not add tests solely to increase counts or line coverage. Do not delete or weaken a test merely because it is inconvenient or currently failing.

### 5.3 Mutation and fault-sensitivity gate

If a compatible mutation tool is already installed and its operation can be isolated safely, run it against the target module. Examples include PIT, Stryker, mutmut, cargo-mutants, or an established project-specific tool.

Before running a mutation tool:

1. Read its configuration and understand whether it edits source files, creates worktrees, or uses temporary copies.
2. Confirm it will not overwrite user changes or touch unrelated production files.
3. Prefer an isolated copy/worktree or the tool's safe temporary mode.
4. If isolation cannot be guaranteed, skip mutation execution and explain why.

Report actual mutation outcomes: killed, survived, timed out, uncovered, or not run. A mutation score is meaningful only with the mutation scope and exclusions stated.

If no mutation tool is available, perform a **manual fault-sensitivity analysis** for each important refined assertion:

- identify the exact production decision or state transition that could be wrong;
- describe a plausible fault (for example, changing `>` to `>=`, dropping a tenant predicate, omitting a state update, or swallowing an exception);
- show which assertion would fail and why.

Label this as manual analysis, **not empirical mutation proof**. Do not claim that a mutation was killed unless a mutation runner actually executed it and reported that result.

### 5.4 Verify determinism and order independence

Select only runner-supported checks and report them separately:

- baseline targeted run;
- repeated run;
- randomized order, when supported;
- parallel/concurrent execution, when meaningful and supported;
- race detector or concurrency-specific tests, when available;
- integration/commit-boundary run, when required and safe.

Do not infer order independence from a serial `runInBand` invocation. Do not infer concurrency safety from repeated serial runs. Do not use optional plugin flags until their availability is confirmed.

### 5.5 Compare before and after

After each batch:

1. Run the narrowest relevant tests.
2. Run the relevant broader suite when safe and justified.
3. Compare failures against the captured baseline; distinguish pre-existing failures, known production-defect reproductions, and refinement-introduced failures.
4. Inspect `git diff --check`, `git diff --stat`, and the exact changed paths.
5. Verify no production source files were modified by the refinement.
6. Verify no pre-existing user changes were lost or overwritten.
7. Continue to the next batch only when the current batch is understood and stable.

Do not automatically run formatting across an entire repository. Format only the changed test files, and only when the project formatter is available and doing so will not rewrite unrelated content.

---

## 6. Definition of Done — Pre-Exit Verification Gates

Before concluding `REFINE` or an authorized `DIFF` remediation, report the status of all applicable gates. A gate may be **PASS**, **FAIL**, or **NOT RUN**; do not mark it as passed without evidence.

- [ ] **Gate 1 — Production integrity:** Compare initial and final Git state. No production source changes were introduced by the skill. Any pre-existing production changes are preserved and clearly distinguished.
- [ ] **Gate 2 — Test outcome:** All targeted tests that passed at baseline still pass, except for clearly documented known production-defect reproductions or environmental blockers. Report pre-existing failures separately; do not require or claim an artificial 100% pass rate.
- [ ] **Gate 3 — Determinism and order:** Run supported repeat/random-order checks where available. If not available, report the exact limitation. Do not claim concurrency independence from serial runs.
- [ ] **Gate 4 — Scoped isolation:** Relevant tenant, user, authorization, filtering, update, or deletion tests include a non-matching/unauthorized decoy where needed and prove it is excluded or untouched.
- [ ] **Gate 5 — High-risk test smells:** No unresolved high-risk weak oracles, swallowed async/exception paths, uncontrolled shared state, or nondeterministic synchronization remain in the refined scope. Document justified exceptions; do not enforce blanket bans on valid test constructs.
- [ ] **Gate 6 — Before/after evidence:** Provide a table comparing discovered test counts (when available), pass/fail/skip counts, runtime, P0–P3 findings resolved, new boundary/isolation scenarios, and mutation results (or manual fault analysis).
- [ ] **Gate 7 — Change integrity:** The final diff contains only intended, in-scope test changes and approved test-only configuration changes. No user changes were discarded.

### Final refinement summary

| Measure | Before | After | Notes |
|---|---:|---:|---|
| Tests discovered | | | State counting method |
| Passed / failed / skipped | | | Separate pre-existing failures |
| Targeted runtime | | | Same command/environment where comparable |
| P0 / P1 / P2 / P3 findings | | | Count by distinct root cause |
| Boundary / negative scenarios | | | Identify newly covered contracts |
| Isolation / decoy scenarios | | | Identify relevant paths |
| Mutation results | | | Killed / survived / not run |
| Production files changed by this skill | 0 | 0 | Must remain zero |

---

## 7. Reporting Principles

1. Lead with the most consequential result, not a list of style suggestions.
2. Separate confirmed defects, likely risks, and possible improvements.
3. Include exact paths and line numbers only when verified against the current file state.
4. Show commands actually run and summarize their real output; never imply a command was run when it was only recommended.
5. State test-run limitations, unavailable tools, and safety-based omissions.
6. Prefer concrete, minimal remediations over broad rewrites.
7. Preserve the user's terminology and repository conventions unless they are directly responsible for a test-quality problem.
8. Do not overstate the score. A high score does not prove correctness; a low score does not mean every test is useless.
9. In `AUDIT`, explicitly confirm that no files were changed only after checking the working tree.
10. In `REFINE`/authorized `DIFF`, end with the changed-file list, verification evidence, remaining risks, and gate statuses.

---

## 8. Quick Decision Guide

| User request | Mode | File changes? |
|---|---|---|
| "Review this test file" | AUDIT | No |
| "Audit the repository's tests" | AUDIT | No |
| "Score test quality" | AUDIT | No |
| "Fix the flaky tests in this module" | REFINE | Test files only |
| "Improve these assertions" | REFINE | Test files only |
| "Review this PR diff" | DIFF | No, unless remediation is explicitly requested |
| "Fix the test issues in this PR" | DIFF | Test files only, strictly within the diff/affected scope |
| Ambiguous request | AUDIT | No |

**Operating principle:** First establish what the tests prove. Then, only with explicit authorization, improve the smallest test boundary that closes the demonstrated gap. Production behavior remains untouched.
