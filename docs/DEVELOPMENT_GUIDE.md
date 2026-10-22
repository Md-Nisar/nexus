# Development Guide

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| JDK | 25 (LTS) | Enforced by maven-enforcer |
| Maven | 3.9+ | Or use the wrapper `./mvnw` |
| Node.js | 24 LTS | CI uses 24; odd versions are not for production |
| Docker | Desktop / Engine | MySQL via compose; Testcontainers for `*IT` tests |

## First-time setup

```bash
git clone <repo> && cd nexus
docker compose up -d                      # MySQL 8.4 → localhost:3306 (db: nexus)
cd nexus-backend && ./mvnw verify -DskipITs   # compiles, unit tests, quality gates
cd ../nexus-frontend && npm ci && npm run test:ci
```

## Backend (`nexus-backend/`)

### Configuration profiles

| Profile | Use | Notes |
|---------|-----|-------|
| `dev` (default) | Local development | SQL logging on, DEBUG for `com.example.nexus` |
| `test` | `@SpringBootTest` smoke tests | H2 in-memory, Flyway off |
| `prod` | Production | ECS JSON logs, springdoc off, credentials from env only |

All environment-specific values use `${ENV_VAR:default}` in `application.yml`. Production requires `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` — there are no prod defaults by design.

### Commands

```bash
./mvnw spring-boot:run                  # run (dev profile, :1000)
./mvnw test                             # unit tests only — no Docker needed
./mvnw verify                           # + integration tests (*IT, Testcontainers) + coverage gate
./mvnw verify -DskipITs                 # full quality gates without Docker
./mvnw verify -Pquality                 # + PMD
./mvnw -Psecurity dependency-check:check  # CVE scan (slow; set NVD_API_KEY)
./mvnw test -Dtest=GlobalExceptionHandlerTest                       # one class
./mvnw test -Dtest='GlobalExceptionHandlerTest#should_return404*'   # one method
```

### Database migrations

Flyway, `src/main/resources/db/migration`, named `V<N>__<snake_case_description>.sql`.
Append-only: never edit an applied migration — write a new one. Non-additive changes (rename/drop/type change) need an expand→contract two-step plan reviewed at design time. Hibernate runs `ddl-auto=validate`; if startup fails with a schema mismatch, you forgot a migration.

### Adding a bounded context

Create `com.example.nexus.<context>` with `domain/`, `application/`, `infrastructure/`, `interfaces/` packages. The ArchUnit suite (`HexagonalArchitectureTest`) picks it up automatically and fails the build on dependency-rule violations. Conventions: `.claude/skills/spring-boot-standards/SKILL.md`.

### Authorization rules (RBAC)

Design: `docs/features/US-018/03-design.md`; decisions: ADR-0021 and ADR-0022 (both still Proposed). Behaviour as built is in `docs/features/US-018/09-technical.md`.

#### Grant-subset rules and "administrator"

A caller may only hand out, take away or attach what they currently hold. The caller's holdings are read live from the DB inside the write transaction, never from the JWT.

| Operation | Rule |
|---|---|
| Assign a role (A2) | Every permission of the target role is in the **union** of the caller's held permissions |
| Attach a permission (A3) | The caller holds that permission (any permission, not only formerly dangerous ones) |
| Self-assign (A4) | Only an administrator may assign a role to themselves |
| Revoke a role | Caller holds every permission of the role; if the role is admin-defining the caller must also be an administrator |
| Detach a permission (role-subset) | Caller holds every permission of the role; if the role is admin-defining the caller must be an administrator through a *different* role |
| `PATCH` / `DELETE` a role (C1) | Role-subset bounds these too (ADR-0021 D5); whether the administrator-through-another-role clause also applies to them is unverified |

**"Administrator" has one definition:** a role is *admin-defining* iff it alone carries every permission in the `permissions` catalogue; a user is an *administrator* iff they hold an active admin-defining role. It is per role, never the union across roles, and never a role name (`RbacAdministrators`). Grant bounds ("could the caller have granted this?") use the union; every "is the caller an administrator?" question uses the per-role definition. The last-admin lockout, the zero-admin health indicator, `listActive` redaction of `assignedBy` and the break-glass CLI use the same definition. Denials are 403 `RBAC_001`; the body's `requiredPermission` is always the endpoint permission, not the missing one.

#### The three access markers

Every MVC handler carries exactly one of these (build fails otherwise: `HexagonalArchitectureTest`, `EndpointClassificationWebTest`):

- `@RequiresPermission(Permissions.X)` — a signed-in caller holding that permission.
- `@AuthenticatedEndpoint` — a signed-in caller, no permission. Own data only: the handler may not bind a caller-chosen identifier (`@PathVariable`, `@RequestParam`, `@RequestHeader`, any `UUID` parameter, `HttpServletRequest`, and so on; identifiers inside a `@RequestBody` are not covered by the rule). Anything addressing another resource needs `@RequiresPermission`.
- `@PublicEndpoint` — anonymous callers allowed. A marker only: access is granted by the `permitAll` list in `SecurityConfig`, and the web test fails if the two disagree. Declare an explicit HTTP method; a handler without one is treated as non-public.

`@RequiresPermission` must sit on a public, non-final, non-static method of a Spring bean, and self-invocation is not intercepted.

#### Token freshness (permission epoch)

Revoking a role or detaching a permission bumps a per-user epoch in Redis (`nexus:rbac:epoch:{tenantId}:{userId}`); tokens carry it as `perm_epoch` (schema version 3), and `JwtAuthenticationFilter` answers 401 `AUTH_003` to a token below the current epoch. A revoked user is therefore cut off on the next request, not after the 15-minute token and permission-cache lifetimes.

- **Latency target:** the epoch check must stay at or below 2 ms p95 at 200 RPS (`nexus.rbac.epoch.check.latency`), within EPIC-002's 5 ms p95 RBAC overhead. A local-Docker run measured 0.58 ms p95 (`STATUS.md`); the staging-topology run is unverified (no environment exists yet).
- **Redis outage:** after 3 read failures in 10 s an instance serves degraded-open (epochs it already saw still make a token stale). **15 minutes** after the first failure (`nexus.rbac.epoch.fail-open-window`) it goes degraded-closed: authenticated, non-public requests get **503 `AUTH_005` with `Retry-After: 30`**. Public endpoints are never rejected. 60 s without a counted failure returns it to healthy.
- The frontend does not yet special-case 503 `AUTH_005` (`09-technical.md` section 12).

#### `Permissions` constants and the migration footer

`com.example.nexus.common.security.Permissions` holds one `String` constant per catalogue row plus `ALL`. Every `@RequiresPermission` value and every service-level `requiredPermission` references a constant, never a literal. Adding a catalogue row means a constant, an entry in `ALL`, and an entry in the frontend `Permission` type (below); `PermissionsCatalogueTest` and `PermissionsCatalogueIT` fail on a mismatch.

Every Flyway migration that inserts into `permissions` must end with the footer from `src/main/resources/db/templates/permission-migration-footer.sql` (not itself a migration; use the A-PRE-V9 variant before V9, A-V9 from V9, plus block B). The footer attaches the new permission to every role that already carried the whole catalogue (so custom administrators are not demoted) and to every system `TENANT_ADMIN`. Replace the single placeholder `{{INSERTED_PERMISSION_IDS}}` with the ids *your* file inserts; copying another migration's footer verbatim fails `PermissionMigrationFooterScannerTest`. Also required, but not scanned: an IT that seeds a full-catalogue custom role and asserts it gains the permission, the custom-admin exposure check around the deploy, and a flush of the `rbac:permset:*` / `roleset:*` cache keys afterwards.

## Frontend (`nexus-frontend/`)

### Commands

```bash
npm start                # dev server :2000 (proxies nothing — dev API URL points at :1000)
npm test                 # Vitest, watch mode
npm run test:ci          # single run + coverage
npm run lint             # ESLint (angular-eslint flat config)
npm run format           # Prettier write
npm run e2e              # Playwright (first time: npx playwright install chromium)
npm run build            # production build
```

### Environments

`src/environments/environment.ts` (production values) is replaced by `environment.development.ts` in dev builds. Consume via the `APP_CONFIG` injection token — never import environment files in feature code, never hardcode URLs.

### Adding a feature

Follow `src/app/features/README.md`: pages/components/services/models per feature, lazy route registration in `app.routes.ts`, no cross-feature imports. Conventions: `.claude/skills/angular-standards/SKILL.md`.

### Permission-gating the UI (`permissionGuard` / `*appHasPermission`)

> **UX only — not a security boundary.** Both tools below merely tidy the interface. The
> server-side `@RequiresPermission` check (US-011) is the *only* thing that actually
> protects an operation: a user who edits client state, replays a request, or calls the API
> directly still receives `403`. Never let a client-side check be the only protection for
> anything.
>

> **Never use `*appHasPermission` to hide data that is already in the browser.** Hiding a
> salary column, an audit field, another tenant's row, or any other value the backend has
> already sent in the response payload does **not** protect that data — by the time the
> directive runs, it has already been delivered to the client and is trivially visible via
> devtools or the network tab. This directive is for hiding *controls* (buttons, menu
> items, links) whose *action* is independently enforced server-side, never for hiding
> data whose *visibility* is the thing that needs protecting. Permission-based field
> hiding within a component is explicitly out of scope for this pattern — do not reach for
> `*appHasPermission` to build it.

Both read `AuthStore.permissions` — a `computed<readonly string[]>` populated from
`GET /v1/users/me` (`permissions[]`, `resource:action`, lowercase). Matching is exact and
case-sensitive. The signal is never `undefined`; "no session" and "no permissions" both
yield an empty array.

#### Gating a route

```typescript
{
  path: 'roles',
  canActivate: [authGuard, permissionGuard],   // order matters — see below
  data: { permission: 'role:read' },
  loadComponent: () => import('./features/roles/roles.component').then((m) => m.RolesComponent),
}
```

On denial the guard redirects to `/access-denied` (never `/auth/login` — the user *is*
authenticated, they just lack the permission).

**`permissionGuard` must never be used alone, and never in the same array as `authGuard`.**
Put `authGuard` on an **ancestor** route (the signed-in `Shell` carries it) and
`permissionGuard` on the child. Guards in one `canActivate` array run *concurrently*, so
`permissionGuard` would read the permission list while `authGuard` is still refreshing the
session; route levels run in sequence, so an ancestor's guard finishes first. Used alone, a
cold start (page reload, in-memory session `null`) makes `permissionGuard` see an empty
permission list and send an entitled user to `/access-denied` instead of `/auth/login`.

**`permissionGuard` fails open.** A route that reaches the guard without a non-empty
string `data.permission` is treated as a misconfiguration and is **allowed through**,
silently. That is deliberate — the guard is not a security boundary, so a typo must not
lock users out of a feature. The consequence: every route using `permissionGuard` needs a
test asserting its `data.permission` value, or a typo will never be caught (see the
route-table contract spec at `core/guards/permission-guard-contract.spec.ts`, which
mechanically enforces both this and the ordering rule above against the real route table).
Note also that Angular merges a parent route's `data` into child snapshots, so declare
`permission` on the exact route you are gating.

**`/access-denied` must remain a top-level, unguarded route and must never become a
descendant of a route carrying `data.permission`.** Because a parent's `data` merges into
child snapshots, nesting the Access Denied page under a gated ancestor would make its own
denial redirect target a route that itself denies — a navigation loop instead of the
intended UX.

#### Hiding an element

```typescript
import { HasPermissionDirective } from '../../shared/directives/has-permission.directive';

@Component({
  imports: [HasPermissionDirective],   // each standalone component imports it itself
  template: `
    <button *appHasPermission="'user:write'" (click)="delete()">Delete user</button>
  `,
})
export class UsersComponent {}
```

There is no global shared-imports barrel in this codebase, and the directive is
intentionally **not** exported from `shared/ui/index.ts` (that barrel is the design-system
component library). Import it directly from its file.

The directive is reactive: elements appear/disappear automatically when the permission set
changes (login, token refresh, `/users/me` re-fetch). When the user lacks the permission —
including before the session has loaded — the element is simply absent from the DOM; the
directive never throws and never logs. There is no `else`-template variant yet; it can be
added later without breaking this API.

`*appHasPermission` is a **custom structural directive**, which is permitted. The
"`@if`/`@for`, not `*ngIf`/`*ngFor`" non-negotiable
(`docs/ARCHITECTURE.md` §Non-negotiables #9) targets Angular's *built-in* control flow;
custom structural directives remain the right tool for a cross-cutting concern like this.

#### Route gating does not protect code

A gated route's lazy chunk is an unauthenticated static asset: `canActivate` gates
*component activation*, not *chunk delivery*. Anyone — including an unauthenticated
visitor who guesses the filename — can fetch a gated feature's JS chunk and read its
templates, endpoint paths, permission strings, and client-side business rules. **Never
place secrets, credentials, internal hostnames, or confidential business logic in a
permission-gated component.** This is inherent to any SPA, not specific to this pattern,
but worth stating here because this is the story that establishes it.

#### Reacting to a 403 in a component

`AppError.requiredPermission` carries the permission the backend demanded — **camelCase**,
and present **only** when `AppError.code === 'RBAC_001'`. A 403 with
`code === 'ACCESS_DENIED'` (Spring Security) has no such field, so never infer its presence
from the status code. It is a developer diagnostic: log it, correlate it with `traceId` — but
never render it, never put it in a URL, and never send it to analytics. Show
`AppError.message` to the user.

#### Code-review checklist for anything touching permission gating

- `AppError.requiredPermission` is never rendered, put in a URL, or forwarded to analytics/telemetry.
- Data hidden by `*appHasPermission` is also omitted **server-side** — the directive hides controls, never data.
- No secret, credential, internal hostname, or confidential business rule lives inside a permission-gated component.

### The `Permission` type and `SKIP_ACCESS_DENIED_REDIRECT`

`shared/types/permission.ts` exports `Permission`, a closed union of the catalogue names, and `PERMISSIONS`. `permissionGuard` data and `*appHasPermission` take a `Permission`, so a misspelt name is a compile error. It mirrors the backend `Permissions` class by hand; `app.routes.spec.ts` walks the route table (including lazy `loadChildren`) and fails on an unknown name. Typing a permission authorizes nothing.

`apiErrorInterceptor` sends a 403 with code `RBAC_001` to `/access-denied`, with no query parameters, and still rethrows the `AppError`. A filter-level `ACCESS_DENIED`, 401 and 404 never redirect. A caller that handles the denial inline opts out per request:

```ts
http.get(url, { context: new HttpContext().set(SKIP_ACCESS_DENIED_REDIRECT, true) });
```

`SKIP_ACCESS_DENIED_REDIRECT` is exported from `core/http/skip-access-denied-redirect.ts`.

### Dev personas, e2e suite, contrast tokens and nav items (US-019)

**Dev personas.** The backend `dev` profile (the default) seeds known-password accounts at startup (`DevDataInitializer`, never under `prod` or `break-glass`): an administrator (the E2E login), a second administrator, a member, a Role Manager (`role:read`, `role:write`), a User Manager (`user:read`, `user:role:assign`, `user:directory:read`), a locked user, a pending user, and an administrator of a fixture-only second tenant who cannot sign in. All share the dev-only password `TestPass99!`. The addresses live in `nexus-frontend/e2e/fixtures/personas.ts`. They are synthetic; never reuse them or the password anywhere else.

**Run the e2e suite locally.** Start `docker compose up -d` (MySQL, Redis, MailHog), then the backend on the dev profile (`cd nexus-backend && ./mvnw spring-boot:run`), then `cd nexus-frontend && E2E_REQUIRE_BACKEND=1 npm run e2e` (Playwright starts the dev server on :2000 itself; first time `npx playwright install chromium`). Without `E2E_REQUIRE_BACKEND=1`, specs that need the backend are skipped when it is unreachable, which is convenient locally but means a green run proves less. CI sets it, rejects any skipped test and enforces a floor (`E2E_MIN_TESTS` in `.github/workflows/e2e-full-stack.yml`; raise it when you add specs).

**Contrast tokens.** For text use `--nx-color-{primary,error,success,warning}-text`; keep the base `--nx-color-*` for fills, borders and icons. The text tokens are lighter in dark mode and darker in light mode to reach WCAG AA. They are defined in `src/styles/_tokens.scss` for both themes and both `data-theme` overrides; change all three places together.

**Add a nav item.** Add an entry to `NAV_ITEMS` in `src/app/core/layout/nav.config.ts` and a route under the shell in `app.routes.ts`. The item's `permission` must equal the route's `data.permission` (`null` for every signed-in user); `nav.config.spec.ts` fails otherwise. Hiding a nav item is cosmetic, so the route still needs `permissionGuard` and the endpoint `@RequiresPermission`. Add the item to `NAV_LABELS` in the shell e2e spec.

**Agent usage ledger.** `docs/metrics/agent-usage-ledger.csv` is described under "Usage ledger" in *The Operating Model* below; commit the rows the hook appends.

## Docker

```bash
docker compose up -d                   # MySQL only
docker compose --profile full up -d    # MySQL + backend + frontend images
docker compose down -v                 # reset including data volume
```

Both Dockerfiles are multi-stage; the frontend image serves through nginx with `/api/` proxied to the backend service.

## Quality gates (what CI enforces)

| Gate | Where | Threshold |
|------|-------|-----------|
| Checkstyle | every build (validate phase) | 0 errors |
| Unit + integration tests | surefire (`*Test`) / failsafe (`*IT`) | all green |
| JaCoCo line coverage | `mvn verify` | ≥ 80% (config classes excluded) |
| SpotBugs | `mvn verify` | 0 findings |
| ArchUnit | unit test phase | hexagonal rule, no field injection, no `System.out` |
| Prettier + ESLint | frontend CI | clean |
| Vitest + Playwright | frontend CI | all green |

## The Operating Model (mandatory for feature work)

Every non-trivial change follows this model. It is enforced by approval gates (human) and by automated quality gates (machine — see the next section). A quick fix or typo does not need the full model; substantial features do. The single front door is **`/new-feature <FEATURE-ID>`**.

### Plan half — design before code (no implementation until Gate 3 passes)

| # | Step | Command | Agent / skill | Output | Gate |
|---|------|---------|---------------|--------|------|
| 0 | Discovery | `/new-feature` | `feature-discovery` skill | reuse-first survey, impact map, open questions | — |
| 1 | Requirements | `/analyze-story` | business-analyst | `01-requirements.md` | **Gate 1: requirements approved** |
| 2 | Impact analysis | `/impact-analysis` | architect | `02-impact.md` | — |
| 3 | Design + API + DB + threat model | `/design` | architect + security-reviewer | `03-design.md`, `03b-threat-model.md` | **Gate 2: architecture approved** |
| 4 | Task breakdown | `/breakdown` | architect + engineers + qa | `04-tasks.md` | **Gate 3: plan approved** |

**Design review covers, against the standards skills:**
- **API design** (`api-design` skill): REST shape, status codes, RFC 7807 errors, versioning, pagination, idempotency.
- **DB design** (ADR 0003): Flyway migration plan; additive vs expand/contract; indexes; audit columns; naming (`docs/coding-standards.md`).
- **Security** (`SECURITY.md`): STRIDE threat model; each threat → a mitigation task; authz/PII/tenant concerns.
- **Frontend** (`angular-standards`): routes, smart/dumb components, signal state, guards.

### Agent dispatch and context economy

An agent's context grows with everything it reads and is re-sent on every model call, so cost is driven by context size times call count, not by the token figure the UI shows (that figure is the size of the last context, not a total). Measured on US-019 (design, threat model, breakdown): 197 calls, 58M cache-read tokens, and three resumes after long waits that each rebuilt a 380K-550K context. None of the rules below reduce what an agent must verify.

- **Fresh agent for revisions and delta reviews.** Brief it with the concrete asks and section numbers; do not `SendMessage`-resume a finished agent after more than ~5 minutes (the prompt cache has expired and the whole context is rewritten). Resume only an agent that died before writing its deliverable.
- **Read selectively.** `Grep` for headings or identifiers, then ranged `Read`. Whole-file reads are for the document being reviewed adversarially (first-pass threat model reads the whole design). Do not re-read a file you just wrote; grep the changed lines.
- **Upstream documents are read once per agent** and cited by section number. Briefs carry the gate decisions (for example requirements section 13a) so the agent does not re-derive them.
- **Short final answers.** The artifact is the deliverable; the final answer is path, counts, decisions and human asks.
- **Usage transparency.** A `SubagentStop` hook (`.claude/hooks/agent-usage.mjs`) prints a one-line token report when each agent stops: calls, tool uses, last context (the figure the UI shows), max context, cache-read, cache-write, uncached input, output (a lower bound) and an input-equivalent total, plus the delta for a resumed agent. Every report is appended to `~/.claude/nexus-agent-usage.jsonl`. `node .claude/hooks/agent-usage.mjs --report` prints one row per agent for the latest session. The input-equivalent weights (`0.1,1.25,5` for cache-read, cache-write, output) are an assumption, overridable with `NEXUS_USAGE_WEIGHTS`; billing comes from the provider's usage page.
- **Usage ledger.** The same hook appends one row per agent to the committed `docs/metrics/agent-usage-ledger.csv` (date, story, task, agent type, model, agent id, calls, tool uses, cache-read, cache-write, output lower bound, max context, input-equivalent). Story and task are the first `US-nnn` and `T-nnn` found in the agent's prompt, so name the task first in every dispatch prompt; a row without them is design-phase or cross-task work. Rows are cumulative per agent (a resumed agent adds a newer row; readers keep the last). `node .claude/hooks/agent-usage.mjs --ledger` totals by story and task; `--backfill <subagents dir>` adds agents the ledger lacks. Not captured: the main session's own usage, thinking tokens and dollars. Commit the ledger with each task so cost is reviewed alongside the diff.
- **Resume cost check.** After a usage-limit stop, resuming is right only if the agent had no deliverable yet and its exploration is the work to keep.

### Action half — build, prove, ship

| # | Step | Command | Agent | Output | Gate |
|---|------|---------|-------|--------|------|
| 5 | Implement (per task, test-first) | `/implement <ID> <TASK>` | backend/frontend-engineer | code + tests | per-task plan-mode approval |
| 6 | Code review | `/review` | code-reviewer (review-only, no code edits) | `06-code-review.md` | `APPROVE` |
| 7 | Security review | `/security-review` | security-reviewer (review-only, no code edits) | `07-security-review.md` | no Blockers |
| 8 | Test validation | `/test-validate` | qa-engineer | `08-test-audit.md` | coverage gates green |
| 9 | Documentation | `/docs` | — | `09-technical.md` | — |
| 10 | Release prep | `/release-prep` | release-manager | `10-release/` | verdict `READY` |
| 11 | Retro (post-deploy) | `/retro` | — | `retrospective.md` | — |

`/userstory-plan` and `/userstory-action` run each half as a batch. Before any PR: **`/pre-pr-check`**.

**Pilot — autonomous delivery.** `/autonomous-feature <ID>` runs Phases 0–9 unattended for **low/medium-risk** stories: agents hold Gates 2–3 and per-task plan approval (recorded as `claude-agent:<name>`), a human answers Gate 1 open questions and reviews the draft PR. High-risk stories stay on the human-gated flow above. Cloud setup: `docs/runbooks/cloud-agent-setup.md`.

### Requirements summary
- **Discovery/analysis before coding** — Steps 0–2, reuse-first.
- **Architecture + API/DB + security review before coding** — Step 3, Gate 2.
- **Testing** — test-first in Step 5; coverage gates in `docs/TESTING.md` enforced at Step 8 and CI.
- **Documentation** — Step 9 + update standards/ADRs when conventions change.
- **PR requirements** — `/pre-pr-check` green (for a feature: gate records in `01`/`03`/`04` and artifacts `03b`, `06`–`09` present) + Definition of Done (`CONTRIBUTING.md`) + Conventional Commit title + ≥1 code-owner approval.

## How gates are enforced (4 layers)

Standards are not just documented — they fail builds and block merges:

1. **Claude hooks** (`.claude/settings.json`, cross-platform Node `.mjs`): block prod-command/prod-file/secret writes (PreToolUse), auto-format frontend (PostToolUse), run affected unit tests at session end (Stop).
2. **Local git hook** (`.githooks/pre-push`): runs format/lint/tests for changed sides before a human push. Enable once: `git config core.hooksPath .githooks` (also in setup below).
3. **CI** (`.github/workflows/`): `mvn verify` (Checkstyle, per-layer JaCoCo, SpotBugs, ArchUnit, Testcontainers ITs), frontend format/lint/test/build/e2e, weekly OWASP+Trivy, Conventional-Commit PR-title check.
4. **Branch protection** (`nexus-scripts/setup-branch-protection.sh` + `.github/CODEOWNERS`): required status checks, ≥1 code-owner approval, resolved conversations, no force-push. A repo admin runs the script once.

### One-time local setup
```bash
git config core.hooksPath .githooks     # enable the pre-push gate
# (Claude Code reads .claude/settings.json automatically; no setup needed.)
```

## AI-assisted workflow

This repo is configured for Claude Code (`.claude/`): the operating model above as slash commands, per-role sub-agents (review agents are instructed not to edit code; they still have `Bash`, so this is a prompt rule, not a tool restriction), standards/workflow skills, and the enforcement hooks in `.claude/settings.json`. Behaviour: `CLAUDE.md`; map, constraints and commands: `PROJECT.md`; full `.claude` layout: `.claude/README.md`.
