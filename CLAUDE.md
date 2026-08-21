**Behavioral guidelines for working with Claude Code on Nexus — how to work, not what the project is.**

**Project structure, commands, key constraints, and the operating model live in [PROJECT.md](PROJECT.md).** That is the single source of truth for all of them; read it before starting non-trivial work. Do not restate its contents here.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly.
- Make routine judgment calls yourself — the kind a careful colleague would just decide. Ask only when two readings would lead to materially different work.
- If multiple interpretations exist and they diverge materially, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is genuinely unclear and no assumption is safe, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

- State a brief plan: the steps, and how each will be verified.
- Verification means *running* the gate, not reasoning about it. Default loop for code changes (run from the module directory; `mvnw.cmd` on Windows):
  - Backend — `./mvnw verify -DskipITs`; use plain `./mvnw verify` when Docker is up and you touched persistence, migrations, or a `*IT`.
  - Frontend — `npm run test:ci`, then `npm run lint && npm run format:check`.
- A failing gate **is** the result. Report the actual output; never describe unverified work as done.
- Loop on the failure until green or until you can explain precisely why it can't be. Don't weaken a test or a gate to pass it.
- Before opening any PR, run `/pre-pr-check`.

Full command reference and the feature-development gates: [PROJECT.md](PROJECT.md).

---

These guidelines aim to reduce unnecessary changes, prevent overcomplication, and encourage clarifying questions before implementation.
