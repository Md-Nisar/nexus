# Rule allowlist

An allowlist, not a denylist. If a rule is absent, the agent may not fix it.
Keep Tier 1 in sync with `DEFAULT_RULES` in `nexus-scripts/fetch_sonar_issues.sh`.

> Verify these keys against your actual Sonar quality profile before relying on
> them - rule keys occasionally change between analyser versions. Open any issue
> in the Sonar UI to read its exact key.

## Tier 1 - agent may fix autonomously

### Java
| Rule | Description | Why safe |
|---|---|---|
| `java:S1128` | Unused imports | No runtime effect. Check Javadoc `{@link}` first. |
| `java:S1481` | Unused local variables | Safe once the initialiser is confirmed side-effect free. |
| `java:S1596` | Use `Collections.emptyList()` | Direct equivalent. |
| `java:S2293` | Use the diamond operator | Pure syntax; type inference is identical. |
| `java:S1125` | Redundant boolean literals | `x == true` -> `x`. Mechanical. |

### TypeScript
| Rule | Description | Why safe |
|---|---|---|
| `typescript:S1128` | Unused imports | Check the paired `.html` template first. |
| `typescript:S1481` | Unused local variables | Same caveat as Java. |
| `typescript:S3512` | Use template literals | Mechanical string concat rewrite. |
| `typescript:S1125` | Redundant boolean literals | Mechanical. |
| `typescript:S1116` | Redundant semicolons | No semantic effect. |

## Tier 2 - agent may PROPOSE, human decides

Present a diff in chat; do not open a PR from the scheduled routine.

- `java:S1155` `size() == 0` -> `isEmpty()`
- `java:S1118` utility class private constructor
- `java:S1602` lambda brace removal
- `java:S1854` dead stores (needs side-effect analysis)
- `typescript:S4325` unnecessary type assertions
- `typescript:S3626` redundant jump statements
- Any `@Deprecated` API replacement

## Tier 3 - human only, never automated

- Every **Security Hotspot** and **Vulnerability**, without exception
- Concurrency, threading, `synchronized`, `CompletableFuture`
- Cognitive complexity / method extraction (design change)
- Any naming rule (renames ripple across call sites)
- Exception-handling changes (swallowed exceptions often hide real intent)
- SQL, JPA queries, Flyway migrations (`nexus-database/`, `nexus-backend/src/main/resources/db/`)
- RxJS subscription and lifecycle rules in Angular (leak semantics are subtle)
- Anything Sonar rates as effort > 1h

## Promotion policy

A Tier 2 rule moves to Tier 1 only after **five consecutive PRs using it were
merged with zero human edits**. Record the promotion in the PR that changes
this file. Demote immediately on any revert.
