# Verification

Run every applicable command. All must pass before handing off to PR authoring.
Verification is not optional and its result is not negotiable.

## Backend changed (`nexus-backend/**`)
```bash
./mvnw -B -ntp -f nexus-backend/pom.xml clean verify -DskipITs
```
*(Or `./mvnw -B -ntp -f nexus-backend/pom.xml clean verify` if Docker/Testcontainers is available)*
Covers compilation, Checkstyle, SpotBugs, ArchUnit, unit tests, and JaCoCo coverage report generation.
Do not use `-Dmaven.test.failure.ignore=true`.

## Frontend changed (`nexus-frontend/**`)
```bash
npm --prefix nexus-frontend run lint
npm --prefix nexus-frontend run test:ci
npm --prefix nexus-frontend run build -- --configuration production
```
The production build matters: AOT compilation catches template errors that
unit tests do not, and template breakage is the main risk when removing
"unused" TypeScript symbols.

## Both changed
Run both verification suites. Prefer splitting changes into distinct backend and frontend PRs.

## Interpreting failures

| Symptom | Action |
|---|---|
| A test fails | Revert your change. Never edit the test. |
| Coverage drops | Revert. You removed covered code or added uncovered code. |
| Lint / Checkstyle fails | Revert. Do not add a suppression annotation/comment. |
| AOT build fails | You removed a template-referenced symbol. Revert. |
| Flaky/unrelated failure | Re-run once. Still failing -> abort the whole run. |

If more than one fix fails verification, abort the entire run rather than
bisecting indefinitely. A failed run costs nothing; a half-verified PR costs
review time and trust.

## Not your job

Do not run the Sonar scanner locally. CI runs it on the PR and the quality gate
is a required status check. Attempting it locally wastes tokens and can push a
misleading analysis to the wrong branch.
