---
description: Fix approved Sonar issues on a branch and open a PR
---

Use the `sonar-safe-fix` skill, then the `pr-authoring` skill.

Issues approved for fixing: $ARGUMENTS

Steps:
1. Confirm every issue is Tier 1 and every file is outside the forbidden paths.
   Report anything you are skipping, and why, before you start editing.
2. Create branch `ai/sonar-<rule-slug>` off the current `main`.
3. Apply the minimal fixes. Do not touch tests, build files, or config.
4. Run the full verification suite from `reference/verification.md`.
5. Commit using the pr-authoring template and write the PR body to a file.
   `git push` is denied for Claude sessions (`.claude/settings.json`), so do not
   attempt to push or open the PR yourself.
6. Stop. Give the user the exact `git push -u origin <branch>` and
   `gh pr create --body-file <file> ...` commands to run. Never merge or enable auto-merge.

If verification fails at any point, revert and report what happened rather
than attempting a workaround.
