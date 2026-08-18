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
5. Commit and open a PR using the pr-authoring template.
6. Stop. Do not merge and do not enable auto-merge - report the PR URL.

If verification fails at any point, revert and report what happened rather
than attempting a workaround.
