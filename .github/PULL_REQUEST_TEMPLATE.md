<!-- PR title MUST be a Conventional Commit: <type>(<scope>): <summary>
     types: feat, fix, docs, test, refactor, chore, perf, security, build, ci
     The PR Title check enforces this. -->

## What

<!-- One sentence: what does this PR change? -->

## Why

<!-- Link the ticket: NEXUS-XXXX. Context a reviewer needs. -->

## How to test

<!-- Commands or steps. Screenshots for UI changes. -->

## Definition of Done

The canonical checklist lives in [CONTRIBUTING.md → Definition of Done](../CONTRIBUTING.md#definition-of-done-canonical--the-pr-template-and-pr-checklist-skill-reference-this-list).

- [ ] I ran `/pre-pr-check` (or walked the checklist manually) and every item passes

### UI changes: manual WCAG 2.2 checks

<!-- axe cannot fully cover these. Tick or write "n/a" for PRs without UI changes. -->

- [ ] 2.4.11 Focus Not Obscured: tabbing through the page never leaves the focused element hidden under a sticky header, the shell header or an overlay
- [ ] 2.5.8 Target Size (Minimum): every new pointer target (icon buttons, chips, checkboxes) is at least 24 by 24 CSS px, taken from tokens
- [ ] 1.4.10 Reflow: at 320 CSS px wide the page has no horizontal scroll (only a tab bar or a table may scroll inside its own container)
- [ ] Keyboard-only walkthrough: every new control, editor and dialog is reachable and operable with the keyboard alone, focus order is logical, and focus returns where it started when a dialog closes
- [ ] Screen-reader pass of the access-console permission matrix and dialogs with NVDA + Firefox and with VoiceOver + Safari (US-020 design §13)

### Access-console propagation copy

- [ ] If either TTL changes in `application.yml` or an environment (`nexus.jwt.access-token-ttl-seconds`, `nexus.rbac.permission-cache-ttl-seconds`), update `propagation.ts` (US-020 design §9.3)

<!-- For substantial features, link the docs/features/<ID>/ artifacts and confirm code + security reviews passed. -->
