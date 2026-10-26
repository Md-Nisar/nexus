# US-020 pending items

What is still open after the implementation, the code and security reviews, their delta reviews and
the follow-up fixes. **Closed in code** items are listed so a reader can see what changed since the
review reports; **Open** items need a person, an environment this repository's sandbox does not have,
or a backend change outside this story's scope. Nothing here is an approval: the gates in
`01-requirements.md`, `03-design.md` and `04-tasks.md` record who approved what.

## Closed in code

| Item | Resolution |
|---|---|
| Edge security headers lost in `location /` and the static-asset location (security High) | One shared snippet `nexus-frontend/nginx/nexus-security-headers.conf`, included at server level and in every location that sets a header; pinned by `e2e/tools/tools.selftest.mjs`; checked by the edge smoke. |
| CSP `script-src 'self'` blocked Angular's critical-CSS inline script (delta NEW-H1) | Production build has `inlineCritical: false`; `e2e/tools/check-index-csp.mjs` fails CI on an inline script, handler or print-media swap in the built `index.html`. |
| F-5: registration accepted bidi/zero-width/space-separator characters in the address | `RegisterRequest.email` rejects control/format/private-use/unassigned/surrogate characters, space separators and the invisible fillers (`RegisterRequestValidationTest`). The e2e target for RC-68 stays seeded by the dev seeder. |
| `NxInput` never showed its `error` (code review MN-3; affected the auth forms) | The inner `matInput` has its own form control and an error matcher driven by the `error` input (`input.spec.ts`). |
| Create page could trap the user while a request never answers (delta m3) | A create in flight refuses a leave for at most 15 s (`LEAVE_REFUSAL_MS`), then lets the user go; destroying the page cancels the request and refreshes the roles list. |
| Review Majors MJ-1..MJ-5 and the Minors/Lows listed in the fix-pass commit | See commit `77d03f6` and the delta reviews. |

## Open: backend follow-ups (outside this story's frontend-only scope)

| ID | Item | Why it is not done here |
|---|---|---|
| F-1 | Distinct administrator count and a per-role `isAdminDefining` flag, so the console can replace its permission-count hint | New backend API and contract; needs its own story and design. |
| F-2 | Role fields (name, system flag) on a user's assignments response, so the user page needs no roles join | New backend API field; needs its own story. |
| F-3 | Audited export of the user directory | New backend feature with audit and retention decisions. |
| F-4 | Take over (or reject) role grants on a PENDING account at email verification | Identity-domain change; until it lands the console blocks administrator-looking roles for unverified targets (H-2). |

## Open: needs a person or an environment

| ID | Item | Owner |
|---|---|---|
| H-1 | Platform Security Owner accepts the public-route pin widening to `/unavailable` and the `authGuard` change | Platform Security Owner |
| H-2 | Record the decision that administrator-looking roles stay blocked for unverified targets until F-4 (switch: `PENDING_ADMIN_ROLE_BLOCK`) | Story owner, before the S3b merge |
| H-3 | Schedule F-4 (and confirm F-5 reached the identity owner) | Identity owner |
| H-4 | Confirm the production edge sends the shared security headers, keeps strong ETags (`gzip off` for `/api/`), and name a non-administrator smoke identity (D-3(d)) | Ops |
| H-5 | Decide and rehearse the kill-switch off path (`accessConsoleEnabled`) | Release manager |
| H-6 | Data-protection officer acknowledgement of the user-directory email exposure; blocks enabling `us019` in production | DPO |
| UX/PM | Approve the provisional D2 designs and D3 content deck, and the provisional copy added during implementation | UX / PM |
| P-11 | First green full-stack e2e run on CI (`E2E_MIN_TESTS` is pinned to the Playwright list) | CI |

## Open: measurements

| Item | Note |
|---|---|
| FR-F8 (role detail interactive within 1 s; 500 roles under 200 ms) | Needs a measured run on a realistic stack; no number is recorded anywhere. |
| Safari / VoiceOver table semantics at 320 px, manual WCAG checks | Manual; the PR template carries the checklist. |

## Known smaller items

- Registration address check (F-5) is a denylist of control, format, private-use, unassigned,
  surrogate and separator characters plus known invisible fillers. It does not catch look-alike
  (confusable or mixed-script) addresses, and nonspacing marks stay allowed because real scripts need
  them. An allowlist or NFKC plus confusable check is a decision for the identity owner (RES-54).
- Low 5 (security review): log redaction matches key names only; an anchored regex would stop
  redacting keys such as `userEmail`, so it was left as is.
- Three copies of the roles-list `::ng-deep` card layout and the repeated 403 code set / `toAppError`
  helpers are candidates for a shared helper in a refactor story.
- The roles list is re-read after an assign or revoke by fetching every page (up to 5 requests on a
  large tenant).
