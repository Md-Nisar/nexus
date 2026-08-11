---
name: design-system
description: Use when writing or reviewing any UI code in the Nexus frontend. Enforces the Angular Material 3 + --nx-* tokens + shared/ui wrapper rules from ADR 0004.
---

# Nexus Design System Standards

Reference: [ADR 0004](../../../docs/adr/0004-angular-material-design-system.md)

## The golden rule

**App-level code never imports `@angular/material` directly.**
All Material usage is encapsulated in `src/app/shared/ui/`. Feature components import only from there.

```ts
// ✅ Correct
import { NxButton, NxCard } from '@shared/ui';

// ❌ Wrong
import { MatButtonModule } from '@angular/material/button';
```

## Tokens — `--nx-*` CSS custom properties

All visual values (colour, spacing, radius, type, motion) come from `src/styles/_tokens.scss`.

```scss
// ✅ Correct
.my-panel {
  background-color: var(--nx-color-surface);
  padding: var(--nx-space-4);
  border-radius: var(--nx-radius-sm);
  color: var(--nx-color-on-surface);
}

// ❌ Wrong — never raw values
.my-panel {
  background-color: #ffffff;
  padding: 16px;
  border-radius: 8px;
  color: #202124;
}
```

### Token families

| Family | Prefix | Examples |
|--------|--------|---------|
| Color — brand | `--nx-color-primary` | `primary`, `primary-hover`, `primary-surface` |
| Color — semantic | `--nx-color-error` | `error`, `warning`, `success`, `info` (+ `-surface` variants) |
| Color — neutral | `--nx-color-canvas` / `--nx-color-surface` | `canvas`, `surface`, `surface-2`, `surface-3`, `surface-variant`, `outline`, `outline-variant`, `outline-strong`, `on-surface`, `on-surface-muted`, `on-surface-faint`, `on-surface-dim` |
| Spacing | `--nx-space-N` | `1`=4px … `24`=96px |
| Border radius | `--nx-radius-*` | `xs`=4px, `sm`=6px, `md`=8px, `lg`=12px, `xl`=16px, `2xl`=24px, `full` |
| Typography | `--nx-text-*`, `--nx-weight-*`, `--nx-leading-*` | sizes: `xs`–`6xl`; weights: `regular`=400 / `medium`=500 / `semibold`=600 / `bold`=700 |
| Shadow | `--nx-shadow-*` | `xs`–`xl` — **all `none` in dark mode** (depth via surface lift + hairline); real values only under `prefers-color-scheme: light` |
| Motion | `--nx-duration-*`, `--nx-easing-*` | `fast`=100ms, `base`=150ms, `slow`=250ms |
| Z-index | `--nx-z-*` | `dropdown/sticky/overlay/modal/toast/tooltip` |

## `shared/ui` components

| Selector | Source | Wraps | Notes |
|----------|--------|-------|-------|
| `<nx-button>` | `shared/ui/button` | _(token-native; `MatIcon` only)_ | variants: `primary/secondary/tertiary/danger/ghost`; sizes: `sm/md/lg`; `loading` input |
| `<nx-card>` | `shared/ui/card` | `MatCard` | elevations: `raised/flat/outlined`; `[slot=header-actions]` + `[slot=actions]` |
| `<nx-input>` | `shared/ui/input` | `MatInput` + `MatFormField` | CVA — works with `formControl` / `ngModel`; `prefixIcon`, `suffixIcon`, `hint`, `error` |
| `<nx-select>` | `shared/ui/select` | `MatSelect` | CVA; generic `SelectOption<T>`; `multiple` input |
| `<nx-table>` | `shared/ui/table` | `MatTable` + `MatSort` + `MatPaginator` | `columns: TableColumn[]`; `loading`; `pageable`; `rowClick` / `sortChange` / `pageChange` outputs |
| `<nx-dialog>` | `shared/ui/dialog` | `MatDialog` | inject `NxDialog`; call `.open(DialogData)` or `.openTemplate(tpl)` |
| `NxToast` | `shared/ui/toast` | `MatSnackBar` | injectable service; `.success()`, `.error()`, `.warning()`, `.info()` |
| `<nx-empty-state>` | `shared/ui/empty-state` | `MatIcon` | required `title` input; `icon` + `description` optional; `role=status` |
| `<nx-error-state>` | `shared/ui/error-state` | `MatIcon` + `MatButton` | `retry` output; `showRetry` input; `role=alert` |

All components:
- `standalone: true`, `ChangeDetectionStrategy.OnPush`
- Inputs declared with `input()` / `input.required()` functions (not decorators)
- Outputs declared with `output()` functions
- `data-testid` attribute on the root interactive element

## Writing a new `shared/ui` component

1. Create `src/app/shared/ui/<name>/<name>.ts` + `.scss` + `.spec.ts`
2. The component selector must be `nx-<name>` with `standalone: true` and `OnPush`
3. Import only from `@angular/material/*` and `@angular/cdk/*` — never from feature modules
4. Never use raw values in SCSS; always `var(--nx-*)` tokens
5. Add to `shared/ui/index.ts` barrel
6. Write a spec covering all component inputs + outputs and accessibility attributes
7. Add a preview card in `shared/ui/preview/design-system.html`
8. Re-run DesignSync (`/design-sync`) to push the update to Claude Design

## Forbidden patterns

| Pattern | Replacement |
|---------|-------------|
| `import { MatButtonModule } from '@angular/material/button'` in a feature | Use `<nx-button>` from `shared/ui` |
| Raw hex / px / rem values in component SCSS | `var(--nx-*)` token |
| `::ng-deep` without a comment explaining why | Avoid entirely; use `panelClass` for overlay styling |
| Direct `MatSnackBar` injection in a feature | `NxToast` service |
| `new MatDialog().open(...)` in a feature | `NxDialog.open(DialogData)` |

## Testing

- Use `data-testid` attributes for all stable selectors
- Every CVA component (NxInput, NxSelect) must be tested with `writeValue`, `setDisabledState`
- Every stateful component must cover all states (disabled, loading, error, empty)

## Accessibility contract

| Requirement | Enforcement |
|-------------|-------------|
| Color contrast ≥ 4.5:1 for normal text, 3:1 for large/UI | Token values are pre-checked; never override without re-checking |
| Focus ring visible | `:focus-visible` in `styles.scss` — do not remove |
| Interactive elements keyboard-reachable | Use `<button>`, not `<div click>`; `MatButton` handles this |
| ARIA roles on non-semantic containers | `role=status` on `nx-empty-state`, `role=alert` on `nx-error-state` |
| `aria-label` on icon-only buttons | Pass via `ariaLabel` input |
