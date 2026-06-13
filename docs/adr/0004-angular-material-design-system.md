# ADR 0004 — Angular Material 3 Design System

**Status:** Accepted
**Date:** 2026-06-12
**Author:** Engineering Team

## Context

Nexus is a multi-tenant SaaS platform. As features are built, every team member independently choosing colours, spacing, and interactive patterns produces visual and behavioural inconsistency, accessibility regressions, and exponential rework when branding changes. A shared design system solves this before the problem compounds.

Key constraints:
- **Accessibility first.** WCAG 2.1 AA is non-negotiable for enterprise customers.
- **Brandable.** Colours and shape need to be swappable per tenant without a code change.
- **Angular 21.** Any UI library must integrate natively with standalone components, signals, and the Angular CDK.
- **Minimal abstraction cost.** The team should rarely need to think about the underlying library.

## Decision

We adopt **Angular Material 21 (Material Design 3)** as the component engine, skinned through a thin **`shared/ui` wrapper layer** using **CSS custom properties (`--nx-*`)** as design tokens.

### Structure

```
nexus-frontend/src/
├── styles/
│   ├── _tokens.scss          # --nx-* CSS custom properties (brand, semantic, spacing, radius, type, motion)
│   └── _material-theme.scss  # mat.define-theme() + mat.all-component-themes() + token bridge
├── styles.scss               # @use tokens + theme; global resets
└── app/shared/ui/
    ├── button/               # nx-button  → token-native (MatIcon only)
    ├── card/                 # nx-card    → MatCard
    ├── input/                # nx-input   → MatInput + MatFormField  (CVA)
    ├── select/               # nx-select  → MatSelect               (CVA)
    ├── table/                # nx-table   → MatTable + MatSort + MatPaginator
    ├── dialog/               # nx-dialog  → MatDialog (service helper)
    ├── toast/                # NxToast    → MatSnackBar (injectable service)
    ├── empty-state/          # nx-empty-state  (no Material dep, uses MatIcon)
    ├── error-state/          # nx-error-state  (role=alert, retry output)
    └── index.ts              # barrel re-export
```

### Rules enforced by this ADR

1. **App code never imports `@angular/material` directly.** Only `shared/ui` imports Material modules.
2. **Components never use raw hex/px values.** All visual values come from `--nx-*` tokens.
3. **Token names are stable.** Changing the underlying colour requires only a token value update.
4. **CVA pattern for form controls.** `NxInput` and `NxSelect` implement `ControlValueAccessor` — they integrate with Angular reactive forms transparently.
5. **Accessibility contract:** every wrapper maintains the ARIA contract of its Material base; any `aria-*` or `role` deviation must be documented in the component.

### Design sync

The `shared/ui/preview/design-system.html` file is the canonical visual spec. It is pushed to the **"Nexus Design System"** project in Claude Design via `DesignSync` on each iteration, giving designers a live view without a running dev server.

## Alternatives Considered

| Option | Rejected because |
|--------|-----------------|
| **Tailwind CSS + HeadlessUI** | No Angular-native component set; accessibility primitives must be hand-built for every component. Higher ongoing a11y surface. |
| **PrimeNG** | Heavier bundle; weaker Material 3 tokens / CSS variable story; less aligned with the Angular team's own patterns. |
| **Raw MDC (no Angular Material)** | More control, but we lose Angular CDK overlays, focus management, and form integration that Material provides for free. |
| **No shared library — inline styles** | Already the status quo pain point this ADR resolves. |

## Consequences

**Positive:**
- A11y primitives (focus management, keyboard nav, ARIA) come from the Angular/Material team — maintained upstream.
- Token-based theming makes multi-tenant branding a config change, not a code change.
- `shared/ui` gives a single choke point to upgrade Material or swap it entirely without touching feature code.
- Claude Design sync keeps designers in the loop without a Storybook instance.

**Negative / trade-offs:**
- Angular Material's component set has opinions; highly custom UI patterns (e.g. a bespoke data grid) will need CDK primitives and more wrapper effort.
- The `@angular/material` bundle adds ~60–80 kB gzipped to the initial chunk; mitigated by lazy-loading and tree-shaking.
- Material 3 is still evolving; some M3-specific tokens may change across minor Angular versions.

**Follow-on work:**
- [ ] Add a `design-system` CI check that builds `design-system.html` and fails on broken imports.
- [ ] Extend `angular-standards` skill with design-system rules (see `.claude/skills/design-system/`).
- [ ] Write `nx-chip`, `nx-badge`, `nx-spinner`, `nx-breadcrumb` as the first features need them.
- [ ] Add `@angular/material` theming tokens to the tenant config system when multi-tenancy lands.
