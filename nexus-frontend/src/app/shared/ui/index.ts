/**
 * @fileoverview Nexus shared UI component library
 *
 * A comprehensive, accessible, Material Design 3-based component library for Nexus applications.
 * All components are:
 * - **Standalone**: No NgModule; imported directly into components
 * - **Signals-based**: Modern Angular control flow (@if/@for/etc)
 * - **Accessible**: WCAG 2.1 AA compliant with full keyboard and screen reader support
 * - **Themed**: Design tokens-driven; responds to light/dark mode automatically
 * - **Type-safe**: Full TypeScript strict mode support
 *
 * ## Component Categories
 *
 * ### Form Inputs
 * - `NxInput` — text input field with labels, errors, and validation
 * - `NxSelect` — dropdown select with custom options
 *
 * ### Feedback & Data Display
 * - `NxTable` — data table with sorting, pagination, and flexible cell types
 * - `NxBadge` — semantic status labels with color variants
 * - `NxCard` — container with elevation and optional interactive state
 *
 * ### Dialogs & Overlays
 * - `NxDialog` — modal dialog with backdrop and configurable content
 * - `NxDialogShell` — internal shell component for dialog structure
 *
 * ### Notifications & States
 * - `NxToast` — brief, dismissible notifications (success/error/warning/info)
 * - `NxEmptyState` — placeholder UI for zero-data states (search results, lists)
 * - `NxErrorState` — prominent error UI with retry action and recovery options
 *
 * ### Actions
 * - `NxButton` — primary/secondary/tertiary buttons with variants and sizes
 *
 * ## Usage Examples
 *
 * ### Import a component
 * ```typescript
 * import { NxButton, NxTable, TableColumn } from '@shared/ui';
 *
 * @Component({
 *   imports: [NxButton, NxTable],
 *   template: `
 *     <button nx-button variant="primary" (click)="save()">Save</button>
 *     <nx-table [columns]="columns()" [rows]="rows()" />
 *   `
 * })
 * export class MyComponent { ... }
 * ```
 *
 * ### Use a service
 * ```typescript
 * import { NxToast } from '@shared/ui';
 *
 * constructor(private toast: NxToast) {}
 *
 * onSubmit() {
 *   this.api.save(data).subscribe({
 *     next: () => this.toast.success('Saved'),
 *     error: () => this.toast.error('Failed to save'),
 *   });
 * }
 * ```
 *
 * ## Design System
 *
 * All components use **design tokens** defined in CSS custom properties:
 * - `--nx-color-{primary,success,error,warning,info}` — semantic colors
 * - `--nx-space-{xs,sm,md,lg,xl}` — spacing scale
 * - `--nx-text-{sm,base,lg}` — typography sizes
 * - `--nx-radius-{sm,md,lg}` — border radius scale
 * - `--nx-duration-{fast,normal,slow}` — animation durations
 *
 * Themes (light/dark) are automatically switched based on user preference or explicit setting.
 *
 * ## Accessibility
 *
 * Every component includes:
 * - **Semantic HTML**: `<button>`, `<input>`, `<table>`, `<div role="alert">`, etc.
 * - **ARIA attributes**: `aria-label`, `aria-live`, `aria-expanded`, etc.
 * - **Keyboard support**: Full tab order, arrow keys, Enter/Space activation
 * - **Screen reader announcements**: Status changes, dynamic content, form errors
 * - **Color contrast**: ≥4.5:1 (WCAG AA) for all text-on-color combinations
 * - **Focus indicators**: Visible, high-contrast focus rings
 * - **Form validation**: Error messages linked to inputs via `aria-describedby`
 *
 * See each component's JSDoc for detailed accessibility notes.
 *
 * ## Testing
 *
 * All components include:
 * - `data-testid` attributes for robust test selection
 * - Vitest + Playwright integration tests
 * - Coverage gates enforced in CI
 *
 * Example test:
 * ```typescript
 * it('emits rowClick when table row is clicked', () => {
 *   const fixture = TestBed.createComponent(NxTable);
 *   fixture.componentRef.setInput('rows', [{ id: '1', name: 'Alice' }]);
 *   fixture.detectChanges();
 *   fixture.nativeElement.querySelector('tbody tr').click();
 *   expect(rowClickSpy).toHaveBeenCalledWith({ id: '1', name: 'Alice' });
 * });
 * ```
 *
 * ## ADR References
 * - ADR 0004: Design System & UI Component Governance
 * - ADR 0011: Accessibility Standards
 */

export { NxBadge } from './badge/badge';
export type { BadgeVariant } from './badge/badge';

export { NxButton } from './button/button';
export type { ButtonVariant, ButtonSize } from './button/button';

export { NxCard } from './card/card';
export type { CardElevation } from './card/card';

export { NxInput } from './input/input';

export { NxSelect } from './select/select';
export type { SelectOption } from './select/select';

export { NxTable } from './table/table';
export type { TableColumn, CellType } from './table/table';

export { NxDialog, NxDialogShell } from './dialog/dialog';
export type { DialogData } from './dialog/dialog';

export { NxToast } from './toast/toast';
export type { ToastVariant, ToastOptions } from './toast/toast';

export { NxEmptyState } from './empty-state/empty-state';

export { NxErrorState } from './error-state/error-state';
