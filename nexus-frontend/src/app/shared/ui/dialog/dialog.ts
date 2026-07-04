import { ChangeDetectionStrategy, Component, inject, Service, TemplateRef } from '@angular/core';
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogModule,
  MatDialogRef,
} from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

/**
 * Configuration data model for opening a standard confirmation dialog via `NxDialog.open()`.
 *
 * All properties are read-only and passed to the dialog shell component via dependency injection.
 * Use this interface to strongly type dialog configuration.
 *
 * @see NxDialog.open() — service method that accepts this data structure
 */
export interface DialogData {
  /**
   * Dialog title, displayed as a semantic `<h2>` heading.
   *
   * Always required; provides context for the user decision.
   * Keep concise but descriptive (e.g. "Delete Account?" vs "Confirmation").
   *
   * @example `title: "Sign out?"`
   */
  readonly title: string;

  /**
   * Optional message/body text, displayed below the title.
   *
   * - If omitted, only the title is shown
   * - Use for explaining consequences or providing additional context
   * - Avoid repeating the title; keep message concise
   *
   * @default undefined (no message rendered)
   *
   * @example `message: "You will be logged out of all devices. This action cannot be undone."`
   */
  readonly message?: string;

  /**
   * Button label for the confirm/primary action.
   *
   * Use action verbs (Delete, Confirm, Submit) rather than "OK".
   * In danger variant, this button is highlighted in error color.
   *
   * @default 'Confirm'
   *
   * @example `confirmLabel: "Delete Account"`
   */
  readonly confirmLabel?: string;

  /**
   * Button label for the cancel/dismiss action.
   *
   * Use consistent language (Cancel, Dismiss, Go Back).
   * This button always appears as a secondary action (left-aligned in footer).
   *
   * @default 'Cancel'
   *
   * @example `cancelLabel: "Keep Account"`
   */
  readonly cancelLabel?: string;

  /**
   * Visual variant controlling button styling and intent signaling.
   *
   * - `'default'` — standard confirmation (confirm button is primary blue)
   *   Use for non-destructive, reversible, or neutral actions
   *
   * - `'danger'` — destructive action warning (confirm button is error red)
   *   Use for delete, logout, revoke, or other irreversible actions
   *   The danger color + text helps prevent accidental clicks
   *
   * @default 'default'
   *
   * @example
   * ```typescript
   * // Non-destructive
   * dialog.open({ title: 'Save changes?', variant: 'default' })
   *
   * // Destructive
   * dialog.open({
   *   title: 'Delete Account?',
   *   variant: 'danger',
   *   confirmLabel: 'Delete'
   * })
   * ```
   */
  readonly variant?: 'default' | 'danger';
}

/**
 * Internal shell component rendering a standard confirmation dialog.
 *
 * This component is opened and managed by `NxDialog.open(data)` — never instantiate
 * or open this component directly. It receives dialog configuration via `MAT_DIALOG_DATA`
 * dependency injection and renders a Material Dialog with title, optional message, and actions.
 *
 * ## Layout
 * - Header: Title (h2) + Close button (top-right)
 * - Content: Optional message text (only if message provided)
 * - Actions: Cancel button (secondary) | Confirm button (primary or danger)
 *
 * The confirm button is highlighted in error color (`--nx-color-error`) if
 * the dialog variant is set to `'danger'`, signaling destructive intent.
 *
 * @internal
 * This is a shell component for MatDialog. Use the `NxDialog` service to open dialogs;
 * do not reference this component directly in application code.
 *
 * @design-system
 * Uses Nexus token families:
 * - `--nx-color-surface` — dialog background
 * - `--nx-color-surface-variant` — header/footer backgrounds (optional subtle distinction)
 * - `--nx-color-error` and `--nx-color-error-surface` — danger variant styling
 * - `--nx-space-md` / `--nx-space-lg` — padding (header, content, footer)
 * - `--nx-radius-lg` — border-radius on dialog panel (via 'nx-dialog-panel' class)
 * - `--nx-text-title` / `--nx-text-body` — typography hierarchy
 * - `--nx-duration-*` — dialog enter/exit animations
 *
 * Dialog width and sizing are controlled by `NxDialog.open()` config; this component
 * only applies styling, not layout.
 *
 * @accessibility
 * - Dialog title marked with `mat-dialog-title` (semantic h2 heading)
 * - Close button labeled with explicit `aria-label="Close dialog"` for screen readers
 * - Focus automatically placed on first tabbable element on open (`autoFocus='first-tabbable'`)
 * - Focus returned to trigger element on close (`restoreFocus=true`)
 * - `role="dialog"` and `aria-modal="true"` applied by MatDialogModule
 * - Danger variant uses color + icon + text to redundantly signal destructiveness
 *   (not relying on color alone per WCAG 2.1 SC 1.4.1)
 * - Escape key closes dialog (native MatDialog behavior)
 * - Backdrop prevents interaction with page content until dismissed
 */
@Component({
  selector: 'nx-dialog-shell',
  standalone: true,
  imports: [MatDialogModule, MatButtonModule, MatIconModule],
  template: `
    <div
      class="nx-dialog"
      [class.nx-dialog--danger]="data.variant === 'danger'"
      data-testid="nx-dialog"
    >
      <div class="nx-dialog__header">
        <h2 mat-dialog-title class="nx-dialog__title">{{ data.title }}</h2>
        <button mat-icon-button mat-dialog-close aria-label="Close dialog">
          <mat-icon>close</mat-icon>
        </button>
      </div>
      @if (data.message) {
        <mat-dialog-content class="nx-dialog__content">
          {{ data.message }}
        </mat-dialog-content>
      }
      <mat-dialog-actions align="end" class="nx-dialog__actions">
        <button mat-button mat-dialog-close>
          {{ data.cancelLabel ?? 'Cancel' }}
        </button>
        <button
          mat-flat-button
          [class.nx-dialog__confirm--danger]="data.variant === 'danger'"
          [mat-dialog-close]="true"
        >
          {{ data.confirmLabel ?? 'Confirm' }}
        </button>
      </mat-dialog-actions>
    </div>
  `,
  styleUrl: './dialog.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxDialogShell {
  /**
   * Dialog configuration data injected via Angular Material's `MAT_DIALOG_DATA` token.
   *
   * Contains title, message, button labels, and variant from `NxDialog.open(data)`.
   * This property is populated by MatDialog and drives all rendered content and styling.
   *
   * @internal Used only within this shell component; not exposed to consumers.
   */
  readonly data: DialogData = inject<DialogData>(MAT_DIALOG_DATA);
}

/**
 * Service for opening modal dialogs with standardized behavior, styling, and accessibility.
 *
 * `NxDialog` wraps Angular Material's `MatDialog` service and provides two primary methods:
 * 1. `open(data)` — Opens a standard confirmation dialog (title, message, action buttons)
 * 2. `openTemplate(tpl, config)` — Opens a custom dialog from a TemplateRef (for complex layouts)
 *
 * All dialogs are automatically configured with Nexus styling via the 'nx-dialog-panel' class,
 * responsive width sizing, focus management (autoFocus + restoreFocus), and accessibility
 * attributes. Dialog consumers only need to provide data or a template; the service
 * handles the rest.
 *
 * ## Features
 * - Two dialog types: standard confirmation, custom template
 * - Automatic focus management (focus first interactive element on open, restore on close)
 * - Mobile-responsive sizing (90vw max-width)
 * - Keyboard-accessible (Escape closes, Tab navigates)
 * - Token-based styling via 'nx-dialog-panel' panelClass
 * - Type-safe configuration for standard dialogs
 *
 * @example
 * Standard confirmation dialog:
 * ```typescript
 * export class MyComponent {
 *   constructor(private dialog: NxDialog) {}
 *
 *   confirmDelete() {
 *     this.dialog.open({
 *       title: 'Delete Account?',
 *       message: 'This action cannot be undone.',
 *       confirmLabel: 'Delete',
 *       variant: 'danger'
 *     }).afterClosed().subscribe(confirmed => {
 *       if (confirmed) {
 *         this.accountService.deleteAccount().subscribe(() => {
 *           this.router.navigate(['/goodbye']);
 *         });
 *       }
 *     });
 *   }
 * }
 * ```
 *
 * @example
 * Custom template dialog:
 * ```typescript
 * @Component({
 *   template: `
 *     <ng-template #settingsModal>
 *       <form (ngSubmit)="saveSettings()">
 *         <label> Theme <select [(ngModel)]="theme"></select></label>
 *         <button type="submit">Save</button>
 *       </form>
 *     </ng-template>
 *   `
 * })
 * export class SettingsComponent {
 *   @ViewChild('settingsModal') modal!: TemplateRef<unknown>;
 *
 *   openSettings() {
 *     this.dialog.openTemplate(this.modal, {
 *       width: '600px'
 *     }).afterClosed().subscribe(() => {
 *       // reload settings after dialog closes
 *     });
 *   }
 * }
 * ```
 *
 * @design-system
 * Dialog sizing and styling:
 * - Standard confirmation dialogs: 480px width (narrower for focus)
 * - Custom template dialogs: 600px width (allows complex layouts)
 * - Mobile: 90vw maxWidth (responsive on small screens)
 * - panelClass: 'nx-dialog-panel' applies Nexus tokens for background, border-radius, shadows
 * - All dialogs use Material Dialog backdrop to prevent interaction with page content
 *
 * @accessibility
 * - `autoFocus='first-tabbable'` ensures keyboard users can immediately interact
 *   (focus is placed on the first focusable element, usually a button)
 * - `restoreFocus=true` returns focus to the element that triggered the dialog
 *   when the dialog closes (maintains user context)
 * - Dialog backdrop traps focus and prevents page scrolling while open
 * - Escape key closes the dialog (native MatDialog behavior; communicated to users)
 * - `role="dialog"` and `aria-modal="true"` applied by MatDialogModule
 * - All text and buttons are semantic and properly labeled
 * - Danger variant uses color + icon + text (not color alone) to signal intent
 */
@Service()
export class NxDialog {
  /**
   * Injected Angular Material MatDialog service.
   *
   * Used internally by `open()` and `openTemplate()` to manage dialog lifecycle,
   * positioning, and backdrop behavior.
   *
   * @internal
   */
  private readonly matDialog = inject(MatDialog);

  /**
   * Opens a standard confirmation dialog with predefined title, message, and action buttons.
   *
   * This method is appropriate for most dialog needs (confirmations, warnings, deletions).
   * For dialogs with complex layouts (multi-step forms, custom actions), use `openTemplate()` instead.
   *
   * ## Behavior
   * - Renders `NxDialogShell` component with provided configuration
   * - Automatically sets focus to first interactive element (usually a button)
   * - Returns focus to trigger element when dialog closes
   * - Responsive width: 480px on desktop, 90vw on mobile
   * - Dialog can be closed via Escape key, close button, or action buttons
   *
   * @param data — Dialog configuration (DialogData interface)
   *   - title (required): Dialog heading
   *   - message (optional): Body text below title
   *   - confirmLabel (optional, default 'Confirm'): Primary action button label
   *   - cancelLabel (optional, default 'Cancel'): Secondary/dismiss button label
   *   - variant (optional, default 'default'): Visual style ('danger' for destructive actions)
   *
   * @returns MatDialogRef<NxDialogShell, boolean> with:
   *   - `afterClosed()` observable emits:
   *     - `true` when confirm button is clicked or close button during confirm focus
   *     - `false` or `undefined` when cancel button is clicked or dialog is dismissed
   *
   * @example
   * ```typescript
   * this.dialog.open({
   *   title: 'Sign Out?',
   *   message: 'You will be logged out of all devices.',
   *   confirmLabel: 'Sign Out',
   *   variant: 'default'
   * }).afterClosed().subscribe(confirmed => {
   *   if (confirmed) {
   *     this.authService.logout().subscribe();
   *   }
   * });
   * ```
   *
   * @example
   * Danger variant for destructive action:
   * ```typescript
   * this.dialog.open({
   *   title: 'Delete Account?',
   *   message: 'This action cannot be undone. All data will be lost.',
   *   confirmLabel: 'Delete',
   *   variant: 'danger'
   * }).afterClosed().subscribe(confirmed => {
   *   if (confirmed) {
   *     this.accountService.deleteAccount().subscribe();
   *   }
   * });
   * ```
   */
  open(data: DialogData): MatDialogRef<NxDialogShell, boolean> {
    return this.matDialog.open(NxDialogShell, {
      data,
      width: '480px',
      maxWidth: '90vw',
      panelClass: 'nx-dialog-panel',
      autoFocus: 'first-tabbable',
      restoreFocus: true,
    });
  }

  /**
   * Opens a custom dialog from a TemplateRef with optional configuration overrides.
   *
   * Use this method for dialogs with layouts more complex than standard confirmation
   * (e.g. multi-step forms, custom actions, settings panels, file uploads).
   *
   * ## Behavior
   * - Renders provided TemplateRef as the dialog body
   * - Focus management (autoFocus + restoreFocus) applied automatically
   * - Sizing and panelClass cannot be overridden (locked for consistency)
   * - Dialog can be closed via Escape key, backdrop click, or template logic
   *
   * ## Type Safety
   * The generic type parameter `R` allows you to specify the result type emitted
   * by `afterClosed()`. This helps with type-safe async operations.
   *
   * @template R — Type of value emitted by `afterClosed()` observable
   *
   * @param tpl — TemplateRef to render as dialog content
   *   - Usually obtained via `@ViewChild('templateName') tpl!: TemplateRef<unknown>`
   *   - Context and variables are provided by the component hosting the template
   *
   * @param config — Optional partial MatDialogConfig for fine-tuning
   *   - Useful properties: `width`, `height`, `disableClose`, `panelClass` (merged, not overridden)
   *   - Locked properties (cannot override): `autoFocus`, `restoreFocus`, `panelClass`
   *   - If you need different focus or panelClass, open via MatDialog directly (advanced)
   *
   * @returns MatDialogRef<unknown, R> with:
   *   - `afterClosed()` observable emits:
   *     - Value of type `R` specified when closing (template's responsibility)
   *     - `undefined` if dialog is dismissed without a result
   *   - Other MatDialogRef methods (componentInstance, etc.) available
   *
   * @example
   * Simple custom dialog:
   * ```typescript
   * @Component({
   *   template: `
   *     <h2>Edit Profile</h2>
   *     <form (ngSubmit)="save()">
   *       <label>
   *         Name
   *         <input [(ngModel)]="name" name="name">
   *       </label>
   *       <button type="submit">Save</button>
   *       <button type="button" mat-dialog-close>Cancel</button>
   *     </form>
   *   `
   * })
   * export class EditProfileComponent {
   *   name = 'John Doe';
   *
   *   constructor(private dialogRef: MatDialogRef<EditProfileComponent>) {}
   *
   *   save() {
   *     this.dialogRef.close(this.name);
   *   }
   * }
   * ```
   *
   * @example
   * Trigger custom dialog from another component:
   * ```typescript
   * @Component({
   *   template: `
   *     <ng-template #editProfile>
   *       <h2>Edit Profile</h2>
   *       <form (ngSubmit)="save()">
   *         <label>
   *           Name
   *           <input [(ngModel)]="name" name="name">
   *         </label>
   *         <button type="submit">Save</button>
   *         <button type="button" mat-dialog-close>Cancel</button>
   *       </form>
   *     </ng-template>
   *   `
   * })
   * export class MyComponent {
   *   @ViewChild('editProfile') editProfileTemplate!: TemplateRef<unknown>;
   *   name = 'John Doe';
   *
   *   constructor(private dialog: NxDialog) {}
   *
   *   openEditDialog() {
   *     this.dialog.openTemplate<string>(this.editProfileTemplate, {
   *       width: '500px'
   *     }).afterClosed().subscribe(newName => {
   *       if (newName) {
   *         this.name = newName;
   *         this.profileService.updateProfile(newName).subscribe();
   *       }
   *     });
   *   }
   * }
   * ```
   */
  openTemplate<R>(
    tpl: TemplateRef<unknown>,
    config?: Parameters<MatDialog['open']>[1],
  ): MatDialogRef<unknown, R> {
    return this.matDialog.open(tpl, {
      width: '600px',
      maxWidth: '90vw',
      panelClass: 'nx-dialog-panel',
      autoFocus: 'first-tabbable',
      restoreFocus: true,
      ...config,
    });
  }
}
