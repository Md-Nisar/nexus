import {
  ChangeDetectionStrategy,
  Component,
  forwardRef,
  input,
  output,
  signal,
} from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';

/**
 * Configurable option for `NxSelect` dropdown menu.
 * Used to define available choices in the selection list.
 *
 * @template T Type of the option value (defaults to string)
 *
 * @example
 * const options: SelectOption<number>[] = [
 *   { label: 'Small', value: 1 },
 *   { label: 'Medium', value: 2 },
 *   { label: 'Large', value: 3, disabled: true }
 * ];
 */
export interface SelectOption<T = string> {
  /** Display text shown in the dropdown menu and trigger button. */
  readonly label: string;
  /** Underlying value returned by the form when this option is selected. */
  readonly value: T;
  /** If true, option cannot be selected; shown with disabled styling. */
  readonly disabled?: boolean;
}

/**
 * Dropdown select component built on Material Design 3.
 *
 * Provides a controlled single- or multi-select dropdown with optional label,
 * hint, and error message. Generic `T` parameter allows type-safe values
 * (e.g., `NxSelect<number>` for numeric IDs). Implements `ControlValueAccessor`
 * for seamless integration with reactive forms and `[(ngModel)]`.
 *
 * @template T Type of option values (defaults to string)
 *
 * @example
 * // Single-select with string values
 * <nx-select
 *   label="Country"
 *   placeholder="Select a country"
 *   [options]="countryOptions"
 *   [formControl]="countryControl"
 *   (selectionChange)="onCountryChange($event)"
 * />
 *
 * @example
 * // Multi-select with numeric IDs
 * <nx-select
 *   label="Assigned users"
 *   [options]="userOptions"
 *   [multiple]="true"
 *   [formControl]="assignedUsersControl"
 *   [error]="assignedUsersControl.errors | json"
 * />
 *
 * @example
 * // Type-safe multi-select component
 * <app-user-selector
 *   [userOptions]="users$ | async"
 *   [formControl]="selectedUserIds"
 * />
 * // In component:
 * users$: Observable<SelectOption<number>[]> = ...;
 * selectedUserIds: FormControl<number[]> = new FormControl([]);
 *
 * @accessibility
 * - `aria-label` automatically derived from `label()` input
 * - Dropdown menu has `role=listbox` (implicit via MatSelect)
 * - Options have `role=option` (implicit); disabled options announced as disabled
 * - Keyboard navigation: ↑/↓ to navigate, Space/Enter to select, Esc to close
 * - Multiple selection: maintains focus after each selection for rapid multi-choice
 * - Error messages associated via Material's implicit ARIA linking in form fields
 * - Hint text available to screen readers via `<mat-hint>` implicit association
 *
 * @ux-notes
 * - Dropdown panel opens below the trigger button; scrolls within viewport if needed
 * - Selected values shown as chips in multi-select mode for easy visual confirmation
 * - Disabled options are greyed out but keyboard-navigable (not selectable)
 * - Empty dropdown (no options provided) shows no visual feedback; parent should
 *   handle loading states separately (use NxErrorState or NxEmptyState as needed)
 * - Material filterable select pattern not built-in; for large lists (100+ items),
 *   consider using a custom filtered dropdown component
 * - Validation errors are shown inline below the select (same as NxInput);
 *   parent form should call `markAsTouched()` after blur
 * - Change detection is OnPush; use signal inputs for reactive option updates
 *
 * @state-management
 * - Single-select: stores a single `T` value or null
 * - Multi-select: stores `T[]` array; empty array when no selections
 * - Disabled state managed via form control disabled flag (setDisabledState callback)
 *
 * @see {@link ControlValueAccessor} for form integration details
 * @see {@link SelectOption} for option structure
 * @see Material 3 select specifications for design reference
 */
@Component({
  selector: 'nx-select',
  standalone: true,
  imports: [MatFormFieldModule, MatSelectModule],
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => NxSelect),
      multi: true,
    },
  ],
  template: `
    <mat-form-field class="nx-select" appearance="outline" subscriptSizing="dynamic">
      @if (label()) {
        <mat-label>{{ label() }}</mat-label>
      }
      <mat-select
        [value]="value()"
        [disabled]="isDisabled()"
        [placeholder]="placeholder()"
        [multiple]="multiple()"
        [attr.aria-label]="label() || null"
        (selectionChange)="onSelect($event.value)"
        (blur)="onTouched()"
        data-testid="nx-select"
      >
        @for (opt of options(); track opt.value) {
          <mat-option [value]="opt.value" [disabled]="opt.disabled ?? false">
            {{ opt.label }}
          </mat-option>
        }
      </mat-select>
      @if (hint()) {
        <mat-hint>{{ hint() }}</mat-hint>
      }
      @if (error()) {
        <mat-error>{{ error() }}</mat-error>
      }
    </mat-form-field>
  `,
  styleUrl: './select.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxSelect<T = string> implements ControlValueAccessor {
  /**
   * Visible label text displayed above the select.
   * Also used to populate `aria-label` for screen readers.
   * @default ''
   */
  readonly label = input<string>('');

  /**
   * Placeholder text shown when no option is selected.
   * @default ''
   */
  readonly placeholder = input<string>('');

  /**
   * Array of selectable options.
   * Each option has a label (display text) and value (form value).
   * Options can be individually disabled.
   * @default []
   */
  readonly options = input<SelectOption<T>[]>([]);

  /**
   * Helper text displayed below the select in secondary color.
   * Use for constraint descriptions or guidance.
   * Not shown if error() is present.
   * @default ''
   */
  readonly hint = input<string>('');

  /**
   * Error message displayed below the select in error color.
   * When non-empty, replaces hint and shifts focus to error state.
   * Parent form should bind to validation errors from FormControl.
   * @example
   * [error]="form.get('country')?.errors?.['required'] ? 'Country is required' : ''"
   * @default ''
   */
  readonly error = input<string>('');

  /**
   * If true, enables multi-select mode.
   * - Single-select (false): `value()` is `T | null`
   * - Multi-select (true): `value()` is `T[]`
   * - FormControl type should match: `FormControl<T>` vs `FormControl<T[]>`
   * @default false
   */
  readonly multiple = input(false);

  /**
   * Emitted when selection changes.
   * Fires after user selects/deselects an option.
   * Payload type matches the current selection mode:
   * - Single-select: `T` (the selected value)
   * - Multi-select: `T[]` (array of selected values)
   * @event
   */
  readonly selectionChange = output<T | T[]>();

  protected readonly value = signal<T | T[] | null>(null);
  protected readonly isDisabled = signal(false);

  private onChange: (v: T | T[] | null) => void = () => {
    /* replaced by registerOnChange */
  };
  protected onTouched: () => void = () => {
    /* replaced by registerOnTouched */
  };

  writeValue(val: T | T[] | null): void {
    this.value.set(val ?? null);
  }

  registerOnChange(fn: (v: T | T[] | null) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  setDisabledState(disabled: boolean): void {
    this.isDisabled.set(disabled);
  }

  protected onSelect(val: T | T[]): void {
    this.value.set(val);
    this.onChange(val);
    this.selectionChange.emit(val);
  }
}
