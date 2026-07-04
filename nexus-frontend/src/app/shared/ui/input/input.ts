import {
  ChangeDetectionStrategy,
  Component,
  forwardRef,
  input,
  output,
  signal,
} from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR, ReactiveFormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';

/**
 * Text input wrapper component built on Material Design 3.
 *
 * Provides a controlled text input with optional label, hint, error message,
 * and icon support. Implements `ControlValueAccessor` for seamless integration
 * with reactive forms and `[(ngModel)]`.
 *
 * @example
 * // Reactive form usage
 * <nx-input
 *   inputId="email-input"
 *   label="Email address"
 *   type="email"
 *   placeholder="Enter your email"
 *   hint="We'll never share your email"
 *   [error]="form.get('email')?.errors | json"
 *   [formControl]="form.get('email')"
 * />
 *
 * @example
 * // With prefix icon and suffix action
 * <nx-input
 *   label="Password"
 *   type="password"
 *   prefixIcon="lock"
 *   suffixIcon="visibility_off"
 *   (suffixIconClick)="togglePasswordVisibility()"
 *   [formControl]="passwordControl"
 * />
 *
 * @accessibility
 * - `aria-label` automatically derived from `label()` input
 * - Native HTML input ensures keyboard navigation support
 * - Icons marked with `aria-hidden="true"` to avoid redundant announcements
 * - Error messages associated via Material's implicit ARIA linking in form fields
 * - Hint text available to screen readers via `<mat-hint>` implicit association
 *
 * @ux-notes
 * - Validation errors are shown inline below the input; parent form should call
 *   `markAsTouched()` after blur to trigger error display (Material FormField
 *   handles this automatically via `onTouched()` callback)
 * - Hint text appears in secondary text color and is useful for constraint
 *   descriptions (e.g., "Min 8 characters, 1 uppercase")
 * - Icon buttons (suffix) inherit cursor pointer; use them for actions like
 *   password reveal or clear field
 * - Type attribute controls input behavior: use `email`, `password`, `number`, etc.
 *   to enable browser-native validation and mobile keyboards
 * - Autocomplete attribute affects browser password managers and autofill; set to
 *   `username`, `email`, `password`, etc. for semantic meaning
 *
 * @see {@link ControlValueAccessor} for form integration details
 * @see Material 3 text field specifications for design reference
 */
@Component({
  selector: 'nx-input',
  standalone: true,
  imports: [MatFormFieldModule, MatInputModule, MatIconModule, ReactiveFormsModule],
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => NxInput),
      multi: true,
    },
  ],
  template: `
    <mat-form-field class="nx-input" [appearance]="appearance()" subscriptSizing="dynamic">
      @if (label()) {
        <mat-label>{{ label() }}</mat-label>
      }
      @if (prefixIcon()) {
        <mat-icon matPrefix>{{ prefixIcon() }}</mat-icon>
      }
      <input
        matInput
        [id]="inputId()"
        [type]="type()"
        [placeholder]="placeholder()"
        [disabled]="isDisabled()"
        [value]="value()"
        [attr.aria-label]="label() || null"
        [attr.autocomplete]="autocomplete()"
        (input)="onInput($event)"
        (blur)="onTouched()"
        data-testid="nx-input"
      />
      @if (suffixIcon()) {
        <mat-icon matSuffix style="cursor: pointer" (click)="suffixIconClick.emit()">{{
          suffixIcon()
        }}</mat-icon>
      }
      @if (hint()) {
        <mat-hint>{{ hint() }}</mat-hint>
      }
      @if (error()) {
        <mat-error>{{ error() }}</mat-error>
      }
    </mat-form-field>
  `,
  styleUrl: './input.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxInput implements ControlValueAccessor {
  /**
   * HTML id attribute for the input element.
   * Used for associating labels and accessibility features.
   * @default ''
   */
  readonly inputId = input<string>('');

  /**
   * Visible label text displayed above the input.
   * Also used to populate `aria-label` for screen readers.
   * Omit to hide the label (placeholder becomes visible hint).
   * @default ''
   */
  readonly label = input<string>('');

  /**
   * Placeholder text shown when input is empty.
   * @default ''
   */
  readonly placeholder = input<string>('');

  /**
   * HTML input type attribute.
   * Common values: `text`, `email`, `password`, `number`, `tel`, `url`, `date`, `time`.
   * Controls browser validation, mobile keyboard layout, and autofill behavior.
   * @default 'text'
   */
  readonly type = input<string>('text');

  /**
   * Helper text displayed below the input in secondary color.
   * Use for constraint descriptions (e.g., "Min 8 characters, 1 uppercase")
   * or guidance. Not shown if error() is present.
   * @default ''
   */
  readonly hint = input<string>('');

  /**
   * Error message displayed below the input in error color.
   * When non-empty, replaces hint and shifts focus to error state.
   * Parent form should bind to validation errors from FormControl.
   * @example
   * [error]="form.get('email')?.errors?.['required'] ? 'Email is required' : ''"
   * @default ''
   */
  readonly error = input<string>('');

  /**
   * Material icon name to display before the input text.
   * Marked as decorative (`aria-hidden`); use label/hint for semantic meaning.
   * @default ''
   */
  readonly prefixIcon = input<string>('');

  /**
   * Material icon name to display after the input text.
   * Typically used for action buttons (e.g., password reveal, clear field).
   * Emits `suffixIconClick` when clicked.
   * @default ''
   */
  readonly suffixIcon = input<string>('');

  /**
   * HTML autocomplete attribute value.
   * Common values: `off`, `on`, `username`, `email`, `password`, `current-password`.
   * Affects browser password managers and autofill behavior.
   * @default 'off'
   */
  readonly autocomplete = input<string>('off');

  /**
   * Material form field appearance variant.
   * - `outline`: bordered box (recommended for standard forms)
   * - `fill`: filled background (legacy, not recommended for new designs)
   * @default 'outline'
   */
  readonly appearance = input<'fill' | 'outline'>('outline');

  /**
   * Emitted when the input value changes.
   * Fires after every keystroke; for validation, use FormControl.valueChanges instead.
   * @event
   */
  readonly valueChange = output<string>();

  /**
   * Emitted when the suffix icon is clicked.
   * Typical use: toggle password visibility or clear the field.
   * @event
   */
  readonly suffixIconClick = output<void>();

  protected readonly value = signal('');
  protected readonly isDisabled = signal(false);

  private onChange: (v: string) => void = () => {
    /* replaced by registerOnChange */
  };
  protected onTouched: () => void = () => {
    /* replaced by registerOnTouched */
  };

  writeValue(val: string): void {
    this.value.set(val ?? '');
  }

  registerOnChange(fn: (v: string) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  setDisabledState(disabled: boolean): void {
    this.isDisabled.set(disabled);
  }

  protected onInput(event: Event): void {
    const v = (event.target as HTMLInputElement).value;
    this.value.set(v);
    this.onChange(v);
    this.valueChange.emit(v);
  }
}
