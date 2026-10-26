import {
  Component,
  ElementRef,
  computed,
  effect,
  forwardRef,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';
import { ErrorStateMatcher } from '@angular/material/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInput, MatInputModule } from '@angular/material/input';

let nextId = 0;

/**
 * Multi-line text field wrapping `MatFormField` and a `MatInput` textarea, usable with
 * `formControl` / `ngModel` (US-020 design §15.1).
 *
 * - **Label:** visible and tied to the field (`label` is required).
 * - **Hint, counter, error:** rendered as text under the field and linked through
 *   `aria-describedby`, in that order. The counter "{n} of {max}" is shown when `maxLength` is set
 *   and is **not** a live region, so it is not announced on every keystroke (design §13 "Forms").
 *   A non-empty `error` also marks the field invalid (`aria-invalid`, error outline).
 * - **No native `maxlength`:** the counter and the form's validator state the limit, so a paste is
 *   never cut short without telling the user.
 * - `focus()` moves focus to the field, for error-summary links.
 */
@Component({
  selector: 'nx-textarea',
  imports: [MatFormFieldModule, MatInputModule],
  providers: [
    { provide: NG_VALUE_ACCESSOR, useExisting: forwardRef(() => NxTextarea), multi: true },
  ],
  template: `
    <mat-form-field class="nx-textarea" appearance="outline" subscriptSizing="dynamic">
      <mat-label>{{ label() }}</mat-label>
      <textarea
        #field
        matInput
        class="nx-textarea__field"
        [id]="fieldId()"
        [rows]="rows()"
        [disabled]="isDisabled()"
        [value]="value()"
        [aria-describedby]="describedBy()"
        [attr.data-testid]="testId()"
        (input)="onInput($event)"
        (blur)="onTouched()"
      ></textarea>
    </mat-form-field>
    @if (hint()) {
      <p class="nx-textarea__hint" [id]="hintId">{{ hint() }}</p>
    }
    @if (counter(); as text) {
      <p class="nx-textarea__counter" [id]="counterId" data-testid="nx-textarea-counter">
        {{ text }}
      </p>
    }
    @if (error()) {
      <p class="nx-textarea__error" [id]="errorId" data-testid="nx-textarea-error">
        {{ error() }}
      </p>
    }
  `,
  styleUrl: './textarea.scss',
})
export class NxTextarea implements ControlValueAccessor {
  /** Visible label of the field. */
  readonly label = input.required<string>();
  /** Help text under the field. */
  readonly hint = input('');
  /** Error text under the field; non-empty marks the field invalid. */
  readonly error = input('');
  /** The limit the counter shows; `null` shows no counter. */
  readonly maxLength = input<number | null>(null);
  readonly rows = input(4);
  /** `data-testid` of the textarea element. */
  readonly testId = input('nx-textarea');
  /** Id of the textarea element; generated when empty. */
  readonly inputId = input('');

  private readonly field = viewChild.required<ElementRef<HTMLTextAreaElement>>('field');
  private readonly matInput = viewChild.required(MatInput);
  private readonly baseId = `nx-textarea-${nextId++}`;
  protected readonly hintId = `${this.baseId}-hint`;
  protected readonly counterId = `${this.baseId}-counter`;
  protected readonly errorId = `${this.baseId}-error`;

  protected readonly value = signal('');
  protected readonly isDisabled = signal(false);

  protected readonly fieldId = computed(() => this.inputId() || this.baseId);

  protected readonly counter = computed(() => {
    const max = this.maxLength();
    return max === null ? '' : `${this.value().length} of ${max}`;
  });

  protected readonly describedBy = computed(() =>
    [
      this.hint() ? this.hintId : '',
      this.counter() ? this.counterId : '',
      this.error() ? this.errorId : '',
    ]
      .filter(Boolean)
      .join(' '),
  );

  /** The field is in error exactly when an error text is given. */
  private readonly errorMatcher: ErrorStateMatcher = {
    isErrorState: () => this.error() !== '',
  };

  constructor() {
    // MatInput re-evaluates its error state only for a field with its own NgControl. This one is
    // driven by `error`, so its matcher is set here and re-evaluated whenever `error` changes.
    effect(() => {
      this.error();
      const field = this.matInput();
      field.errorStateMatcher = this.errorMatcher;
      field.updateErrorState();
    });
  }

  private onChange: (value: string) => void = () => undefined;
  protected onTouched: () => void = () => undefined;

  writeValue(value: string | null): void {
    this.value.set(value ?? '');
  }

  registerOnChange(fn: (value: string) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  setDisabledState(disabled: boolean): void {
    this.isDisabled.set(disabled);
  }

  /** Moves focus to the field. */
  focus(): void {
    this.field().nativeElement.focus();
  }

  protected onInput(event: Event): void {
    const value = (event.target as HTMLTextAreaElement).value;
    this.value.set(value);
    this.onChange(value);
  }
}
