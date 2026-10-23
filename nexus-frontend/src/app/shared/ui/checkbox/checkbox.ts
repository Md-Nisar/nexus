import { Component, computed, forwardRef, input, output, signal } from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';
import { MatCheckbox, MatCheckboxChange } from '@angular/material/checkbox';

let nextId = 0;

/**
 * Tri-state checkbox wrapping `MatCheckbox`, usable with `formControl` / `ngModel`.
 *
 * Indeterminate renders `aria-checked="mixed"` (APG). With `disabledReason` the checkbox is
 * disabled but stays focusable (`disabledInteractive`) and the visible reason text is linked
 * through `aria-describedby`, so the reason never depends on a tooltip alone.
 */
@Component({
  selector: 'nx-checkbox',
  imports: [MatCheckbox],
  providers: [
    { provide: NG_VALUE_ACCESSOR, useExisting: forwardRef(() => NxCheckbox), multi: true },
  ],
  template: `
    <mat-checkbox
      class="nx-checkbox"
      [attr.data-testid]="testId()"
      [checked]="value()"
      [indeterminate]="indeterminate()"
      [disabled]="isDisabled()"
      [disabledInteractive]="!!disabledReason()"
      [required]="required()"
      [aria-describedby]="describedByIds()"
      (change)="onToggle($event)"
      (blur)="onTouched()"
      >{{ label() }} <ng-content
    /></mat-checkbox>
    @if (disabledReason()) {
      <span class="nx-checkbox__reason" data-testid="nx-checkbox-reason" [id]="reasonIdValue">{{
        disabledReason()
      }}</span>
    }
  `,
  styleUrl: './checkbox.scss',
})
export class NxCheckbox implements ControlValueAccessor {
  readonly label = input.required<string>();
  readonly indeterminate = input(false);
  readonly disabled = input(false);
  /** Visible explanation for a disabled checkbox; keeps it focusable and announced. */
  readonly disabledReason = input('');
  readonly required = input(false);
  /** Id of an element that describes this checkbox, such as a validation message. */
  readonly describedBy = input('');
  readonly testId = input('nx-checkbox');

  /** Emits the new checked state after a user toggle. */
  readonly changed = output<boolean>();

  protected readonly value = signal(false);
  private readonly cvaDisabled = signal(false);
  protected readonly isDisabled = computed(() => this.disabled() || this.cvaDisabled());
  protected readonly reasonIdValue = `nx-checkbox-reason-${nextId++}`;
  protected readonly reasonId = computed(() => (this.disabledReason() ? this.reasonIdValue : ''));
  protected readonly describedByIds = computed(() =>
    [this.reasonId(), this.describedBy()].filter(Boolean).join(' '),
  );

  private onChange: (value: boolean) => void = () => undefined;
  protected onTouched: () => void = () => undefined;

  writeValue(value: boolean | null): void {
    this.value.set(!!value);
  }

  registerOnChange(fn: (value: boolean) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  setDisabledState(isDisabled: boolean): void {
    this.cvaDisabled.set(isDisabled);
  }

  protected onToggle(event: MatCheckboxChange): void {
    this.value.set(event.checked);
    this.onChange(event.checked);
    this.changed.emit(event.checked);
  }
}
