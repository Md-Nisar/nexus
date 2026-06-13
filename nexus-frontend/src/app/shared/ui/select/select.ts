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

export interface SelectOption<T = string> {
  readonly label: string;
  readonly value: T;
  readonly disabled?: boolean;
}

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
  readonly label = input<string>('');
  readonly placeholder = input<string>('');
  readonly options = input<SelectOption<T>[]>([]);
  readonly hint = input<string>('');
  readonly error = input<string>('');
  readonly multiple = input(false);
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
