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
        <mat-icon
          matSuffix
          style="cursor: pointer"
          (click)="suffixIconClick.emit()"
        >{{ suffixIcon() }}</mat-icon>
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
  readonly inputId = input<string>('');
  readonly label = input<string>('');
  readonly placeholder = input<string>('');
  readonly type = input<string>('text');
  readonly hint = input<string>('');
  readonly error = input<string>('');
  readonly prefixIcon = input<string>('');
  readonly suffixIcon = input<string>('');
  readonly autocomplete = input<string>('off');
  readonly appearance = input<'fill' | 'outline'>('outline');
  readonly valueChange = output<string>();
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
