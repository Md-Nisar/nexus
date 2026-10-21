import { Component, DestroyRef, forwardRef, inject, input, output, signal } from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';
import { MatIconButton } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';

export type SearchMode = 'debounced' | 'submit';

/**
 * Search input wrapping `MatFormField` + `MatInput`, usable with `formControl` / `ngModel`.
 *
 * `search` emits the trimmed, distinct query: after `debounceMs` of quiet in `debounced`
 * mode, or only on Enter in `submit` mode (use `submit` wherever each query is a throttled
 * or audited lookup). Enter always searches immediately. Escape or the clear button empties
 * the field, cancels a pending search and emits `cleared` (not `search`).
 */
@Component({
  selector: 'nx-search-field',
  imports: [MatFormFieldModule, MatInputModule, MatIconModule, MatIconButton],
  providers: [
    { provide: NG_VALUE_ACCESSOR, useExisting: forwardRef(() => NxSearchField), multi: true },
  ],
  template: `
    <div role="search">
      <mat-form-field class="nx-search-field" subscriptSizing="dynamic">
        <mat-icon matPrefix aria-hidden="true">search</mat-icon>
        <input
          matInput
          type="search"
          data-testid="nx-search-input"
          [placeholder]="placeholder()"
          [attr.aria-label]="label()"
          [disabled]="isDisabled()"
          [value]="value()"
          (input)="onInput($event)"
          (keydown.enter)="onEnter($event)"
          (keydown.escape)="clear()"
          (blur)="onTouched()"
        />
        @if (value() && !isDisabled()) {
          <button
            type="button"
            mat-icon-button
            matSuffix
            data-testid="nx-search-clear"
            aria-label="Clear search"
            (click)="clear()"
          >
            <mat-icon aria-hidden="true">close</mat-icon>
          </button>
        }
      </mat-form-field>
    </div>
  `,
  styleUrl: './search-field.scss',
})
export class NxSearchField implements ControlValueAccessor {
  readonly label = input.required<string>();
  readonly placeholder = input('');
  readonly mode = input<SearchMode>('debounced');
  readonly debounceMs = input(300);
  /** Trimmed queries shorter than this are not emitted. */
  readonly minLength = input(0);

  /** The trimmed, distinct query. */
  // The name is the contract of design 12.4; the native `search` event never reaches this host.
  // eslint-disable-next-line @angular-eslint/no-output-native
  readonly search = output<string>();
  readonly cleared = output<void>();

  protected readonly value = signal('');
  protected readonly isDisabled = signal(false);

  private lastEmitted: string | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private onChange: (value: string) => void = () => undefined;
  protected onTouched: () => void = () => undefined;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.cancelPending());
  }

  writeValue(value: string | null): void {
    this.value.set(value ?? '');
  }

  registerOnChange(fn: (value: string) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }

  setDisabledState(isDisabled: boolean): void {
    this.isDisabled.set(isDisabled);
  }

  protected onInput(event: Event): void {
    const raw = (event.target as HTMLInputElement).value;
    this.value.set(raw);
    this.onChange(raw);
    this.cancelPending();
    if (this.mode() === 'debounced') {
      this.timer = setTimeout(() => {
        this.timer = null;
        this.emitSearch();
      }, this.debounceMs());
    }
  }

  protected onEnter(event: Event): void {
    event.preventDefault();
    this.cancelPending();
    this.emitSearch();
  }

  protected clear(): void {
    this.cancelPending();
    if (!this.value()) return;
    this.value.set('');
    this.lastEmitted = null;
    this.onChange('');
    this.cleared.emit();
  }

  private emitSearch(): void {
    const query = this.value().trim();
    if (query.length < this.minLength() || query === this.lastEmitted) return;
    this.lastEmitted = query;
    this.search.emit(query);
  }

  private cancelPending(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
