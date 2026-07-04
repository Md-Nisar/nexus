# Form UI Components — Validation & State Management

This document outlines how validation and state are managed across Nexus form UI components.

## ControlValueAccessor Integration

Form input components (`NxInput`, `NxSelect`) implement Angular's `ControlValueAccessor` interface, enabling seamless integration with `ReactiveFormsModule`.

### Implementation Pattern

```typescript
@Component({
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => NxInput),
      multi: true,
    },
  ],
})
export class NxInput implements ControlValueAccessor {
  protected readonly value = signal('');
  protected readonly isDisabled = signal(false);

  private onChange: (v: string) => void = () => { };
  protected onTouched: () => void = () => { };

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
    this.onChange(v);        // notify form control of change
    this.valueChange.emit(v); // for direct listeners
  }
}
```

**Key points:**

- **Signals for state** — use `signal()` instead of class properties for internal state
- **onChange callback** — call after every user input to update the form control's value
- **onTouched callback** — call on blur to mark the form control as touched (triggers validation display)
- **setDisabledState** — called by the form control to enable/disable the component
- **writeValue** — called when the form control's value is programmatically set

### Form Binding Examples

```typescript
// Reactive Forms (preferred)
const emailControl = new FormControl('', Validators.required);

<nx-input
  label="Email"
  [formControl]="emailControl"
  [error]="emailControl.errors?.['required'] ? 'Email is required' : ''"
/>

// Template-driven Forms (legacy)
<nx-input
  label="Email"
  [(ngModel)]="email"
/>

// Standalone without form control
const emailSignal = signal('');

<nx-input
  label="Email"
  [value]="emailSignal()"
  (valueChange)="emailSignal.set($event)"
/>
```

## Validation & Error Display

### Error Message Binding

Validation errors are passed to the component via the `error` input:

```typescript
// In component
readonly email = new FormControl('', [
  Validators.required,
  Validators.email,
]);

// In template
<nx-input
  label="Email"
  [formControl]="email"
  [error]="getErrorMessage(email)"
/>

// Helper function
protected getErrorMessage(control: FormControl<string>): string {
  if (!control.errors || !control.touched) {
    return '';
  }
  if (control.errors['required']) {
    return 'Email is required';
  }
  if (control.errors['email']) {
    return 'Enter a valid email address';
  }
  return 'Invalid email';
}
```

### Error Display Lifecycle

1. User interacts with input (onInput fires)
2. Form control's value updates
3. User leaves the field (blur / onTouched fires)
4. Form control is marked as touched
5. Parent detects `control.touched && control.errors`
6. Parent updates `error` input with error message
7. Component displays error below the input

**Key:** Errors only show after touch to avoid overwhelming users during typing.

### Custom Validators Example

```typescript
// Async username availability check
function usernameValidator(api: ApiService): AsyncValidatorFn {
  return (control: AbstractControl): Observable<ValidationErrors | null> => {
    if (!control.value) {
      return of(null);
    }
    return api.checkUsername(control.value).pipe(
      map(available => available ? null : { usernameTaken: true }),
      catchError(() => of(null)),
    );
  };
}

// Usage
readonly username = new FormControl(
  '',
  [Validators.required, Validators.minLength(3)],
  [usernameValidator(this.api)]
);
```

## State Management Patterns

### Signal-Based State

Form components use signals for reactive state management:

```typescript
// Inside NxInput
protected readonly value = signal('');
protected readonly isDisabled = signal(false);

// In template
<input
  [value]="value()"
  [disabled]="isDisabled()"
  [attr.aria-label]="label() || null"
/>
```

**Benefits:**
- Fine-grained reactivity (only affected signals trigger change detection)
- No memory leaks (Angular handles cleanup)
- Works seamlessly with OnPush change detection
- Type-safe with TypeScript strict mode

### Input/Output Signals

Component inputs and outputs use the new signal-based APIs:

```typescript
// Inputs (read-only signal)
readonly label = input<string>('');
readonly error = input<string>('');
readonly placeholder = input<string>('');

// Outputs (event emitter as signal)
readonly valueChange = output<string>();
readonly suffixIconClick = output<void>();
```

**Updating state from inputs:**

```typescript
// Change detection automatically tracks input signal reads
// No need for ngOnChanges or manual subscription

// Computed values from inputs
protected buttonLabel = computed(() =>
  this.loading() ? 'Loading...' : this.label()
);
```

## Empty State & Loading State

### NxEmptyState Usage

Use when data load completes with zero items:

```typescript
items$ = this.api.getItems();
hasItems$ = this.items$.pipe(map(items => items.length > 0));

// In template
@if (!(hasItems$ | async); else showList) {
  <nx-empty-state
    title="No items"
    description="Create an item to get started."
    icon="inbox"
  >
    <button nx-button variant="primary" (click)="create()">
      Create item
    </button>
  </nx-empty-state>
}

@template #showList {
  <!-- render table/list -->
}
```

### Loading Placeholder

For async operations, use a spinner or skeleton:

```typescript
isLoading$ = this.api.getItems().pipe(
  startWith(null),
  tap(items => this.items = items),
  map(items => items === null) // still loading if null
);

// In template
@if (isLoading$ | async) {
  <!-- Show skeleton loader or spinner -->
  <mat-spinner />
} @else if (items.length === 0) {
  <nx-empty-state title="No items" />
} @else {
  <!-- render items -->
}
```

### Error Handling

Use `NxErrorState` for load/action failures:

```typescript
loadError$ = new Subject<HttpErrorResponse>();
isRetrying$ = new Subject<void>();

loadItems(): void {
  this.api.getItems().pipe(
    tap(items => this.items = items),
    catchError(err => {
      this.loadError$.next(err);
      return of([]);
    })
  ).subscribe();
}

// In template
@if (loadError$ | async as error) {
  <nx-error-state
    title="Failed to load items"
    [message]="getErrorMessage(error)"
    (retry)="loadItems()"
  />
} @else if (isLoading$ | async) {
  <mat-spinner />
} @else if (items.length === 0) {
  <nx-empty-state title="No items" />
} @else {
  <!-- render items -->
}
```

## Disabled State Management

### Form Control Disabled Flag

The form control's disabled flag is automatically synced to the component:

```typescript
// Component
<nx-input
  label="User ID"
  [formControl]="userIdControl"
/>

// Parent component
readonly userIdControl = new FormControl({ value: '123', disabled: true });

// Programmatically disable
userIdControl.disable();  // updates NxInput's internal isDisabled signal
userIdControl.enable();   // clears isDisabled signal
```

### Visual States

The component reflects disabled state:

- Input element has `[disabled]` attribute
- Cursor appears as `not-allowed` (CSS)
- Opacity reduced (Material FormField styling)
- Tab navigation skips the disabled input

### Disabled State in Signals

If not using form control, manage disabled state directly:

```typescript
readonly isDisabled = signal(false);

<nx-input
  label="Email"
  [value]="email()"
  (valueChange)="email.set($event)"
/>

// Toggle disabled
<button (click)="isDisabled.update(v => !v)">
  Toggle disabled
</button>
```

## Multi-Select State

The `NxSelect` component supports both single and multi-select modes:

```typescript
// Single-select
readonly priorityControl = new FormControl<string>('high');

<nx-select
  label="Priority"
  [options]="priorityOptions"
  [formControl]="priorityControl"
/>

// Multi-select
readonly tagsControl = new FormControl<string[]>(['bug', 'urgent']);

<nx-select
  label="Tags"
  [options]="tagOptions"
  [multiple]="true"
  [formControl]="tagsControl"
/>
```

**State shape:**
- Single-select: `FormControl<T>` where `T` is the option value type
- Multi-select: `FormControl<T[]>` where `T[]` is an array of values

## Accessibility & State

### Touch State Announcement

When a form control is marked as touched, the component's error state is displayed:

```typescript
readonly email = new FormControl('', Validators.required);

// Error is hidden until touched
// After blur (onTouched), component shows error

<nx-input
  [formControl]="email"
  [error]="email.touched && email.errors?.['required'] ? 'Required' : ''"
/>
```

### Busy State (Loading)

The `NxButton` component announces loading state to screen readers:

```typescript
<nx-button
  [loading]="isSaving()"
  (clicked)="save()"
>
  Save
</nx-button>

// Rendered as: <button aria-busy="true">Save</button>
```

Screen readers announce: "Save, button, busy" or "Save, button, please wait"

### Alert State

The `NxErrorState` component uses `role="alert"`:

```typescript
<nx-error-state
  title="Connection failed"
  message="Check your network connection."
/>

// role="alert" immediately announces to screen readers when inserted
```

## Testing State Management

### Unit Test Example

```typescript
describe('NxInput validation', () => {
  it('displays error after touch', () => {
    const fixture = TestBed.createComponent(MyForm);
    fixture.componentRef.setInput('email', '');
    fixture.detectChanges();

    // Error not shown initially
    expect(getError(fixture)).toBe('');

    // Simulate touch
    const input = fixture.debugElement.query(By.css('nx-input'));
    input.componentInstance.onTouched();

    // Manually trigger change detection
    fixture.detectChanges();

    // Error now shown
    expect(getError(fixture)).toContain('Email is required');
  });

  it('calls onChange when input changes', () => {
    const fixture = TestBed.createComponent(NxInput);
    const onChange = vi.fn();
    fixture.componentInstance.registerOnChange(onChange);

    const nativeInput = fixture.debugElement.query(By.css('input'));
    nativeInput.nativeElement.value = 'new value';
    nativeInput.nativeElement.dispatchEvent(new Event('input'));

    expect(onChange).toHaveBeenCalledWith('new value');
  });
});
```

## Best Practices

1. **Always use form controls** — Prefer `FormControl` + `[formControl]` over `[(ngModel)]`
2. **Validate early, display late** — Show errors only after touch to avoid UX noise
3. **Use computed error helpers** — Create reusable functions for error message logic
4. **Mark touched on blur** — Component calls `onTouched()` automatically on blur
5. **Disable form during submission** — Set `form.disable()` while awaiting server response
6. **Provide context in hints** — Use `hint` input for validation constraints (e.g., "Min 8 characters")
7. **Handle async validators** — Use `debounce` + `distinctUntilChanged` for API checks
8. **Test state transitions** — Verify empty → loading → data/error flows
9. **Use `ng-content` for actions** — Let parents provide context-specific buttons/links
10. **Document validation rules** — Comments for non-obvious validator combinations

## References

- [Angular Reactive Forms](https://angular.io/guide/reactive-forms)
- [ControlValueAccessor](https://angular.io/api/forms/ControlValueAccessor)
- [Custom Validators](https://angular.io/guide/form-validation#custom-validators)
- [Signals API](https://angular.io/guide/signals)
- [Material FormField API](https://material.angular.io/components/form-field/api)
