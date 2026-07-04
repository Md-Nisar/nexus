# Nexus Shared UI Components

Reusable, accessible, and well-documented Angular components built on Material Design 3 and Nexus design tokens.

## Quick Start

### Form Components

**`NxInput`** — Text input with validation
```typescript
import { NxInput } from '@shared/ui';
import { FormControl, Validators } from '@angular/forms';

const email = new FormControl('', Validators.required);

<nx-input
  label="Email"
  type="email"
  placeholder="Enter your email"
  hint="We'll never share your email"
  [formControl]="email"
  [error]="email.touched && email.errors?.['required'] ? 'Email is required' : ''"
/>
```

**`NxSelect`** — Single/multi-select dropdown
```typescript
import { NxSelect, type SelectOption } from '@shared/ui';

const countries: SelectOption[] = [
  { label: 'United States', value: 'us' },
  { label: 'Canada', value: 'ca' },
  { label: 'Mexico', value: 'mx' },
];

const countryControl = new FormControl('us');

<nx-select
  label="Country"
  [options]="countries"
  [formControl]="countryControl"
/>

// Multi-select
<nx-select
  label="Tags"
  [options]="tagOptions"
  [multiple]="true"
  [formControl]="selectedTags"
/>
```

**`NxButton`** — Customizable button with variants
```typescript
import { NxButton } from '@shared/ui';

<nx-button variant="primary" size="md" (clicked)="save()">
  Save Changes
</nx-button>

<nx-button variant="danger" (clicked)="delete()">
  Delete Account
</nx-button>

<nx-button [loading]="isSaving()" type="submit">
  Save
</nx-button>
```

### State Components

**`NxEmptyState`** — Empty/no-data states
```typescript
import { NxEmptyState } from '@shared/ui';

@if (!items.length) {
  <nx-empty-state
    icon="inbox"
    title="No items"
    description="Create an item to get started."
  >
    <button nx-button variant="primary" (click)="create()">
      Create item
    </button>
  </nx-empty-state>
}
```

**`NxErrorState`** — Error/failure states
```typescript
import { NxErrorState } from '@shared/ui';

@if (loadError) {
  <nx-error-state
    title="Failed to load items"
    message="Check your connection and try again."
    [showRetry]="true"
    (retry)="retryLoad()"
  />
}
```

## Component Reference

| Component | Purpose | Form Integration |
|-----------|---------|------------------|
| `NxInput` | Text input with label, hint, error | ✅ ControlValueAccessor |
| `NxSelect` | Dropdown menu (single/multi) | ✅ ControlValueAccessor |
| `NxButton` | Customizable button with variants | ❌ Emit clicks via `clicked` |
| `NxEmptyState` | Empty/no-data state display | ❌ Presentation only |
| `NxErrorState` | Error/failure state display | ❌ Emit retry via `retry` |
| `NxCard` | Container with title and actions | ❌ Presentation only |
| `NxBadge` | Status/label indicator | ❌ Presentation only |
| `NxTable` | Data table with sorting | ❌ Presentation only |
| `NxDialog` | Modal dialog | ❌ Manual open/close |
| `NxToast` | Toast notification | ❌ Service-driven |

## Input/Output Patterns

### Common Input Properties

All form inputs accept these standardized properties:

```typescript
// Label and placeholder
label: string;              // "Email address"
placeholder: string;        // "Enter your email"

// Validation & UX
hint: string;               // "Min 8 characters, 1 uppercase"
error: string;              // "Email is required"

// Visual variants
appearance: 'outline' | 'fill';  // Material form field appearance
disabled: boolean;          // Via form control or [disabled]
```

### Common Output Properties

```typescript
// Values
valueChange: output<T>();  // Emitted on every input change
selectionChange: output<T>();  // Emitted on select change

// Events
clicked: output<void>();   // Button clicked
retry: output<void>();     // Error state retry
suffixIconClick: output<void>();  // Icon button clicked
```

## Form Integration

### Reactive Forms (Recommended)

```typescript
import { FormControl, FormGroup, Validators } from '@angular/forms';

class LoginForm {
  form = new FormGroup({
    email: new FormControl('', [
      Validators.required,
      Validators.email,
    ]),
    password: new FormControl('', [
      Validators.required,
      Validators.minLength(8),
    ]),
  });

  getEmailError(): string {
    const control = this.form.get('email');
    if (!control?.touched || !control?.errors) {
      return '';
    }
    if (control.errors['required']) {
      return 'Email is required';
    }
    if (control.errors['email']) {
      return 'Enter a valid email';
    }
    return '';
  }
}

// Template
<form [formGroup]="form">
  <nx-input
    label="Email"
    type="email"
    formControlName="email"
    [error]="getEmailError()"
  />
  <nx-input
    label="Password"
    type="password"
    formControlName="password"
    [error]="form.get('password')?.touched && form.get('password')?.errors?.['required'] ? 'Password is required' : ''"
  />
  <nx-button type="submit" [disabled]="!form.valid">
    Sign in
  </nx-button>
</form>
```

### Standalone with Signals

```typescript
const email = signal('');
const password = signal('');

<nx-input
  label="Email"
  [value]="email()"
  (valueChange)="email.set($event)"
/>

<nx-input
  label="Password"
  type="password"
  [value]="password()"
  (valueChange)="password.set($event)"
/>
```

## Accessibility Features

All components include:

- **Keyboard navigation** — Full keyboard support with focus indicators
- **Screen reader support** — Proper ARIA labels, roles, and live regions
- **Color contrast** — WCAG AA compliant in light and dark modes
- **Semantic HTML** — Native `<button>`, `<input>`, `<select>` elements
- **Touch targets** — Minimum 44×44px clickable area (mobile-friendly)

### Accessibility in Templates

```typescript
// Provide aria-label for icon-only buttons
<nx-button ariaLabel="Delete item" leadingIcon="trash">
</nx-button>

// Error messages are automatically associated via Material FormField
<nx-input
  label="Email"
  [formControl]="email"
  [error]="email.errors?.['required'] ? 'Required' : ''"
/>

// Empty/error states use appropriate ARIA roles
<nx-empty-state role="status" title="No items" />
<nx-error-state role="alert" title="Failed to load" />
```

## Validation Examples

### Built-in Validators

```typescript
import { Validators } from '@angular/forms';

const email = new FormControl('', [
  Validators.required,
  Validators.email,
]);

const password = new FormControl('', [
  Validators.required,
  Validators.minLength(8),
  Validators.maxLength(128),
  Validators.pattern(/[A-Z]/) // At least one uppercase
]);

const age = new FormControl('', [
  Validators.required,
  Validators.min(18),
  Validators.max(120),
]);

const terms = new FormControl(false, Validators.requiredTrue);
```

### Custom Validators

```typescript
function passwordStrength(control: AbstractControl): ValidationErrors | null {
  const value = control.value;
  if (!value) return null;

  const hasUpper = /[A-Z]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasNumber = /[0-9]/.test(value);

  const valid = hasUpper && hasLower && hasNumber;
  return valid ? null : { passwordStrength: true };
}

const password = new FormControl('', [
  Validators.required,
  Validators.minLength(8),
  passwordStrength,
]);
```

### Async Validators

```typescript
function usernameAvailable(api: ApiService): AsyncValidatorFn {
  return (control: AbstractControl): Observable<ValidationErrors | null> => {
    if (!control.value) {
      return of(null);
    }
    return api.checkUsername(control.value).pipe(
      debounceTime(300),
      map(available => available ? null : { usernameTaken: true }),
      catchError(() => of(null)),
    );
  };
}

const username = new FormControl('', {
  validators: [Validators.required, Validators.minLength(3)],
  asyncValidators: [usernameAvailable(this.api)],
  updateOn: 'blur',  // Only validate on blur
});
```

## Styling & Theming

### Design Tokens

All components use Nexus design tokens (CSS custom properties):

```css
/* Colors */
--nx-color-primary          /* Primary brand color */
--nx-color-error            /* Error/danger color */
--nx-color-surface          /* Background color */
--nx-color-on-surface       /* Text color */

/* Typography */
--nx-text-base              /* 14px body text */
--nx-text-md                /* 16px default */
--nx-text-lg                /* 18px large */

/* Spacing */
--nx-space-sm               /* 8px */
--nx-space-md               /* 16px */
--nx-space-lg               /* 24px */

/* Radius */
--nx-radius-sm              /* 4px */
--nx-radius-md              /* 8px */
--nx-radius-lg              /* 12px */
```

### Material 3 Integration

Components extend Material Design 3 components (`MatInput`, `MatSelect`, `MatButton`, etc.):

```typescript
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';

// All Material styling (color, typography, spacing) applies automatically
// No CSS overrides needed in most cases
```

### Custom Styling

To customize a component's appearance, use CSS custom properties or Material theme:

```scss
// In your component's SCSS
.my-form {
  --nx-color-primary: #007acc;
  --nx-text-md: 16px;
}

nx-input {
  // Component inherits these tokens
}
```

## Documentation

### Component JSDoc

Each component includes comprehensive JSDoc with:

- **Description** — What the component does
- **Use cases** — When to use this component
- **Alternatives** — When NOT to use this component
- **Examples** — Real-world usage patterns (2-3)
- **Accessibility** — ARIA, keyboard, screen reader support
- **UX Notes** — Styling, responsive, state management
- **State Management** — Signal/form control patterns

### Reference Guides

- **[FORM_UI_STANDARDS.md](./FORM_UI_STANDARDS.md)** — Documentation standards for form components
- **[VALIDATION_AND_STATE.md](./VALIDATION_AND_STATE.md)** — Form validation, state, and ControlValueAccessor patterns

## Testing

### Unit Testing Example

```typescript
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { describe, it, expect, vi } from 'vitest';
import { NxInput } from './input';

describe('NxInput', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxInput],
      providers: [provideAnimationsAsync()],
    });
  });

  it('displays error message', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.componentRef.setInput('error', 'Email is required');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Email is required');
  });

  it('emits valueChange when user types', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.detectChanges();
    const handler = vi.fn();
    fixture.componentInstance.valueChange.subscribe(handler);

    const input = fixture.debugElement.query(By.css('input'));
    input.nativeElement.value = 'test@example.com';
    input.nativeElement.dispatchEvent(new Event('input'));

    expect(handler).toHaveBeenCalledWith('test@example.com');
  });
});
```

### E2E Testing with Playwright

```typescript
test('login form validation', async ({ page }) => {
  await page.goto('/login');

  const emailInput = page.locator('[data-testid="email-input"]');
  const submitButton = page.locator('[data-testid="submit-button"]');

  // Initially, submit is enabled
  expect(await submitButton.isDisabled()).toBe(false);

  // User enters invalid email
  await emailInput.fill('not-an-email');
  await emailInput.blur();

  // Error message shown
  const error = page.locator('[data-testid="email-error"]');
  expect(error).toContainText('Enter a valid email');

  // Submit button disabled if form is invalid
  // (depends on form control state)
});
```

## Common Patterns

### Form with Async Operations

```typescript
export class LoginComponent {
  private authService = inject(AuthService);
  private toastService = inject(NxToast);

  form = new FormGroup({
    email: new FormControl('', [Validators.required, Validators.email]),
    password: new FormControl('', [Validators.required, Validators.minLength(8)]),
  });

  isSaving = signal(false);

  onSubmit(): void {
    if (!this.form.valid) {
      this.toastService.show({ message: 'Please fix errors', variant: 'error' });
      return;
    }

    this.isSaving.set(true);

    this.authService.login(this.form.value).subscribe({
      next: () => {
        this.toastService.show({ message: 'Logged in!', variant: 'success' });
        // Navigate to dashboard
      },
      error: (err) => {
        this.isSaving.set(false);
        this.toastService.show({
          message: 'Login failed: ' + err.message,
          variant: 'error',
        });
      },
    });
  }
}

// Template
<form [formGroup]="form" (ngSubmit)="onSubmit()">
  <nx-input
    label="Email"
    type="email"
    formControlName="email"
    [error]="getErrorMessage(form.get('email'))"
    [disabled]="isSaving()"
  />
  <nx-input
    label="Password"
    type="password"
    formControlName="password"
    [error]="getErrorMessage(form.get('password'))"
    [disabled]="isSaving()"
  />
  <nx-button
    type="submit"
    variant="primary"
    [loading]="isSaving()"
    [disabled]="!form.valid || isSaving()"
  >
    Sign in
  </nx-button>
</form>
```

### Data List with Empty/Error States

```typescript
export class ItemsComponent {
  private api = inject(ApiService);

  items$ = this.api.getItems();
  error$ = new Subject<Error>();
  isLoading$ = signal(true);

  loadItems(): void {
    this.isLoading$.set(true);
    this.api.getItems().subscribe({
      next: (items) => {
        this.isLoading$.set(false);
        // items$ emits via observable
      },
      error: (err) => {
        this.isLoading$.set(false);
        this.error$.next(err);
      },
    });
  }
}

// Template
@if (isLoading()) {
  <mat-spinner />
} @else if ((error$ | async) as error) {
  <nx-error-state
    title="Failed to load items"
    message="Check your connection and try again."
    (retry)="loadItems()"
  />
} @else if ((items$ | async) as items) {
  @if (items.length === 0) {
    <nx-empty-state
      icon="inbox"
      title="No items"
      description="Create an item to get started."
    >
      <button nx-button (click)="create()">Create</button>
    </nx-empty-state>
  } @else {
    <nx-table [data]="items" [columns]="columns" />
  }
}
```

## Troubleshooting

### "Type 'string' is not assignable to type 'never'"

**Problem:** Form control type doesn't match component input type.

```typescript
// ❌ Wrong: form expects string, component expects SelectOption<number>
const userId = new FormControl<string>('123');

<nx-select
  [options]="users"  // SelectOption<number>[]
  [formControl]="userId"
/>

// ✅ Correct: types match
const userId = new FormControl<number>(123);

<nx-select
  [options]="users"  // SelectOption<number>[]
  [formControl]="userId"
/>
```

### Error not showing after user input

**Problem:** Error input is bound but not updating on form control changes.

```typescript
// ❌ Wrong: error not reactive to form changes
<nx-input
  [error]="form.get('email')?.errors?.['required'] ? 'Required' : ''"
/>

// ✅ Correct: use a method or computed signal
readonly emailError = computed(() => {
  const control = this.form.get('email');
  return !control?.touched ? '' :
    control.errors?.['required'] ? 'Required' :
    control.errors?.['email'] ? 'Invalid email' : '';
});

<nx-input [error]="emailError()" />
```

### Material animations not working

**Problem:** Components require animations provider.

```typescript
// app.config.ts
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';

export const appConfig: ApplicationConfig = {
  providers: [
    provideAnimationsAsync(),
    // ... other providers
  ],
};
```

## Contributing

When adding new form components:

1. Implement `ControlValueAccessor` if accepting form control input
2. Use signals for internal state management
3. Add comprehensive JSDoc following [FORM_UI_STANDARDS.md](./FORM_UI_STANDARDS.md)
4. Include 2-3 @example blocks covering common use cases
5. Document @accessibility and @ux-notes sections
6. Write unit tests covering state, events, and validation
7. Test in both light and dark themes
8. Verify keyboard navigation and screen reader support

## References

- [Angular Docs](https://angular.io/docs)
- [Angular Material](https://material.angular.io/)
- [Material Design 3](https://m3.material.io/)
- [WCAG 2.1 Accessibility](https://www.w3.org/WAI/WCAG21/quickref/)
- [MDN Web Docs](https://developer.mozilla.org/en-US/)
