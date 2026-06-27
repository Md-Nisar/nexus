# Angular 22 Migration Guide: nexus-frontend

This document records the upgrade of the `nexus-frontend` application from **Angular 21.2.17** to **Angular 22.0.4**. It details the steps taken, package updates, new features adopted, and verification procedures.

---

## 1. Overview

The upgrade was performed incrementally on **June 28, 2026**. The primary goals were to transition the application to a signal-first architecture, reduce boilerplate, and align with the stable features introduced in Angular 22.

### Version Upgrades
* **Angular Core & CLI:** `21.2.17` ➔ `22.0.4`
* **Angular Material & CDK:** `21.2.14` ➔ `22.0.2`
* **TypeScript:** `5.9.3` ➔ `6.0.3`
* **Node.js Requirement:** `>= 22.0.0` (Verified on `v24.16.0`)

---

## 2. Upgrade Steps Executed

1. **Dependency Restoration:** Cleaned the local package state and ran `npm install` to ensure a consistent baseline.
2. **Angular CLI Update:** Executed the update command using the `--allow-dirty` flag to handle local workspace changes:
   ```bash
   node node_modules/@angular/cli/bin/ng.js update @angular/core @angular/cli @angular/material angular-eslint --allow-dirty
   ```
3. **Automated Migrations:** The CLI ran built-in schematics, updating configuration files such as [app.config.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/app.config.ts) and [tsconfig.app.json](file:///C:/entomo/AI/nexus/nexus-frontend/tsconfig.app.json).

---

## 3. Adopted Features & Code Examples

### 🔌 A. `@Service()` Decorator (Stable)
We migrated all core application-wide singletons from the verbose `@Injectable({ providedIn: 'root' })` to the new `@Service()` decorator.

**Before:**
```typescript
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class AuthStore { ... }
```

**After:**
```typescript
import { Service } from '@angular/core';

@Service()
export class AuthStore { ... }
```

**Files Migrated:**
* [auth.store.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/core/auth/auth.store.ts)
* [logger.service.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/core/logging/logger.service.ts)
* [theme.service.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/core/theme.service.ts)
* [auth.service.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/auth.service.ts)
* [dialog.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/shared/ui/dialog/dialog.ts)
* [toast.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/shared/ui/toast/toast.ts)

---

### 🔄 B. `httpResource` API (Stable)
We replaced the manual RxJS-based `HttpClient` subscription in the dashboard with the declarative `httpResource` API, which automatically tracks request lifecycles and handles loading/error states.

**Before:**
```typescript
export class DashboardComponent implements OnInit {
  private readonly http = inject(HttpClient);

  ngOnInit(): void {
    this.http
      .get(`${this.config.apiBaseUrl}/v1/users/me`)
      .pipe(catchError(() => EMPTY))
      .subscribe();
  }
}
```

**After:**
```typescript
import { httpResource } from '@angular/common/http';

export class DashboardComponent {
  readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);
}
```

**Files Migrated:**
* [dashboard.component.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/features/dashboard/dashboard.component.ts)

---

### 🚦 C. Signal Forms API (Stable)
We migrated the login form from `ReactiveFormsModule` (`FormGroup`, `FormControl`) to the new type-safe, signal-driven forms.

**Before:**
```typescript
readonly form = new FormGroup({
  email: new FormControl('', { validators: [Validators.required, Validators.email] }),
  password: new FormControl('', { validators: [Validators.required] })
});

// Submit
const { email, password } = this.form.getRawValue();
```

**After:**
```typescript
import { form, required, email, maxLength, FormField } from '@angular/forms/signals';

readonly loginModel = signal({ email: '', password: '' });

readonly loginForm = form(this.loginModel, (schema) => {
  required(schema.email, { message: 'Email is required.' });
  email(schema.email, { message: 'Enter a valid email address.' });
  maxLength(schema.email, 254, { message: 'Email is too long.' });

  required(schema.password, { message: 'Password is required.' });
  maxLength(schema.password, 256, { message: 'Password is too long.' });
});

// Submit
const { email, password } = this.loginModel();
```

**Files Migrated:**
* [login-form.component.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/login-form/login-form.component.ts)
* [login-form.component.spec.ts](file:///C:/entomo/AI/nexus/nexus-frontend/src/app/features/auth/login-form/login-form.component.spec.ts) (updated test helper to use `loginModel.set(...)`)

---

## 4. Verification & Testing

To verify the integrity of the upgraded application, the unit test suite was executed:
```bash
npm run test:ci
```

### Results
* **Test Files:** 21 passed
* **Total Tests:** 123 passed
* **Coverage:** Maintained at `>89%` overall statement coverage.

---

## 5. Next Steps for Development

Developers working on `nexus-frontend` should adopt these guidelines:
1. **New Services:** Use the `@Service()` decorator instead of `@Injectable({ providedIn: 'root' })`.
2. **New Components:** Change detection now defaults to `OnPush`. No need to add `changeDetection: ChangeDetectionStrategy.OnPush` explicitly to new components.
3. **Forms:** For new forms, prefer the `@angular/forms/signals` (`form()`) API over `ReactiveFormsModule` to maintain type safety and reactivity.
4. **Data Fetching:** Use `httpResource` for reactive GET requests. Continue using `HttpClient` for mutations (POST, PUT, DELETE).
