import { Routes } from '@angular/router';

export const AUTH_ROUTES: Routes = [
  {
    path: 'login',
    loadComponent: () =>
      import('./login-form/login-form.component').then((m) => m.LoginFormComponent),
  },
  {
    path: 'register',
    loadComponent: () =>
      import('./registration-form/registration-form.component').then(
        (m) => m.RegistrationFormComponent,
      ),
  },
  {
    path: 'verify-email',
    loadComponent: () =>
      import('./verification-landing/verification-landing.component').then(
        (m) => m.VerificationLandingComponent,
      ),
  },
];
