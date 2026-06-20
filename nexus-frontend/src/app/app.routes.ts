import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: 'auth',
    loadChildren: () => import('./features/auth/auth.routes').then((m) => m.AUTH_ROUTES),
  },
  {
    path: 'design-system',
    loadComponent: () =>
      import('./features/design-system/design-system-preview.component').then(
        (m) => m.DesignSystemPreviewComponent,
      ),
  },
];
