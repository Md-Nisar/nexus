import { httpResource } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { finalize } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';
import { AuthService } from '../auth/auth.service';
import { NxButton, NxToast } from '../../shared/ui';

@Component({
  selector: 'nx-dashboard',
  standalone: true,
  imports: [NxButton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="dashboard" data-testid="dashboard-root">
      <h1>Dashboard</h1>
      <nx-button
        variant="secondary"
        [loading]="loggingOut()"
        [disabled]="loggingOut()"
        data-testid="logout-button"
        (clicked)="onLogout()"
      >
        Log out
      </nx-button>
    </main>
  `,
})
export class DashboardComponent {
  private readonly config = inject(APP_CONFIG);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly toast = inject(NxToast);

  readonly loggingOut = signal(false);
  // Triggers the auth interceptor proactive-refresh branch when expiresAt - now < 120 s.
  readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);

  onLogout(): void {
    this.loggingOut.set(true);
    this.authService
      .logout()
      .pipe(finalize(() => this.loggingOut.set(false)))
      .subscribe({
        next: () => {
          this.toast.success('You have been logged out.');
          this.router.navigate(['/auth/login']);
        },
        error: () => {
          this.toast.error('Logout could not be confirmed, but your session was ended.');
          this.router.navigate(['/auth/login']);
        },
      });
  }
}
