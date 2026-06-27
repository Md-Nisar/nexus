import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { httpResource } from '@angular/common/http';
import { APP_CONFIG } from '../../core/config/app-config';

@Component({
  selector: 'nx-dashboard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<main class="dashboard" data-testid="dashboard-root"><h1>Dashboard</h1></main>`,
})
export class DashboardComponent {
  private readonly config = inject(APP_CONFIG);

  // Triggers the auth interceptor — the proactive refresh branch fires here
  // when expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS (120 s).
  readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);
}
