import { ChangeDetectionStrategy, Component, inject, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { catchError, EMPTY } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';

@Component({
  selector: 'nx-dashboard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<main class="dashboard" data-testid="dashboard-root"><h1>Dashboard</h1></main>`,
})
export class DashboardComponent implements OnInit {
  private readonly http = inject(HttpClient);
  private readonly config = inject(APP_CONFIG);

  ngOnInit(): void {
    // Triggers the auth interceptor — the proactive refresh branch fires here
    // when expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS (120 s).
    // catchError swallows the rethrown error; the interceptor has already
    // called clearSession() + router.navigate(['/auth/login']) by that point.
    this.http
      .get(`${this.config.apiBaseUrl}/v1/users/me`)
      .pipe(catchError(() => EMPTY))
      .subscribe();
  }
}
