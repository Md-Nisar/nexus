import { computed, inject, Injectable, signal } from '@angular/core';
import { LoggerService } from '../logging/logger.service';
import { AuthSession } from '../../shared/types/auth';

@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly logger = inject(LoggerService);
  private readonly _session = signal<AuthSession | null>(null);

  readonly session = this._session.asReadonly();
  readonly isAuthenticated = computed(() => {
    const s = this._session();
    return s !== null && Date.now() < s.expiresAt;
  });
  readonly currentUser = computed(() => this._session()?.user ?? null);
  readonly accessToken = computed(() => this._session()?.accessToken ?? null);

  setSession(session: AuthSession): void {
    this._session.set(session);
    this.logger.debug('Auth session established', { userId: session.user.userId });
  }

  clearSession(): void {
    this._session.set(null);
    this.logger.debug('Auth session cleared');
  }
}
