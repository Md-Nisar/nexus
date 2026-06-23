import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { finalize, map, Observable, switchMap, tap } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';
import { AuthStore } from '../../core/auth/auth.store';
import { AuthSession } from '../../shared/types/auth';

interface LoginApiResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  userId: string;
}

interface MeApiResponse {
  userId: string;
  emailVerified: boolean;
  tenantId: string;
  roles: string[];
  tokenVersion: number;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly config = inject(APP_CONFIG);
  private readonly authStore = inject(AuthStore);

  private get base(): string {
    return `${this.config.apiBaseUrl}/v1/auth`;
  }

  register(email: string, password: string, consentAccepted: boolean): Observable<void> {
    return this.http
      .post(`${this.base}/register`, { email, password, consentAccepted })
      .pipe(map(() => undefined));
  }

  verifyEmail(token: string): Observable<void> {
    return this.http.post(`${this.base}/verify-email`, { token }).pipe(map(() => undefined));
  }

  resendVerification(email: string): Observable<void> {
    return this.http.post(`${this.base}/resend-verification`, { email }).pipe(map(() => undefined));
  }

  login(email: string, password: string): Observable<AuthSession> {
    return this.http
      .post<LoginApiResponse>(`${this.base}/login`, { email, password }, { withCredentials: true })
      .pipe(
        switchMap((loginResp) =>
          this.fetchMe(loginResp.accessToken, loginResp.tokenType).pipe(
            map((me) => this.buildSession(loginResp, me)),
          ),
        ),
        tap((session) => this.authStore.setSession(session)),
      );
  }

  logout(): Observable<void> {
    return this.http
      .post<void>(`${this.base}/logout`, null, { withCredentials: true })
      .pipe(finalize(() => this.authStore.clearSession()));
  }

  refresh(): Observable<AuthSession> {
    return this.http
      .post<LoginApiResponse>(`${this.base}/refresh`, null, { withCredentials: true })
      .pipe(
        switchMap((loginResp) =>
          this.fetchMe(loginResp.accessToken, loginResp.tokenType).pipe(
            map((me) => this.buildSession(loginResp, me)),
          ),
        ),
        tap((session) => this.authStore.setSession(session)),
      );
  }

  private fetchMe(token: string, tokenType: string): Observable<MeApiResponse> {
    return this.http.get<MeApiResponse>(`${this.config.apiBaseUrl}/v1/users/me`, {
      headers: { Authorization: `${tokenType} ${token}` },
    });
  }

  private buildSession(login: LoginApiResponse, me: MeApiResponse): AuthSession {
    return {
      accessToken: login.accessToken,
      tokenType: login.tokenType,
      expiresIn: login.expiresIn,
      expiresAt: Date.now() + login.expiresIn * 1000,
      user: {
        userId: me.userId,
        tenantId: me.tenantId,
        emailVerified: me.emailVerified,
        roles: me.roles,
        tokenVersion: me.tokenVersion,
      },
    };
  }
}
