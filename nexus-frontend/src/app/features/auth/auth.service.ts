import { inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly config = inject(APP_CONFIG);

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
}
