import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';
import { ViewState, failure, loading, success } from '../../../shared/types/view-state';

/**
 * Email verification landing page (US-002).
 *
 * Consumes a one-time email verification token from the `?token=` query parameter
 * and transitions the user's account from PENDING → ACTIVE. The token is extracted
 * and immediately removed from the URL to prevent leakage via Referer headers and
 * browser history.
 *
 * States:
 * - `loading` — verification request in progress
 * - `success` — email verified, account is ACTIVE
 * - `error` — token invalid, expired, or consumed; if code is AUTH_VRF_002, shows resend link
 *
 * Security: Token is cleared from URL before any backend call (replaceUrl: true).
 * Ref: docs/features/US-002/03-design.md § 10.11
 */
@Component({
  selector: 'app-verification-landing',
  standalone: true,
  imports: [MatIconModule, RouterLink],
  templateUrl: './verification-landing.component.html',
  styleUrl: './verification-landing.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class VerificationLandingComponent implements OnInit {
  private readonly authService = inject(AuthService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(this.route.queryParams, {
    initialValue: {} as Record<string, string>,
  });

  /** Current verification state: loading, success, or error. */
  protected readonly state = signal<ViewState<void>>(loading);

  /** Extracts error details from state for template binding; null if state is not error. */
  protected readonly errorDetail = computed(() => {
    const s = this.state();
    return s.kind === 'error' ? s.error : null;
  });

  ngOnInit(): void {
    const token = this.queryParams()['token'];

    // SECURITY: Strip the token from the URL immediately to prevent:
    // - Referer header leakage if user navigates away
    // - Browser history exposure if user presses back
    // - Proxy/CDN log exposure
    // This must run BEFORE the backend call to minimize the exposure window.
    // Matches the same hardening applied to password-reset links (US-007).
    this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });

    if (!token) {
      this.state.set(
        failure<void>({
          code: 'INVALID_LINK',
          message:
            'This verification link is invalid. Please use the link from your verification email.',
        }),
      );
      return;
    }

    // POST to /api/v1/auth/verify-email with the token.
    // Backend: hashes the token, looks up in auth_tokens, marks consumed, transitions user PENDING → ACTIVE.
    this.authService.verifyEmail(token).subscribe({
      next: () => this.state.set(success(undefined)),
      error: (err: AppError) => this.state.set(failure<void>(err)),
    });
  }
}
