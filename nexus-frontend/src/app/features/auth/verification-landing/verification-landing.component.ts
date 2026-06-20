import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatIconModule } from '@angular/material/icon';
import { AuthService } from '../auth.service';
import { AppError } from '../../../shared/types/app-error';
import { ViewState, failure, loading, success } from '../../../shared/types/view-state';

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
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParams, {
    initialValue: {} as Record<string, string>,
  });

  protected readonly state = signal<ViewState<void>>(loading);

  protected readonly errorDetail = computed(() => {
    const s = this.state();
    return s.kind === 'error' ? s.error : null;
  });

  ngOnInit(): void {
    const token = this.queryParams()['token'];
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
    this.authService.verifyEmail(token).subscribe({
      next: () => this.state.set(success(undefined)),
      error: (err: AppError) => this.state.set(failure<void>(err)),
    });
  }
}
