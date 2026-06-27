import { inject, Service } from '@angular/core';
import { MatSnackBar, MatSnackBarConfig } from '@angular/material/snack-bar';

export type ToastVariant = 'info' | 'success' | 'warning' | 'error';

export interface ToastOptions {
  readonly message: string;
  readonly variant?: ToastVariant;
  readonly action?: string;
  readonly duration?: number;
}

@Service()
export class NxToast {
  private readonly snackBar = inject(MatSnackBar);

  show(options: ToastOptions): void {
    const variant = options.variant ?? 'info';
    const config: MatSnackBarConfig = {
      duration: options.duration ?? 4000,
      horizontalPosition: 'end',
      verticalPosition: 'bottom',
      panelClass: [`nx-toast`, `nx-toast--${variant}`],
    };
    this.snackBar.open(options.message, options.action ?? 'Dismiss', config);
  }

  success(message: string, action?: string): void {
    this.show({ message, action, variant: 'success' });
  }

  error(message: string, action?: string): void {
    this.show({ message, action, variant: 'error', duration: 8000 });
  }

  warning(message: string, action?: string): void {
    this.show({ message, action, variant: 'warning' });
  }

  info(message: string, action?: string): void {
    this.show({ message, action, variant: 'info' });
  }
}
