import { ChangeDetectionStrategy, Component, inject, Injectable, TemplateRef } from '@angular/core';
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogModule,
  MatDialogRef,
} from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

export interface DialogData {
  readonly title: string;
  readonly message?: string;
  readonly confirmLabel?: string;
  readonly cancelLabel?: string;
  readonly variant?: 'default' | 'danger';
}

// Inline confirmation dialog component — opened by NxDialog.open()
@Component({
  selector: 'nx-dialog-shell',
  standalone: true,
  imports: [MatDialogModule, MatButtonModule, MatIconModule],
  template: `
    <div
      class="nx-dialog"
      [class.nx-dialog--danger]="data.variant === 'danger'"
      data-testid="nx-dialog"
    >
      <div class="nx-dialog__header">
        <h2 mat-dialog-title class="nx-dialog__title">{{ data.title }}</h2>
        <button mat-icon-button mat-dialog-close aria-label="Close dialog">
          <mat-icon>close</mat-icon>
        </button>
      </div>
      @if (data.message) {
        <mat-dialog-content class="nx-dialog__content">
          {{ data.message }}
        </mat-dialog-content>
      }
      <mat-dialog-actions align="end" class="nx-dialog__actions">
        <button mat-button mat-dialog-close>
          {{ data.cancelLabel ?? 'Cancel' }}
        </button>
        <button
          mat-flat-button
          [class.nx-dialog__confirm--danger]="data.variant === 'danger'"
          [mat-dialog-close]="true"
        >
          {{ data.confirmLabel ?? 'Confirm' }}
        </button>
      </mat-dialog-actions>
    </div>
  `,
  styleUrl: './dialog.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxDialogShell {
  readonly data: DialogData = inject<DialogData>(MAT_DIALOG_DATA);
}

@Injectable({ providedIn: 'root' })
export class NxDialog {
  private readonly matDialog = inject(MatDialog);

  open(data: DialogData): MatDialogRef<NxDialogShell, boolean> {
    return this.matDialog.open(NxDialogShell, {
      data,
      width: '480px',
      maxWidth: '90vw',
      panelClass: 'nx-dialog-panel',
      autoFocus: 'first-tabbable',
      restoreFocus: true,
    });
  }

  openTemplate<R>(
    tpl: TemplateRef<unknown>,
    config?: Parameters<MatDialog['open']>[1],
  ): MatDialogRef<unknown, R> {
    return this.matDialog.open(tpl, {
      width: '600px',
      maxWidth: '90vw',
      panelClass: 'nx-dialog-panel',
      autoFocus: 'first-tabbable',
      restoreFocus: true,
      ...config,
    });
  }
}
