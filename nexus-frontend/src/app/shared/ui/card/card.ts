import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';

export type CardElevation = 'flat' | 'raised' | 'outlined';

@Component({
  selector: 'nx-card',
  standalone: true,
  imports: [MatCardModule],
  template: `
    <mat-card [class]="cardClass()" [attr.aria-label]="ariaLabel() || null" data-testid="nx-card">
      @if (title() || subtitle()) {
        <mat-card-header>
          @if (title()) {
            <mat-card-title>{{ title() }}</mat-card-title>
          }
          @if (subtitle()) {
            <mat-card-subtitle>{{ subtitle() }}</mat-card-subtitle>
          }
          <div class="nx-card__header-actions">
            <ng-content select="[slot=header-actions]" />
          </div>
        </mat-card-header>
      }
      <mat-card-content>
        <ng-content />
      </mat-card-content>
      <mat-card-actions align="end">
        <ng-content select="[slot=actions]" />
      </mat-card-actions>
    </mat-card>
  `,
  styleUrl: './card.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class NxCard {
  readonly title = input<string>('');
  readonly subtitle = input<string>('');
  readonly elevation = input<CardElevation>('raised');
  readonly ariaLabel = input<string>('');

  protected cardClass(): string {
    return `nx-card nx-card--${this.elevation()}`;
  }
}
