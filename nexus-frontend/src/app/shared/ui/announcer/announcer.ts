import { LiveAnnouncer } from '@angular/cdk/a11y';
import { inject, Service } from '@angular/core';

export type AnnouncerPoliteness = 'polite' | 'assertive' | 'off';

/**
 * Screen-reader announcements through a shared live region (CDK `LiveAnnouncer`).
 * Polite by default so announcements never interrupt the user; use `assertive` only for
 * errors that need immediate attention.
 */
@Service()
export class NxAnnouncer {
  private readonly live = inject(LiveAnnouncer);

  announce(message: string, politeness: AnnouncerPoliteness = 'polite'): Promise<void> {
    return this.live.announce(message, politeness);
  }

  /** Clears the current announcement. */
  clear(): void {
    this.live.clear();
  }
}
