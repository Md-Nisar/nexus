import { TestBed } from '@angular/core/testing';
import { SensitiveBadge } from './sensitive-badge';

describe('SensitiveBadge', () => {
  it('shows the word Sensitive as text next to an icon, never colour alone', () => {
    const fixture = TestBed.createComponent(SensitiveBadge);
    fixture.detectChanges();
    const badge = (fixture.nativeElement as HTMLElement).querySelector(
      '[data-testid="sensitive-badge"]',
    ) as HTMLElement;
    expect(badge.textContent).toContain('Sensitive');
    expect(badge.querySelector('nx-icon')).not.toBeNull();
  });
});
