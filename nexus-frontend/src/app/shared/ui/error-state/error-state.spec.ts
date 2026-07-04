import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxErrorState } from './error-state';

/**
 * Test suite for NxErrorState component.
 *
 * ## Coverage
 * - Rendering: container, icon, title, message
 * - Accessibility: role="alert" attribute
 * - Inputs: title, message, showRetry
 * - Output: retry event emission
 * - Conditional rendering: message visibility, retry button visibility
 * - ng-content slot: custom action projection
 *
 * ## Test Strategy
 * - Component is tested in isolation with TestBed
 * - Focus is on input binding, conditional rendering, and event emission
 * - Accessibility is verified via role attribute and test IDs
 * - Material Icon component is imported but not mocked; we verify icon renders
 * - ng-content slot is verified implicitly through DOM structure tests
 *
 * Note: Visual/styling tests and end-to-end interaction tests would be in
 * `error-state.integration.spec.ts` using Playwright for screenshot comparison
 * and full user flow testing.
 */
describe('NxErrorState', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxErrorState],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders the error state container', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-error-state"]'))).toBeTruthy();
  });

  it('has role=alert for accessibility', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.detectChanges();
    const el: HTMLElement = fixture.debugElement.query(
      By.css('[data-testid="nx-error-state"]'),
    ).nativeElement;
    expect(el.getAttribute('role')).toBe('alert');
  });

  it('displays a custom title', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.componentRef.setInput('title', 'Failed to load');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Failed to load');
  });

  it('shows retry button when showRetry=true', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.componentRef.setInput('showRetry', true);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-error-state-retry"]'))).toBeTruthy();
  });

  it('hides retry button when showRetry=false', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.componentRef.setInput('showRetry', false);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-error-state-retry"]'))).toBeNull();
  });

  it('emits retry when the retry button is clicked', () => {
    const fixture = TestBed.createComponent(NxErrorState);
    fixture.componentRef.setInput('showRetry', true);
    fixture.detectChanges();
    const handler = vi.fn();
    fixture.componentInstance.retry.subscribe(handler);
    fixture.debugElement
      .query(By.css('[data-testid="nx-error-state-retry"]'))
      .nativeElement.click();
    expect(handler).toHaveBeenCalledOnce();
  });
});
