import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxErrorState } from './error-state';

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
