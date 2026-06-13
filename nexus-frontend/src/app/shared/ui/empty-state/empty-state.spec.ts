import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { NxEmptyState } from './empty-state';

describe('NxEmptyState', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxEmptyState],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders the empty state container', () => {
    const fixture = TestBed.createComponent(NxEmptyState);
    fixture.componentRef.setInput('title', 'No items');
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-empty-state"]'))).toBeTruthy();
  });

  it('displays the required title', () => {
    const fixture = TestBed.createComponent(NxEmptyState);
    fixture.componentRef.setInput('title', 'Nothing here');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Nothing here');
  });

  it('shows description when provided', () => {
    const fixture = TestBed.createComponent(NxEmptyState);
    fixture.componentRef.setInput('title', 'No items');
    fixture.componentRef.setInput('description', 'Add one to get started.');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Add one to get started.');
  });

  it('has role=status for accessibility', () => {
    const fixture = TestBed.createComponent(NxEmptyState);
    fixture.componentRef.setInput('title', 'Empty');
    fixture.detectChanges();
    const el: HTMLElement = fixture.debugElement.query(
      By.css('[data-testid="nx-empty-state"]'),
    ).nativeElement;
    expect(el.getAttribute('role')).toBe('status');
  });
});
