import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, beforeEach } from 'vitest';
import { AccessDeniedComponent } from './access-denied.component';

/**
 * AccessDeniedComponent — the redirect target for permissionGuard's denial path.
 *
 * Verifies AC-5 (WCAG 2.1 AA): correct heading hierarchy, a <main> landmark, and two
 * descriptive, keyboard-operable action links.
 */
describe('AccessDeniedComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AccessDeniedComponent],
      providers: [provideRouter([]), provideAnimationsAsync()],
    });
  });

  it('renders exactly one <h1> with the text "Access denied"', () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();

    const headings = fixture.debugElement.queryAll(By.css('h1'));
    expect(headings.length).toBe(1);
    expect((headings[0].nativeElement as HTMLElement).textContent?.trim()).toBe('Access denied');
  });

  it('renders a <main> landmark', () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();

    const root = fixture.debugElement.query(By.css('[data-testid="access-denied-root"]'));
    expect(root).not.toBeNull();
    expect((root.nativeElement as HTMLElement).tagName).toBe('MAIN');
  });

  it('renders a "Return to dashboard" link pointing to /dashboard', () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();

    const link = fixture.debugElement.query(By.css('[data-testid="access-denied-dashboard-link"]'));
    const el = link.nativeElement as HTMLAnchorElement;
    expect(el.textContent?.trim()).toBe('Return to dashboard');
    expect(el.getAttribute('routerLink') ?? el.getAttribute('ng-reflect-router-link')).toBe(
      '/dashboard',
    );
  });

  it('renders a "Contact your administrator" link with descriptive text, not "click here"', () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();

    const link = fixture.debugElement.query(By.css('[data-testid="access-denied-contact-link"]'));
    const el = link.nativeElement as HTMLAnchorElement;
    expect(el.textContent?.trim()).toBe('Contact your administrator');
    expect(el.textContent?.trim().toLowerCase()).not.toContain('click here');
    expect(el.getAttribute('href')).toMatch(/^mailto:/);
  });

  it('moves focus to the heading on render', async () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const heading = fixture.debugElement.query(By.css('[data-testid="access-denied-heading"]'))
      .nativeElement as HTMLElement;
    expect(document.activeElement).toBe(heading);
  });
});
