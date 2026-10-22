import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, beforeEach } from 'vitest';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, AppConfig } from '../../../core/config/app-config';
import { createAuthSession, createAuthUser } from '../../testing/auth.fixtures';
import { AccessDeniedComponent } from './access-denied.component';

const BASE_CONFIG: AppConfig = {
  production: false,
  apiBaseUrl: '/api',
  logLevel: 'debug',
  supportContact: null,
};

function render(supportContact: AppConfig['supportContact'], roles?: readonly string[]) {
  TestBed.overrideProvider(APP_CONFIG, { useValue: { ...BASE_CONFIG, supportContact } });
  if (roles) {
    TestBed.inject(AuthStore).setSession(createAuthSession({ user: createAuthUser({ roles }) }));
  }
  const fixture = TestBed.createComponent(AccessDeniedComponent);
  fixture.detectChanges();
  return fixture;
}

function contactLink(fixture: ReturnType<typeof render>) {
  return fixture.debugElement.query(By.css('[data-testid="access-denied-contact-link"]'));
}

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
      providers: [
        provideRouter([]),
        provideAnimationsAsync(),
        { provide: APP_CONFIG, useValue: BASE_CONFIG },
      ],
    });
  });

  it('renders exactly one <h1> with the text "Access denied"', () => {
    const fixture = TestBed.createComponent(AccessDeniedComponent);
    fixture.detectChanges();

    const headings = fixture.debugElement.queryAll(By.css('h1'));
    expect(headings).toHaveLength(1);
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

  it('renders the configured mailto contact link with its label', () => {
    const link = contactLink(render({ label: 'Email IT support', href: 'mailto:it@corp.example' }));
    const el = link.nativeElement as HTMLAnchorElement;
    expect(el.textContent?.trim()).toBe('Email IT support');
    expect(el.getAttribute('href')).toBe('mailto:it@corp.example');
  });

  it('renders an https contact link', () => {
    const link = contactLink(render({ label: 'Help desk', href: 'https://help.corp.example/it' }));
    expect((link.nativeElement as HTMLAnchorElement).getAttribute('href')).toBe(
      'https://help.corp.example/it',
    );
  });

  it.each([
    ['null', null],
    ['ftp:', { label: 'x', href: 'ftp://files.example/x' }],
    ['javascript:', { label: 'x', href: 'javascript:alert(1)' }],
    ['mixed-case javascript:', { label: 'x', href: 'JaVaScRiPt:alert(1)' }],
    ['data:', { label: 'x', href: 'data:text/html,<script>1</script>' }],
    ['http:', { label: 'x', href: 'http://corp.example' }],
    ['scheme-relative', { label: 'x', href: '//evil.example' }],
    ['leading whitespace', { label: 'x', href: ' javascript:alert(1)' }],
    ['embedded newline', { label: 'x', href: 'https://a.example/\njavascript:1' }],
    ['empty label', { label: ' ', href: 'mailto:it@corp.example' }],
  ])('hides the contact link when supportContact is %s', (_name, supportContact) => {
    expect(contactLink(render(supportContact))).toBeNull();
  });

  it("lists the signed-in user's roles with the as-of caption", () => {
    const fixture = render(null, ['USER', 'AUDITOR']);
    const text = (
      fixture.debugElement.query(By.css('[data-testid="access-denied-roles"]'))
        .nativeElement as HTMLElement
    ).textContent;
    expect(text).toContain('Your roles: USER, AUDITOR');
    expect(text).toContain('as of when you signed in');
  });

  it('shows no roles line when signed out', () => {
    const fixture = render(null);
    expect(fixture.debugElement.query(By.css('[data-testid="access-denied-roles"]'))).toBeNull();
  });

  it('never shows the RBAC reason or required permission', () => {
    const fixture = render(null, ['USER']);
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    for (const leaked of ['GRANT_EXCEEDS_CALLER', 'SELF_ASSIGNMENT', 'ADMINISTRATOR_REQUIRED']) {
      expect(text).not.toContain(leaked);
    }
    expect(text).not.toMatch(/role:read|requiredPermission|reason/i);
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
