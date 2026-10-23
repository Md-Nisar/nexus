import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { describe, expect, it } from 'vitest';
import { routes } from '../../../app.routes';
import { AuthStore } from '../../../core/auth/auth.store';
import { createAuthSession } from '../../testing/auth.fixtures';
import { NotFoundComponent } from './not-found.component';

describe('NotFoundComponent', () => {
  it('renders the heading and a dashboard link', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(NotFoundComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')?.textContent?.trim()).toBe('Page not found');
    const link = el.querySelector('[data-testid="not-found-dashboard-link"]');
    expect(link?.textContent?.trim()).toBe('Go to dashboard');
    expect(link?.getAttribute('href')).toBe('/dashboard');
  });

  it('renders for an unknown URL inside the shell (real router)', async () => {
    TestBed.configureTestingModule({ providers: [provideRouter(routes)] });
    TestBed.inject(AuthStore).setSession(createAuthSession());
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/no/such/page');
    const el = harness.routeNativeElement as HTMLElement;
    expect(el.querySelector('main#main-content h1')?.textContent?.trim()).toBe('Page not found');
  });
});
