import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { describe, expect, it } from 'vitest';
import { PublicLayout } from './public-layout';

@Component({ template: '<p data-testid="login-page">login</p>' })
class LoginStub {}

describe('PublicLayout', () => {
  async function render(url: string): Promise<HTMLElement> {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          {
            path: '',
            component: PublicLayout,
            children: [{ path: 'auth/login', component: LoginStub }],
          },
        ]),
      ],
    });
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl(url);
    harness.detectChanges();
    return harness.routeNativeElement as HTMLElement;
  }

  it('renders the header with wordmark and theme toggle on an auth route', async () => {
    const root = await render('/auth/login');
    expect(root.querySelector('header .app-header__wordmark')?.textContent).toContain('Nexus');
    expect(root.querySelector('header')?.getAttribute('class')).toContain('app-header');
    expect(root.querySelector('[data-testid="theme-toggle"]')).not.toBeNull();
  });

  it('renders the routed page and owns no main landmark', async () => {
    const root = await render('/auth/login');
    expect(root.querySelector('[data-testid="login-page"]')).not.toBeNull();
    expect(root.querySelector('main')).toBeNull();
  });
});
