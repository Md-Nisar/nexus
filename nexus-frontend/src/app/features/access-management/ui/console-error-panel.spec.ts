import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { AppError } from '../../../shared/types/app-error';
import { ConsoleErrorView, resolveConsoleError } from '../copy/resolve-console-error';
import { ConsoleErrorPanel } from './console-error-panel';

@Component({
  imports: [ConsoleErrorPanel],
  template: `<app-console-error-panel
    [view]="view"
    [recordedAt]="recordedAt"
    (retry)="retries = retries + 1"
  />`,
})
class Host {
  view!: ConsoleErrorView;
  recordedAt = Date.now();
  retries = 0;
}

function view(code: string, extra: Partial<AppError> = {}): ConsoleErrorView {
  return resolveConsoleError(
    { code, message: 'SERVER-DETAIL-TEXT', ...extra },
    { area: 'roles', action: 'load' },
  );
}

function render(errorView: ConsoleErrorView) {
  TestBed.configureTestingModule({ providers: [provideAnimationsAsync()] });
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.view = errorView;
  fixture.detectChanges();
  const root: HTMLElement = fixture.nativeElement;
  return { fixture, root, host: fixture.componentInstance };
}

describe('ConsoleErrorPanel (US-020 design §6.1, §12.0)', () => {
  it('shows the copy title and body in an alert, with the reference and a Retry', () => {
    const { root, host, fixture } = render(view('INTERNAL_ERROR', { traceId: 'trace-77' }));

    const alert = root.querySelector('[role="alert"]') as HTMLElement;
    expect(alert.textContent).toContain('Something went wrong');
    expect(alert.textContent).toContain('Try again. If it keeps happening');
    expect(root.querySelector('[data-testid="console-error-reference"]')?.textContent).toContain(
      'trace-77',
    );

    (root.querySelector('[data-testid="nx-error-state-retry"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(host.retries).toBe(1);
  });

  it('never shows the server text or a raw code', () => {
    const { root } = render(view('RBAC_012', { traceId: 't' }));
    expect(root.textContent).not.toContain('SERVER-DETAIL-TEXT');
    expect(root.textContent).not.toContain('RBAC_012');
  });

  it('omits the reference line when there is none', () => {
    const { root } = render(view('NETWORK_ERROR'));
    expect(root.querySelector('[data-testid="console-error-reference"]')).toBeNull();
  });

  it('shows no Retry for a code a retry cannot fix', () => {
    const { root } = render(view('ROLE_NOT_FOUND'));
    expect(root.querySelector('[data-testid="nx-error-state-retry"]')).toBeNull();
  });

  it('shows the "not enabled" state as an empty state with no Retry and no alert', () => {
    const { root } = render(view('RESOURCE_NOT_FOUND'));
    expect(root.querySelector('[data-testid="nx-empty-state"]')?.textContent).toContain(
      "Roles aren't enabled",
    );
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(root.querySelector('button')).toBeNull();
  });

  describe('a wait (AUTH_005 on a page load)', () => {
    it('renders the title, body, reference and a Retry that waits out the cool-down', () => {
      const { root } = render(view('AUTH_005', { retryAfterSeconds: 5, traceId: 'trace-5' }));

      expect(root.textContent).toContain('Nexus is temporarily unavailable');
      expect(root.querySelector('[data-testid="unavailable-reference"]')?.textContent).toContain(
        'trace-5',
      );
      const retry = root.querySelector('[data-testid="unavailable-retry"]') as HTMLButtonElement;
      expect(retry.getAttribute('aria-disabled')).toBe('true');
      expect(root.querySelector('[data-testid="nx-error-state-retry"]')).toBeNull();
    });
  });

  it('has no axe violations', async () => {
    const { root } = render(view('INTERNAL_ERROR', { traceId: 'trace-77' }));
    await expectNoAxeViolations(root);
  });
});
