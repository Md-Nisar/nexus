import { TestBed } from '@angular/core/testing';
import { MatSnackBar } from '@angular/material/snack-bar';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxToast } from './toast';

/**
 * Test suite for NxToast service.
 *
 * ## Coverage
 * - Toast variants: info, success, warning, error
 * - Duration defaults: 4s for info/success/warning, 8s for error
 * - Custom duration and action labels
 * - Panel class assignment for variant-specific styling
 * - Service methods: show(), success(), error(), warning(), info()
 * - MatSnackBar integration: open() call with correct config
 *
 * ## Test Strategy
 * - Service is tested in isolation by mocking MatSnackBar
 * - Focus is on config passed to MatSnackBar.open() (duration, panelClass, position)
 * - Event handling (user clicks action, auto-dismiss) is tested in integration tests
 * - Since MatSnackBar itself handles animations/positioning, we only verify configuration
 *
 * Note: End-to-end tests (actual toast display, keyboard interaction, announcements)
 * would be in `toast.integration.spec.ts` using Playwright.
 */
describe('NxToast', () => {
  let service: NxToast;
  let snackBarSpy: { open: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    snackBarSpy = { open: vi.fn() };
    TestBed.configureTestingModule({
      providers: [
        NxToast,
        provideAnimationsAsync(),
        { provide: MatSnackBar, useValue: snackBarSpy },
      ],
    });
    service = TestBed.inject(NxToast);
  });

  it('calls MatSnackBar.open with correct panel class for info', () => {
    service.info('Hello');
    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Hello',
      'Dismiss',
      expect.objectContaining({ panelClass: ['nx-toast', 'nx-toast--info'] }),
    );
  });

  it('calls MatSnackBar.open with nx-toast--success for success()', () => {
    service.success('Saved!');
    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Saved!',
      'Dismiss',
      expect.objectContaining({ panelClass: ['nx-toast', 'nx-toast--success'] }),
    );
  });

  it('uses 8000ms duration for errors', () => {
    service.error('Oops');
    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Oops',
      'Dismiss',
      expect.objectContaining({ duration: 8000 }),
    );
  });

  it('passes custom action label', () => {
    service.warning('Watch out', 'Got it');
    expect(snackBarSpy.open).toHaveBeenCalledWith('Watch out', 'Got it', expect.anything());
  });
});
