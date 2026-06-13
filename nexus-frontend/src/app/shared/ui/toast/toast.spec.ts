import { TestBed } from '@angular/core/testing';
import { MatSnackBar } from '@angular/material/snack-bar';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxToast } from './toast';

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
