import { LiveAnnouncer } from '@angular/cdk/a11y';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NxAnnouncer } from './announcer';

describe('NxAnnouncer', () => {
  let live: { announce: ReturnType<typeof vi.fn>; clear: ReturnType<typeof vi.fn> };
  let announcer: NxAnnouncer;

  beforeEach(() => {
    live = { announce: vi.fn().mockResolvedValue(undefined), clear: vi.fn() };
    TestBed.configureTestingModule({ providers: [{ provide: LiveAnnouncer, useValue: live }] });
    announcer = TestBed.inject(NxAnnouncer);
  });

  it('announces politely by default', async () => {
    await announcer.announce('3 results');
    expect(live.announce).toHaveBeenCalledWith('3 results', 'polite');
  });

  it('honours an explicit politeness', async () => {
    await announcer.announce('Session expired', 'assertive');
    expect(live.announce).toHaveBeenCalledWith('Session expired', 'assertive');
  });

  it('clears pending announcements', () => {
    announcer.clear();
    expect(live.clear).toHaveBeenCalledTimes(1);
  });

  it('writes to a real polite live region', async () => {
    TestBed.resetTestingModule();
    const real = TestBed.inject(NxAnnouncer);
    await real.announce('Saved');
    const region = document.querySelector('.cdk-live-announcer-element');
    expect(region?.getAttribute('aria-live')).toBe('polite');
    expect(region?.textContent).toBe('Saved');
  });
});
