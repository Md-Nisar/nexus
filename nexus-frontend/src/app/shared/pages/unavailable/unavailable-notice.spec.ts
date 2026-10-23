import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxAnnouncer } from '../../ui';
import { COOL_DOWN_RANDOM, UnavailableNotice, coolDownMs } from './unavailable-notice';

const NOW = Date.parse('2026-10-23T10:00:00Z');

describe('coolDownMs (US-020 RC-75)', () => {
  it.each([
    ['no Retry-After, no jitter', undefined, 0, 10_000],
    ['no Retry-After, half jitter', undefined, 0.5, 12_500],
    ['no Retry-After, near-full jitter', undefined, 0.999, 14_995],
    ['Retry-After 30 s, jitter 0.2', 30, 0.2, 31_000],
    ['Retry-After 5 s honoured below the default', 5, 0, 5_000],
    ['Retry-After 60 s at the cap', 60, 0, 60_000],
    ['Retry-After 300 s capped at 60 s', 300, 0.4, 62_000],
  ])('%s', (_name, retryAfter, fraction, expected) => {
    expect(coolDownMs(retryAfter, fraction)).toBe(expected);
  });

  it.each([
    [-1, 10_000],
    [1, 15_000],
    [7, 15_000],
    [Number.NaN, 10_000],
  ])('clamps an out-of-range jitter fraction %s into 0..5 s', (fraction, expected) => {
    expect(coolDownMs(undefined, fraction)).toBe(expected);
  });
});

describe('UnavailableNotice', () => {
  let fixture: ComponentFixture<UnavailableNotice>;
  let announce: ReturnType<typeof vi.fn>;
  let random: ReturnType<typeof vi.fn>;
  let retries: number;

  function q(testId: string): HTMLElement | null {
    return (fixture.nativeElement as HTMLElement).querySelector(`[data-testid="${testId}"]`);
  }

  function retryButton(): HTMLButtonElement {
    return q('unavailable-retry') as HTMLButtonElement;
  }

  function countdownText(): string {
    return q('unavailable-countdown')?.textContent?.trim() ?? '';
  }

  async function advance(ms: number): Promise<void> {
    await vi.advanceTimersByTimeAsync(ms);
    fixture.detectChanges();
  }

  function create(inputs: Record<string, unknown> = {}): void {
    fixture = TestBed.createComponent(UnavailableNotice);
    fixture.componentRef.setInput('recordedAt', NOW);
    for (const [key, value] of Object.entries(inputs)) fixture.componentRef.setInput(key, value);
    fixture.componentInstance.retry.subscribe(() => retries++);
    fixture.detectChanges();
  }

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    retries = 0;
    announce = vi.fn(() => Promise.resolve());
    random = vi.fn(() => 0.5);
    TestBed.configureTestingModule({
      providers: [
        { provide: NxAnnouncer, useValue: { announce, clear: vi.fn() } },
        { provide: COOL_DOWN_RANDOM, useValue: random },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows the reference when one is known', () => {
    create({ reference: 'trace-ref-1' });
    expect(q('unavailable-reference')?.textContent).toContain('Reference:');
    expect(q('unavailable-reference')?.textContent).toContain('trace-ref-1');
  });

  it('shows no reference line when none is known', () => {
    create();
    expect(q('unavailable-reference')).toBeNull();
  });

  it('renders no heading (the host page or console page owns the h1)', () => {
    create({ reference: 'r' });
    expect((fixture.nativeElement as HTMLElement).querySelector('h1, h2, h3')).toBeNull();
  });

  it('keeps Retry focusable but aria-disabled with a visible countdown, then enables it', async () => {
    create(); // 10 s + 0.5 × 5 s = 12.5 s
    expect(retryButton().disabled).toBe(false);
    expect(retryButton().getAttribute('aria-disabled')).toBe('true');
    expect(countdownText()).toBe('Retry in 13 s');

    await advance(12_400);
    expect(countdownText()).toBe('Retry in 1 s');
    expect(retryButton().getAttribute('aria-disabled')).toBe('true');

    await advance(100);
    expect(countdownText()).toBe('You can retry now.');
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();
  });

  it('links the countdown text to Retry with aria-describedby', () => {
    create();
    const describedBy = retryButton().getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(q('unavailable-countdown')?.id).toBe(describedBy);
    expect(q('unavailable-countdown')?.getAttribute('aria-live')).toBeNull();
    expect(q('unavailable-countdown')?.getAttribute('role')).toBeNull();
  });

  it('ignores a press during the countdown and emits once a press after it', async () => {
    create();
    retryButton().click();
    expect(retries).toBe(0);

    await advance(12_500);
    retryButton().click();
    expect(retries).toBe(1);
  });

  it('caps a long Retry-After at 60 s plus jitter', async () => {
    create({ retryAfterSeconds: 300 }); // 60 + 2.5 s
    await advance(62_400);
    expect(retryButton().getAttribute('aria-disabled')).toBe('true');
    await advance(100);
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();
  });

  it('counts exactly 10 s without jitter when jitter is off', async () => {
    random.mockReturnValue(0.99);
    create({ jitter: false });
    expect(countdownText()).toBe('Retry in 10 s');
    await advance(9_999);
    expect(retryButton().getAttribute('aria-disabled')).toBe('true');
    await advance(1);
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();
  });

  it('measures the countdown from recordedAt, not from render', async () => {
    vi.setSystemTime(NOW + 4_000);
    create(); // deadline NOW + 12.5 s, rendered 4 s late
    expect(countdownText()).toBe('Retry in 9 s');
    await advance(8_500);
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();
  });

  it('makes exactly one polite announcement, when the countdown reaches zero', async () => {
    create();
    await advance(12_000);
    expect(announce).not.toHaveBeenCalled();

    await advance(500);
    expect(announce).toHaveBeenCalledTimes(1);
    expect(announce).toHaveBeenCalledWith('You can retry now.', 'polite');

    await advance(60_000);
    expect(announce).toHaveBeenCalledTimes(1);
  });

  it('restarts the countdown, with fresh jitter, when a new failure is recorded', async () => {
    create();
    await advance(12_500);
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();

    random.mockReturnValue(0.2);
    fixture.componentRef.setInput('recordedAt', Date.now());
    fixture.detectChanges();

    expect(retryButton().getAttribute('aria-disabled')).toBe('true');
    expect(countdownText()).toBe('Retry in 11 s');
    await advance(11_000);
    expect(retryButton().getAttribute('aria-disabled')).toBeNull();
    expect(announce).toHaveBeenCalledTimes(2);
  });

  it('shows a busy, non-pressable Retry while retrying', async () => {
    create();
    await advance(12_500);
    fixture.componentRef.setInput('retrying', true);
    fixture.detectChanges();

    expect(retryButton().getAttribute('aria-busy')).toBe('true');
    expect(retryButton().getAttribute('aria-disabled')).toBe('true');
    expect(retryButton().textContent?.trim()).toBe('Retrying…');
    retryButton().click();
    expect(retries).toBe(0);
  });

  it('stops its timer when destroyed', async () => {
    create();
    fixture.destroy();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(announce).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('has no axe violations during the countdown', async () => {
    create({ reference: 'trace-ref-1' });
    vi.useRealTimers();
    await expectNoAxeViolations(fixture.nativeElement as HTMLElement);
  });

  it('has no axe violations once Retry is available', async () => {
    create({ reference: 'trace-ref-1' });
    await advance(12_500);
    vi.useRealTimers();
    await expectNoAxeViolations(fixture.nativeElement as HTMLElement);
  });
});
