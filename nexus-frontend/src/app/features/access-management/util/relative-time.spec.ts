import { describe, expect, it } from 'vitest';
import { formatRelativeTime } from './relative-time';

const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe('formatRelativeTime (US-020 design §5, §12.3 "Updated {relative time}")', () => {
  it.each([
    ['the same instant', 0, 'now'],
    ['under a minute ago', 59 * SECOND, 'now'],
    ['one minute ago', MINUTE, '1 minute ago'],
    ['59 minutes ago', 59 * MINUTE + 59 * SECOND, '59 minutes ago'],
    ['one hour ago', HOUR, '1 hour ago'],
    ['23 hours ago', 23 * HOUR + 59 * MINUTE, '23 hours ago'],
    ['one day ago', DAY, 'yesterday'],
    ['three days ago', 3 * DAY, '3 days ago'],
  ])('says "%s" as "%s"', (_name, ago, expected) => {
    expect(formatRelativeTime(NOW - ago, NOW, 'en-US')).toBe(expected);
  });

  it('treats a time in the future (clock skew) as now, never "in N minutes"', () => {
    expect(formatRelativeTime(NOW + 5 * MINUTE, NOW, 'en-US')).toBe('now');
  });

  it('follows the locale', () => {
    expect(formatRelativeTime(NOW - 2 * HOUR, NOW, 'de-DE')).toBe('vor 2 Stunden');
  });
});
