const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/**
 * How long ago `then` was, relative to `now`, in the user's locale: "now", "5 minutes ago",
 * "yesterday" (US-020 design §5, §12.3 "Updated {relative time}"). Pure; `Intl.RelativeTimeFormat`
 * with `numeric: 'auto'`.
 *
 * Under a minute is "now", so a once-a-minute refresh of the text is exact enough. A `then` in the
 * future (clock skew between reads) is also "now", never "in N minutes".
 */
export function formatRelativeTime(then: number, now: number, locale: string): string {
  const format = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  const elapsed = Math.max(0, now - then);
  if (elapsed < MINUTE_MS) return format.format(0, 'second');
  if (elapsed < HOUR_MS) return format.format(-Math.floor(elapsed / MINUTE_MS), 'minute');
  if (elapsed < DAY_MS) return format.format(-Math.floor(elapsed / HOUR_MS), 'hour');
  return format.format(-Math.floor(elapsed / DAY_MS), 'day');
}
