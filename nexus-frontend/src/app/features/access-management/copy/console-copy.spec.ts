import { describe, expect, it } from 'vitest';
import { CONSOLE_COPY } from './console-copy';

/** Every string leaf of the copy object. */
function strings(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(strings);
  return [];
}

describe('CONSOLE_COPY (layout strings, US-020 design §14; provisional D3)', () => {
  it('has no empty string', () => {
    for (const text of strings(CONSOLE_COPY)) expect(text.trim()).not.toBe('');
  });

  it('never contains the literal 500 (Q28, N5)', () => {
    for (const text of strings(CONSOLE_COPY)) expect(text).not.toContain('500');
  });

  it('gives each area a one-line explainer with no "Learn more" link (FR-G11, Q25)', () => {
    for (const area of Object.values(CONSOLE_COPY.areas)) {
      expect(area.explainer).not.toMatch(/\n/);
      expect(area.explainer.toLowerCase()).not.toContain('learn more');
    }
  });

  it('uses the D3 profile-unavailable strings (design §14.1, §14.2)', () => {
    expect(CONSOLE_COPY.readOnly.title).toBe('You can view, but not change, access');
    expect(CONSOLE_COPY.readOnly.body).toBe(
      "We couldn't load your access details, so changes are turned off.",
    );
    expect(CONSOLE_COPY.disabledReason.profileUnavailable).toBe(
      "Changes are off because we couldn't confirm your access.",
    );
    expect(CONSOLE_COPY.unavailable).toEqual({
      title: 'Nexus is temporarily unavailable',
      body: "We can't confirm your access right now.",
    });
  });
});
