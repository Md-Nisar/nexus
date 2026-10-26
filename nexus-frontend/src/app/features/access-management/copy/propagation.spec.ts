import { describe, expect, it } from 'vitest';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  PERMISSION_CACHE_TTL_SECONDS,
  PROPAGATION_COPY,
  propagationFor,
} from './propagation';

describe('propagation copy (design §9.3, FR-F3)', () => {
  it('mirrors the two server TTLs', () => {
    expect(ACCESS_TOKEN_TTL_SECONDS).toBe(900);
    expect(PERMISSION_CACHE_TTL_SECONDS).toBe(900);
  });

  it('derives the minutes from the constants: 15 for a grant, a 30-minute ceiling for a revoke', () => {
    const grant = Math.ceil(Math.max(ACCESS_TOKEN_TTL_SECONDS, PERMISSION_CACHE_TTL_SECONDS) / 60);
    const revoke = Math.ceil((ACCESS_TOKEN_TTL_SECONDS + PERMISSION_CACHE_TTL_SECONDS) / 60);
    expect([grant, revoke]).toEqual([15, 30]);

    expect(PROPAGATION_COPY.grant).toBe(
      `This takes effect within about ${grant} minutes, or when the person signs in again.`,
    );
    expect(PROPAGATION_COPY.revoke).toBe(
      `This takes effect on the person's next request, and in every case within about ${revoke} minutes.`,
    );
  });

  it('gives the grant line for adds and for an assign', () => {
    expect(propagationFor({ added: 2, removed: 0 })).toEqual([PROPAGATION_COPY.grant]);
    expect(propagationFor('assign')).toEqual([PROPAGATION_COPY.grant]);
  });

  it('gives the revoke line for removes and for a revoke', () => {
    expect(propagationFor({ added: 0, removed: 1 })).toEqual([PROPAGATION_COPY.revoke]);
    expect(propagationFor('revoke')).toEqual([PROPAGATION_COPY.revoke]);
  });

  it('gives both lines for a replace that adds and removes', () => {
    expect(propagationFor({ added: 1, removed: 1 })).toEqual([
      PROPAGATION_COPY.grant,
      PROPAGATION_COPY.revoke,
    ]);
  });

  it('gives nothing for a change that changes nothing', () => {
    expect(propagationFor({ added: 0, removed: 0 })).toEqual([]);
  });
});
