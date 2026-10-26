import { describe, expect, it } from 'vitest';
import type { AppError } from '../../../shared/types/app-error';
import { NotEnabledCopy, Rbac001ReasonCopy, RbacErrorMessages } from './console-copy';
import { resolveConsoleError } from './resolve-console-error';

const LOAD = { area: 'roles', action: 'load' } as const;

function appError(code: string, extra: Partial<AppError> = {}): AppError {
  return { code, message: 'SERVER-DETAIL-TEXT <b>x</b>', ...extra };
}

describe('resolveConsoleError (design §9.1, §9.2)', () => {
  describe('RBAC_001 by reason', () => {
    it.each(['GRANT_EXCEEDS_CALLER', 'SELF_ASSIGNMENT', 'ADMINISTRATOR_REQUIRED'] as const)(
      'uses the %s copy',
      (reason) => {
        const view = resolveConsoleError(appError('RBAC_001', { reason }), LOAD);
        expect(view.title).toBe(Rbac001ReasonCopy[reason].title);
        expect(view.body).toBe(Rbac001ReasonCopy[reason].body);
      },
    );

    it('uses the UNSPECIFIED copy for an UNSPECIFIED reason, a missing reason and an unknown one', () => {
      const expected = Rbac001ReasonCopy.UNSPECIFIED.title;
      expect(resolveConsoleError(appError('RBAC_001', { reason: 'UNSPECIFIED' }), LOAD).title).toBe(
        expected,
      );
      expect(resolveConsoleError(appError('RBAC_001'), LOAD).title).toBe(expected);
      const unknown = { ...appError('RBAC_001'), reason: 'SOMETHING_NEW' } as unknown as AppError;
      expect(resolveConsoleError(unknown, LOAD).title).toBe(expected);
    });

    it('shows the reference', () => {
      const view = resolveConsoleError(
        appError('RBAC_001', { reason: 'SELF_ASSIGNMENT', traceId: 'trace-1' }),
        LOAD,
      );
      expect(view.reference).toBe('trace-1');
    });
  });

  it('resolves every code in the map to its copy', () => {
    for (const code of Object.keys(RbacErrorMessages) as (keyof typeof RbacErrorMessages)[]) {
      if (code === 'RESOURCE_NOT_FOUND' || code === 'AUTH_005' || code === 'VALIDATION_FAILED') {
        continue;
      }
      const view = resolveConsoleError(appError(code, { retryAfterSeconds: 7 }), LOAD);
      expect(view.title, code).toBe(RbacErrorMessages[code].title);
      expect(view.presentation, code).toBe(RbacErrorMessages[code].presentation);
      expect(view.convergent, code).toBe(RbacErrorMessages[code].convergent === true);
    }
  });

  describe('never renders what the server wrote', () => {
    it('ignores AppError.message, requiredPermission and traceId text in title and body', () => {
      for (const code of Object.keys(RbacErrorMessages)) {
        const view = resolveConsoleError(
          appError(code, { requiredPermission: 'role:write', reason: 'GRANT_EXCEEDS_CALLER' }),
          LOAD,
        );
        const shown = JSON.stringify({ title: view.title, body: view.body });
        expect(shown, code).not.toContain('SERVER-DETAIL-TEXT');
        expect(shown, code).not.toContain('role:write');
        expect(view.fieldErrors, code).toBeUndefined();
      }
    });
  });

  describe('the reference', () => {
    it('is the traceId, else the correlationId', () => {
      expect(
        resolveConsoleError(appError('INTERNAL_ERROR', { traceId: 't', correlationId: 'c' }), LOAD)
          .reference,
      ).toBe('t');
      expect(
        resolveConsoleError(appError('INTERNAL_ERROR', { correlationId: 'c' }), LOAD).reference,
      ).toBe('c');
    });

    it('is absent when the copy does not show it or the error carries none', () => {
      expect(
        resolveConsoleError(appError('RBAC_002', { traceId: 't' }), LOAD).reference,
      ).toBeUndefined();
      expect(resolveConsoleError(appError('INTERNAL_ERROR'), LOAD).reference).toBeUndefined();
    });
  });

  describe('unknown codes', () => {
    it.each(['SOMETHING_NEW', '', 'RATE_001', 'rbac_001'])(
      'maps %j to the generic copy with a reference',
      (code) => {
        const view = resolveConsoleError(appError(code, { traceId: 'trace-9' }), LOAD);
        expect(view.title).toBe(RbacErrorMessages.UNEXPECTED_ERROR.title);
        expect(view.body).toBe(RbacErrorMessages.UNEXPECTED_ERROR.body);
        expect(view.reference).toBe('trace-9');
        expect(view.retryable).toBe(true);
        expect(view.convergent).toBe(false);
      },
    );

    it('does not treat an inherited property name as a code', () => {
      const view = resolveConsoleError(appError('constructor'), LOAD);
      expect(view.title).toBe(RbacErrorMessages.UNEXPECTED_ERROR.title);
      expect(resolveConsoleError(appError('__proto__'), LOAD).title).toBe(
        RbacErrorMessages.UNEXPECTED_ERROR.title,
      );
    });
  });

  describe('429 and waits (design §7.4)', () => {
    it('puts Retry-After in the body and the view', () => {
      const view = resolveConsoleError(appError('RBAC_011', { retryAfterSeconds: 42 }), LOAD);
      expect(view.retryAfterSeconds).toBe(42);
      expect(view.body).toContain('42');
      expect(view.showsWait).toBe(true);
    });

    it('falls back to 30 seconds without Retry-After', () => {
      const view = resolveConsoleError(appError('USER_DIR_002'), LOAD);
      expect(view.retryAfterSeconds).toBe(30);
      expect(view.body).toContain('30');
    });

    it('keeps USER_DIR_001 and USER_DIR_002 apart', () => {
      expect(resolveConsoleError(appError('USER_DIR_001'), LOAD).title).toBe('Too many lookups');
      expect(resolveConsoleError(appError('USER_DIR_002'), LOAD).title).toBe('Too many requests');
    });

    it('leaves a non-wait code without a wait', () => {
      const view = resolveConsoleError(appError('RBAC_002', { retryAfterSeconds: 9 }), LOAD);
      expect(view.retryAfterSeconds).toBeUndefined();
      expect(view.showsWait).toBe(false);
    });
  });

  describe('AUTH_005', () => {
    it('is the unavailable notice on a page load, with Retry-After and a reference', () => {
      const view = resolveConsoleError(
        appError('AUTH_005', { retryAfterSeconds: 12, traceId: 't' }),
        LOAD,
      );
      expect(view.title).toBe('Nexus is temporarily unavailable');
      expect(view.showsWait).toBe(true);
      expect(view.retryAfterSeconds).toBe(12);
      expect(view.reference).toBe('t');
    });

    it.each(['save', 'assign', 'revoke', 'create', 'lookup'] as const)(
      'is "Nothing was changed" for a %s action',
      (action) => {
        const view = resolveConsoleError(appError('AUTH_005', { retryAfterSeconds: 8 }), {
          area: 'roles',
          action,
        });
        expect(view.title).toBe('Nothing was changed');
        expect(view.body).toContain('8');
        expect(view.presentation).toBe('inline');
      },
    );
  });

  describe('RESOURCE_NOT_FOUND is the area’s "not enabled" copy', () => {
    it.each(['roles', 'permissions', 'users', 'assignments', 'profile'] as const)('%s', (area) => {
      const view = resolveConsoleError(appError('RESOURCE_NOT_FOUND'), { area, action: 'load' });
      expect(view.title).toBe(NotEnabledCopy[area].title);
      expect(view.body).toBe(NotEnabledCopy[area].body);
      expect(view.retryable).toBe(false);
      expect(view.notEnabled).toBe(true);
    });

    it('does not treat the entity not-found codes as "not enabled" and gives them no retry', () => {
      const view = resolveConsoleError(appError('ROLE_NOT_FOUND'), LOAD);
      expect(view.notEnabled).toBe(false);
      expect(view.retryable).toBe(false);
      expect(view.title).toBe('This role no longer exists');
    });
  });

  describe('VALIDATION_FAILED', () => {
    it('is the "page doesn’t exist" copy for a list load, with a users variant', () => {
      const roles = resolveConsoleError(appError('VALIDATION_FAILED'), LOAD);
      expect(roles.title).toBe("This page doesn't exist");
      expect(roles.body).toBe('Go back to the first page.');
      const users = resolveConsoleError(appError('VALIDATION_FAILED'), {
        area: 'users',
        action: 'load',
      });
      expect(users.body).toBe(
        'This page is past the end of the list. Use the status filter to narrow it.',
      );
      expect(roles.fieldErrors).toBeUndefined();
    });

    it('is the "details need fixing" copy for a form action, with the server field messages', () => {
      const view = resolveConsoleError(
        appError('VALIDATION_FAILED', {
          details: [
            { field: 'name', message: 'must not be blank' },
            { field: 'description', message: 'size must be at most 255' },
          ],
        }),
        { area: 'roles', action: 'create' },
      );
      expect(view.title).toBe('Some details need fixing');
      expect(view.presentation).toBe('field');
      expect(view.fieldErrors).toEqual([
        { field: 'name', message: 'must not be blank' },
        { field: 'description', message: 'size must be at most 255' },
      ]);
    });

    it('has an empty field list when the server sent no details', () => {
      const view = resolveConsoleError(appError('VALIDATION_FAILED'), {
        area: 'roles',
        action: 'create',
      });
      expect(view.fieldErrors).toEqual([]);
    });
  });

  it('fills {n} from the context count (RBAC_009)', () => {
    const view = resolveConsoleError(appError('RBAC_009'), {
      area: 'roles',
      action: 'delete',
      count: 4,
    });
    expect(view.body).toContain('4');
    expect(view.body).not.toContain('{n}');
  });

  it('marks convergent codes', () => {
    expect(resolveConsoleError(appError('RBAC_004'), LOAD).convergent).toBe(true);
    expect(resolveConsoleError(appError('RBAC_002'), LOAD).convergent).toBe(false);
  });
});
