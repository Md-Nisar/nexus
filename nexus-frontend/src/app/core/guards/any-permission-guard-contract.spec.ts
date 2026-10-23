import { Route, Routes } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { routes } from '../../app.routes';
import { PERMISSIONS } from '../../shared/types/permission';
import { anyPermissionGuard } from './any-permission.guard';
import { authGuard } from './auth.guard';

/** Resolves a route's children, awaiting lazy `loadChildren` when it yields a route array. */
async function childrenOf(route: Route): Promise<Routes> {
  if (route.children) return route.children;
  if (typeof route.loadChildren !== 'function') return [];
  const loaded: unknown = await route.loadChildren();
  if (Array.isArray(loaded)) return loaded as Routes;
  const maybeDefault = (loaded as { default?: unknown } | null)?.default;
  return Array.isArray(maybeDefault) ? (maybeDefault as Routes) : [];
}

function isValidAnyOf(raw: unknown): boolean {
  return (
    Array.isArray(raw) &&
    raw.length > 0 &&
    raw.every((p) => typeof p === 'string' && (PERMISSIONS as readonly string[]).includes(p))
  );
}

/** One route that lists `anyPermissionGuard`, with the path at which it was found. */
interface Usage {
  readonly path: string;
  readonly route: Route;
}

/**
 * Walks a route table, lazy children included, and returns human-readable violations of the
 * `anyPermissionGuard` usage contract: the route declares its OWN valid `data.anyOf` (an
 * inherited value does not count), an ancestor carries `authGuard`, and `authGuard` never shares
 * the route's `canActivate` array (guards in one array run concurrently).
 */
async function findViolations(
  table: Routes,
  prefix = '',
  ancestorHasAuthGuard = false,
  usages: Usage[] = [],
): Promise<string[]> {
  const violations: string[] = [];
  for (const route of table) {
    const path = `${prefix}/${route.path ?? ''}`.replace(/\/+/g, '/');
    const activate = (route.canActivate ?? []) as readonly unknown[];
    const activateChild = (route.canActivateChild ?? []) as readonly unknown[];

    if (activate.includes(anyPermissionGuard)) {
      usages.push({ path, route });
      if (!isValidAnyOf(route.data?.['anyOf'])) {
        violations.push(`${path}: anyPermissionGuard without its own valid data.anyOf`);
      }
      if (activate.includes(authGuard)) {
        violations.push(`${path}: authGuard and anyPermissionGuard must not share canActivate`);
      } else if (!ancestorHasAuthGuard) {
        violations.push(`${path}: anyPermissionGuard requires an authGuard ancestor route`);
      }
    }

    const ownAuth = activate.includes(authGuard) || activateChild.includes(authGuard);
    violations.push(
      ...(await findViolations(
        await childrenOf(route),
        path,
        ancestorHasAuthGuard || ownAuth,
        usages,
      )),
    );
  }
  return violations;
}

async function usagesIn(table: Routes): Promise<readonly Usage[]> {
  const usages: Usage[] = [];
  await findViolations(table, '', false, usages);
  return usages;
}

/** A shell-like parent carrying `authGuard`, wrapping the given children. */
function underShell(children: Routes): Routes {
  return [{ path: '', canActivate: [authGuard], children }];
}

describe('anyPermissionGuard route-table contract', () => {
  it('the real route table has zero violations', async () => {
    expect(await findViolations(routes)).toEqual([]);
  });

  it('is not vacuous: the real table uses anyPermissionGuard at /admin/access', async () => {
    const paths = (await usagesIn(routes)).map((u) => u.path);
    expect(paths).toContain('/admin/access');
  });

  it('accepts a valid route under an authGuard ancestor', async () => {
    const fixture = underShell([
      { path: 'console', canActivate: [anyPermissionGuard], data: { anyOf: ['role:read'] } },
    ]);
    expect(await findViolations(fixture)).toEqual([]);
  });

  it.each([
    ['a missing data.anyOf', undefined],
    ['an empty data.anyOf', { anyOf: [] }],
    ['a non-catalogue member', { anyOf: ['role:read', 'roles:read'] }],
    ['a data.anyOf that is not an array', { anyOf: 'role:read' }],
  ])('reports %s', async (_name, data) => {
    const fixture = underShell([{ path: 'console', canActivate: [anyPermissionGuard], data }]);
    expect(await findViolations(fixture)).toEqual([
      '/console: anyPermissionGuard without its own valid data.anyOf',
    ]);
  });

  it('reports a route with no authGuard ancestor', async () => {
    const fixture: Routes = [
      { path: 'console', canActivate: [anyPermissionGuard], data: { anyOf: ['role:read'] } },
    ];
    expect(await findViolations(fixture)).toEqual([
      '/console: anyPermissionGuard requires an authGuard ancestor route',
    ]);
  });

  it.each([
    ['authGuard first', [authGuard, anyPermissionGuard]],
    ['anyPermissionGuard first', [anyPermissionGuard, authGuard]],
  ])('reports authGuard and anyPermissionGuard in one canActivate (%s)', async (_n, guards) => {
    const fixture: Routes = [
      { path: 'console', canActivate: guards, data: { anyOf: ['role:read'] } },
    ];
    expect(await findViolations(fixture)).toEqual([
      '/console: authGuard and anyPermissionGuard must not share canActivate',
    ]);
  });

  it('reports a route relying on an inherited data.anyOf instead of its own', async () => {
    const fixture = underShell([
      {
        path: 'console',
        data: { anyOf: ['role:read'] },
        children: [{ path: 'inner', canActivate: [anyPermissionGuard] }],
      },
    ]);
    expect(await findViolations(fixture)).toEqual([
      '/console/inner: anyPermissionGuard without its own valid data.anyOf',
    ]);
  });

  it('reports a nested violation inside lazy loadChildren', async () => {
    const lazy: Routes = [{ path: 'deep', canActivate: [anyPermissionGuard], data: { anyOf: [] } }];
    const fixture = underShell([{ path: 'console', loadChildren: () => Promise.resolve(lazy) }]);
    expect(await findViolations(fixture)).toEqual([
      '/console/deep: anyPermissionGuard without its own valid data.anyOf',
    ]);
  });
});
