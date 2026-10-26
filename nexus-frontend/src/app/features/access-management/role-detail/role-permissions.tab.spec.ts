import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it, vi } from 'vitest';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';
import type { LoadState } from '../data/load-state';
import { CatalogueData, CatalogueStore } from '../data/catalogue.store';
import { RoleDetailData, RoleDetailStore } from './role-detail.store';
import { RolePermissionsTab } from './role-permissions.tab';

function permission(name: string): PermissionResponse {
  return { id: `id-${name}`, name, description: `About ${name}`, isSensitive: false };
}

const ROLE: RoleResponse = {
  id: 'role-1',
  name: 'Support',
  description: '',
  isSystemRole: false,
  createdAt: '2026-01-01T00:00:00Z',
  memberCount: 0,
  permissionCount: 2,
};

function catalogue(entries: readonly PermissionResponse[]): LoadState<CatalogueData> {
  return {
    status: 'ready',
    loadedAt: 0,
    data: {
      permissions: entries,
      byId: new Map(entries.map((p) => [p.id, p])),
      byName: new Map(entries.map((p) => [p.name, p])),
      groups: [{ resource: 'role', label: 'Roles', permissions: entries }],
      total: entries.length,
    },
  };
}

function detail(granted: readonly PermissionResponse[]): LoadState<RoleDetailData> {
  return {
    status: 'ready',
    loadedAt: 0,
    data: {
      role: ROLE,
      permissions: granted,
      etag: { kind: 'strong', value: '"v1"' },
      correlationId: null,
      saveAvailability: 'available',
    },
  };
}

function render(detailState: LoadState<RoleDetailData>, catalogueState: LoadState<CatalogueData>) {
  const load = vi.fn();
  TestBed.configureTestingModule({
    providers: [
      { provide: RoleDetailStore, useValue: { state: signal(detailState) } },
      { provide: CatalogueStore, useValue: { state: signal(catalogueState), load } },
    ],
  });
  const fixture = TestBed.createComponent(RolePermissionsTab);
  fixture.detectChanges();
  return { el: fixture.nativeElement as HTMLElement, load };
}

describe('RolePermissionsTab (US-020 design §6.1, §12.3)', () => {
  it('shows a granted permission the catalogue does not know yet, under Other, as Granted', () => {
    const known = permission('role:read');
    const unknown = permission('report:export');
    const { el } = render(detail([known, unknown]), catalogue([known]));

    const rows = Array.from(el.querySelectorAll<HTMLElement>('table tr[data-permission]'));
    expect(rows.map((row) => row.dataset['permission'])).toEqual(['role:read', 'report:export']);
    expect(
      rows[1].querySelector('[data-testid="matrix-status"]')?.getAttribute('data-granted'),
    ).toBe('true');
    const groups = Array.from(el.querySelectorAll('table tr[data-group] th')).map((th) =>
      th.textContent?.trim(),
    );
    expect(groups).toEqual(['Roles', 'Other']);
  });

  it('renders nothing while the role itself is not ready (the page shows that state)', () => {
    const { el } = render({ status: 'loading' }, catalogue([permission('role:read')]));

    expect(el.querySelector('table')).toBeNull();
    expect(el.querySelector('[data-testid="role-permissions-loading"]')).toBeNull();
  });
});
