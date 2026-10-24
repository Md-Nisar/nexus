import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import type { PermissionGroup } from '../data/catalogue.store';
import { PermissionMatrix } from './permission-matrix';

function permission(name: string, isSensitive = false): PermissionResponse {
  return { id: `id-${name}`, name, description: `Server description for ${name}`, isSensitive };
}

const GROUPS: readonly PermissionGroup[] = [
  {
    resource: 'user',
    label: 'Users',
    permissions: [permission('user:read'), permission('user:write', true)],
  },
  { resource: 'role', label: 'Roles', permissions: [permission('role:read')] },
  { resource: 'other', label: 'Other', permissions: [permission('report:export')] },
];

describe('PermissionMatrix, read mode (US-020 design §12.3, §13; FR-A6)', () => {
  let fixture: ComponentFixture<PermissionMatrix>;
  const el = (): HTMLElement => fixture.nativeElement as HTMLElement;

  async function render(roleName: string, granted: readonly string[]): Promise<void> {
    fixture.componentRef.setInput('groups', GROUPS);
    fixture.componentRef.setInput('granted', new Set(granted));
    fixture.componentRef.setInput('roleName', roleName);
    await fixture.whenStable();
  }

  beforeEach(async () => {
    fixture = TestBed.createComponent(PermissionMatrix);
    await render('Support', ['id-user:read', 'id-role:read']);
  });

  function table(): HTMLTableElement {
    return el().querySelector('table') as HTMLTableElement;
  }

  function permissionRows(): HTMLTableRowElement[] {
    return Array.from(table().querySelectorAll<HTMLTableRowElement>('tr[data-permission]'));
  }

  it('is a native table whose caption names the role', () => {
    const caption = table().querySelector('caption');
    expect(caption?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      'Permissions granted by Support',
    );
  });

  it('isolates the role name in the caption inside <bdi>, as text', async () => {
    const name = '<img src=x onerror=alert(1)>‮evil';
    await render(name, []);

    const bdi = table().querySelector('caption bdi');
    expect(bdi?.textContent).toBe(name);
    expect(table().querySelector('img')).toBeNull();
  });

  it('has column headers with scope="col"', () => {
    const headers = Array.from(table().querySelectorAll('thead th'));
    expect(headers.map((th) => th.textContent?.trim())).toEqual([
      'Permission',
      'Code',
      'Description',
      'Status',
    ]);
    expect(headers.every((th) => th.getAttribute('scope') === 'col')).toBe(true);
  });

  it('starts each resource group with a row header spanning every column', () => {
    const groupHeaders = Array.from(table().querySelectorAll('tr[data-group] th'));
    expect(groupHeaders.map((th) => th.textContent?.trim())).toEqual(['Users', 'Roles', 'Other']);
    for (const th of groupHeaders) {
      expect(th.getAttribute('scope')).toBe('row');
      expect(th.getAttribute('colspan')).toBe('4');
    }
  });

  it('gives each permission a row header with its label, then code and description', () => {
    const rows = permissionRows();
    expect(rows.map((row) => row.dataset['permission'])).toEqual([
      'user:read',
      'user:write',
      'role:read',
      'report:export',
    ]);
    const first = rows[0];
    expect(first.querySelector('th')?.getAttribute('scope')).toBe('row');
    expect(first.querySelector('th')?.textContent).toContain('Read user accounts and profiles');
    expect(first.querySelector('code')?.textContent?.trim()).toBe('user:read');
    expect(first.textContent).toContain('Server description for user:read');
  });

  it('shows Granted or Not granted as text with an icon hidden from assistive technology', () => {
    const statuses = permissionRows().map((row) =>
      row.querySelector('[data-testid="matrix-status"]'),
    );
    expect(statuses.map((s) => s?.textContent?.trim())).toEqual([
      expect.stringContaining('Granted'),
      expect.stringContaining('Not granted'),
      expect.stringContaining('Granted'),
      expect.stringContaining('Not granted'),
    ]);
    expect(statuses.map((s) => s?.getAttribute('data-granted'))).toEqual([
      'true',
      'false',
      'true',
      'false',
    ]);
    for (const status of statuses) {
      const icon = status?.querySelector('mat-icon');
      expect(icon?.getAttribute('aria-hidden')).toBe('true');
    }
  });

  it('marks sensitive permissions with the Sensitive badge', () => {
    const rows = permissionRows();
    expect(rows[1].querySelector('[data-testid="sensitive-badge"]')).not.toBeNull();
    expect(rows[0].querySelector('[data-testid="sensitive-badge"]')).toBeNull();
  });

  it('shows an unlabelled code as its code with the Unlabelled badge', () => {
    const unlabelled = permissionRows()[3];
    expect(unlabelled.querySelector('th')?.textContent).toContain('report:export');
    expect(unlabelled.querySelector('[data-testid="unlabelled-badge"]')?.textContent?.trim()).toBe(
      'Unlabelled',
    );
  });

  it('has no checkbox in read mode', () => {
    expect(el().querySelector('input[type="checkbox"]')).toBeNull();
    expect(el().querySelector('nx-checkbox')).toBeNull();
  });

  describe('narrow layout (below 600 px, WCAG 1.4.10)', () => {
    it('renders one section per resource with an h3, in the reflow container', () => {
      const sections = el().querySelector('.permission-matrix__sections');
      expect(sections).not.toBeNull();
      expect(el().querySelector('.permission-matrix__table-wrap')).not.toBeNull();
      const headings = Array.from(sections?.querySelectorAll('section h3') ?? []);
      expect(headings.map((h) => h.textContent?.trim())).toEqual(['Users', 'Roles', 'Other']);
    });

    it('names the sections with an h2 that stands in for the caption, the role name in <bdi>', () => {
      const heading = el().querySelector('.permission-matrix__sections h2');
      expect(heading?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
        'Permissions granted by Support',
      );
      expect(heading?.querySelector('bdi')?.textContent).toBe('Support');
    });

    it('lists label, code, badge and status for each permission', () => {
      const items = Array.from(
        el().querySelectorAll<HTMLElement>('.permission-matrix__sections li'),
      );
      expect(items).toHaveLength(4);
      expect(items[1].textContent).toContain('user:write');
      expect(items[1].querySelector('[data-testid="sensitive-badge"]')).not.toBeNull();
      expect(items[1].querySelector('[data-testid="matrix-status"]')?.textContent).toContain(
        'Not granted',
      );
    });
  });

  it('has no axe violations', async () => {
    await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
  });
});
