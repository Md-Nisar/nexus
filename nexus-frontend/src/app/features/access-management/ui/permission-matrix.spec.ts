import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import type { PermissionGroup } from '../data/catalogue.store';
import type { Affordance } from '../util/affordances';
import { StagedIntent } from '../util/diff-permissions';
import { PermissionMatrix, MatrixGroupToggle, MatrixToggle } from './permission-matrix';

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

describe('PermissionMatrix, edit mode (US-020 design §12.4, §13; FR-A6, FR-B6)', () => {
  let fixture: ComponentFixture<PermissionMatrix>;
  const el = (): HTMLElement => fixture.nativeElement as HTMLElement;
  const toggles: MatrixToggle[] = [];
  const groupToggles: MatrixGroupToggle[] = [];

  const ENABLED: Affordance = { kind: 'enabled' };
  const NOT_HELD: Affordance = { kind: 'disabled', reason: 'not-held' };

  function affordances(overrides: Record<string, Affordance> = {}): Map<string, Affordance> {
    const map = new Map<string, Affordance>();
    for (const group of GROUPS) {
      for (const entry of group.permissions) map.set(entry.id, overrides[entry.id] ?? ENABLED);
    }
    return map;
  }

  async function render(
    options: {
      granted?: readonly string[];
      staged?: StagedIntent;
      affordances?: Map<string, Affordance>;
    } = {},
  ): Promise<void> {
    fixture.componentRef.setInput('groups', GROUPS);
    fixture.componentRef.setInput('granted', new Set(options.granted ?? ['id-user:read']));
    fixture.componentRef.setInput('roleName', 'Support');
    fixture.componentRef.setInput('mode', 'edit');
    fixture.componentRef.setInput(
      'staged',
      options.staged ?? { add: new Set<string>(), remove: new Set<string>() },
    );
    fixture.componentRef.setInput('affordances', options.affordances ?? affordances());
    await fixture.whenStable();
  }

  beforeEach(async () => {
    toggles.length = 0;
    groupToggles.length = 0;
    fixture = TestBed.createComponent(PermissionMatrix);
    fixture.componentInstance.permissionToggle.subscribe((event) => toggles.push(event));
    fixture.componentInstance.groupToggle.subscribe((event) => groupToggles.push(event));
    await render();
  });

  function table(): HTMLTableElement {
    return el().querySelector('table') as HTMLTableElement;
  }

  function rowBox(code: string): HTMLInputElement {
    return table().querySelector(
      `tr[data-permission="${code}"] input[type="checkbox"]`,
    ) as HTMLInputElement;
  }

  function groupBox(resource: string): HTMLInputElement | null {
    return table().querySelector(`tr[data-group="${resource}"] input[type="checkbox"]`);
  }

  function accessibleName(input: HTMLInputElement): string {
    const label = el().querySelector(`label[for="${input.id}"]`);
    return label?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
  }

  it('gives every permission one checkbox with a unique name "{label} ({code})"', () => {
    const boxes = Array.from(
      table().querySelectorAll<HTMLInputElement>('tr[data-permission] input'),
    );
    expect(boxes).toHaveLength(4);
    const names = boxes.map(accessibleName);
    expect(names).toEqual([
      'Read user accounts and profiles (user:read)',
      'Create and modify user accounts (user:write)',
      'Read roles and their permission assignments (role:read)',
      'report:export (report:export)',
    ]);
    expect(new Set(names).size).toBe(names.length);
  });

  it('checks the base set with the staged intent applied', async () => {
    await render({
      granted: ['id-user:read', 'id-role:read'],
      staged: { add: new Set(['id-user:write']), remove: new Set(['id-role:read']) },
    });
    expect(rowBox('user:read').checked).toBe(true);
    expect(rowBox('user:write').checked).toBe(true);
    expect(rowBox('role:read').checked).toBe(false);
    expect(rowBox('report:export').checked).toBe(false);
  });

  it('drops the Status column: the checkbox carries the state', () => {
    const headers = Array.from(table().querySelectorAll('thead th')).map((th) =>
      th.textContent?.trim(),
    );
    expect(headers).toEqual(['Permission', 'Code', 'Description']);
    expect(table().querySelectorAll('[data-testid="matrix-status"]')).toHaveLength(0);
  });

  it('emits permissionToggle with the permission id and the next state', () => {
    rowBox('user:write').click();
    rowBox('user:read').click();
    expect(toggles).toEqual([
      { permissionId: 'id-user:write', next: true },
      { permissionId: 'id-user:read', next: false },
    ]);
  });

  it('labels the group checkbox "All {group} permissions" and marks it mixed', () => {
    const users = groupBox('user') as HTMLInputElement;
    expect(accessibleName(users)).toBe('All Users permissions');
    expect(users.getAttribute('aria-checked')).toBe('mixed');
    expect(users.checked).toBe(false);
    expect(groupBox('role')?.getAttribute('aria-checked')).not.toBe('mixed');
  });

  it('checks the group checkbox when every member is in the result', async () => {
    await render({ granted: ['id-user:read', 'id-user:write'] });
    const users = groupBox('user') as HTMLInputElement;
    expect(users.checked).toBe(true);
    expect(users.getAttribute('aria-checked')).not.toBe('mixed');
  });

  it('emits groupToggle to add the enabled members, then to remove them', async () => {
    (groupBox('user') as HTMLInputElement).click();
    expect(groupToggles).toEqual([{ resource: 'user', next: true }]);
    await render({ granted: ['id-user:read', 'id-user:write'] });
    (groupBox('user') as HTMLInputElement).click();
    expect(groupToggles[1]).toEqual({ resource: 'user', next: false });
  });

  it('turns a group off when every enabled member is already in, even with a disabled one out', async () => {
    await render({
      granted: ['id-user:read'],
      affordances: affordances({ 'id-user:write': NOT_HELD }),
    });
    const users = groupBox('user') as HTMLInputElement;
    expect(users.getAttribute('aria-checked')).toBe('mixed');
    users.click();
    await fixture.whenStable();
    expect(groupToggles).toEqual([{ resource: 'user', next: false }]);
    // The host did not change the inputs: the checkbox still shows the host's state.
    expect(users.getAttribute('aria-checked')).toBe('mixed');
  });

  it('renders no group checkbox for a group with no enabled member', async () => {
    await render({ affordances: affordances({ 'id-role:read': NOT_HELD }) });
    expect(groupBox('role')).toBeNull();
    expect(table().querySelector('tr[data-group="role"] th')?.textContent?.trim()).toBe('Roles');
  });

  it('keeps a disabled row focusable, aria-disabled, with its reason as visible linked text', async () => {
    await render({ affordances: affordances({ 'id-user:write': NOT_HELD }) });
    const box = rowBox('user:write');
    expect(box.disabled).toBe(false);
    expect(box.getAttribute('aria-disabled')).toBe('true');
    const describedBy = box.getAttribute('aria-describedby') ?? '';
    const reason = el().querySelector(`[id="${describedBy}"]`);
    expect(reason?.textContent?.trim()).toBe(
      "You don't hold this permission, so you can't grant it.",
    );
    box.click();
    expect(toggles).toEqual([]);
  });

  it('explains every disabled reason with the D3 text', async () => {
    await render({
      granted: ['id-user:read', 'id-role:read'],
      affordances: affordances({
        'id-user:read': { kind: 'disabled', reason: 'role-exceeds-caller' },
        'id-user:write': { kind: 'disabled', reason: 'admin-only-directory' },
        'id-role:read': { kind: 'disabled', reason: 'profile-unavailable' },
      }),
    });
    const reasonOf = (code: string): string =>
      table()
        .querySelector(`tr[data-permission="${code}"] [data-testid="nx-checkbox-reason"]`)
        ?.textContent?.trim() ?? '';
    expect(reasonOf('user:read')).toBe(
      "You can't remove permissions from this role because it includes access you don't hold.",
    );
    expect(reasonOf('user:write')).toBe(
      'Only an administrator can grant access to email addresses.',
    );
    expect(reasonOf('role:read')).toBe("Changes are off because we couldn't confirm your access.");
  });

  it('gives each rendering its own ids, so no id repeats in the DOM', async () => {
    await render({ affordances: affordances({ 'id-user:write': NOT_HELD }) });
    const ids = Array.from(el().querySelectorAll('[id]')).map((node) => node.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(
      el().querySelectorAll('.permission-matrix__sections input[type="checkbox"]').length,
    ).toBe(table().querySelectorAll('input[type="checkbox"]').length);
  });

  it('has no axe violations', async () => {
    await render({ affordances: affordances({ 'id-user:write': NOT_HELD }) });
    await expect(expectNoAxeViolations(el())).resolves.toBeUndefined();
  });
});
