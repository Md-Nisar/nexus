import catalogue from '../../../../../../contracts/api/permission-catalogue.json';
import { PERMISSIONS, permissionResource } from '../../../shared/types/permission';
import {
  PERMISSION_GROUP_LABELS,
  PERMISSION_GROUP_ORDER,
  PERMISSION_LABELS,
  permissionLabel,
} from './permission-labels';

describe('permission labels (US-020 design §9.4)', () => {
  it('has a non-empty label for every Permission union member and no other key', () => {
    for (const permission of PERMISSIONS) {
      expect(PERMISSION_LABELS[permission], permission).toBeTruthy();
    }
    expect(Object.keys(PERMISSION_LABELS).sort()).toEqual([...PERMISSIONS].sort());
  });

  it('has a label and a group label for every backend catalogue entry', () => {
    for (const entry of catalogue.data) {
      expect(permissionLabel(entry.name), entry.name).toBeTruthy();
      const group = permissionResource(entry.name as (typeof PERMISSIONS)[number]);
      expect(PERMISSION_GROUP_LABELS[group], entry.name).toBeTruthy();
    }
  });

  it('has a group label for every resource of the union, in the fixed display order', () => {
    const resources = new Set(PERMISSIONS.map((permission) => permissionResource(permission)));
    expect([...resources].sort()).toEqual(Object.keys(PERMISSION_GROUP_LABELS).sort());
    expect([...PERMISSION_GROUP_ORDER].sort()).toEqual([...resources].sort());
    expect(PERMISSION_GROUP_ORDER).toEqual(['tenant', 'user', 'role', 'audit']);
  });

  describe('permissionLabel', () => {
    it('returns the label of a known code', () => {
      expect(permissionLabel('role:read')).toBe(PERMISSION_LABELS['role:read']);
    });

    it.each(['report:export', '', 'constructor', '__proto__', 'toString'])(
      'returns undefined for the unknown code %j, never an inherited member',
      (code) => {
        expect(permissionLabel(code)).toBeUndefined();
      },
    );
  });
});
