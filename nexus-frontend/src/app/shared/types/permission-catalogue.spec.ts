import catalogue from '../../../../../contracts/api/permission-catalogue.json';
import {
  PERMISSIONS,
  PERMISSION_GROUP_LABELS,
  PERMISSION_LABELS,
  permissionResource,
} from './permission';

const backendNames: readonly string[] = catalogue.data.map((entry) => entry.name);

describe('permission catalogue', () => {
  it('should know every backend permission name in PERMISSIONS with a label and a group', () => {
    for (const name of backendNames) {
      expect(PERMISSIONS as readonly string[], name).toContain(name);
      expect(PERMISSION_LABELS[name as keyof typeof PERMISSION_LABELS], name).toBeTruthy();
      const group = permissionResource(name as (typeof PERMISSIONS)[number]);
      expect(PERMISSION_GROUP_LABELS[group], name).toBeTruthy();
    }
  });

  it('should not list a permission that the backend catalogue lacks', () => {
    for (const permission of PERMISSIONS) {
      expect(backendNames, permission).toContain(permission);
    }
    expect(Object.keys(PERMISSION_LABELS).sort()).toEqual([...backendNames].sort());
  });

  it('should group user:role:assign and user:directory:read under user', () => {
    expect(permissionResource('user:role:assign')).toBe('user');
    expect(permissionResource('user:directory:read')).toBe('user');
  });
});
