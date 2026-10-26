import catalogue from '../../../../../contracts/api/permission-catalogue.json';
import { PERMISSIONS, permissionResource } from './permission';

const backendNames: readonly string[] = catalogue.data.map((entry) => entry.name);

describe('permission catalogue', () => {
  it('should know every backend permission name in PERMISSIONS', () => {
    for (const name of backendNames) {
      expect(PERMISSIONS as readonly string[], name).toContain(name);
    }
  });

  it('should not list a permission that the backend catalogue lacks', () => {
    for (const permission of PERMISSIONS) {
      expect(backendNames, permission).toContain(permission);
    }
    expect([...PERMISSIONS].sort()).toEqual([...backendNames].sort());
  });

  it('should group user:role:assign and user:directory:read under user', () => {
    expect(permissionResource('user:role:assign')).toBe('user');
    expect(permissionResource('user:directory:read')).toBe('user');
  });
});
