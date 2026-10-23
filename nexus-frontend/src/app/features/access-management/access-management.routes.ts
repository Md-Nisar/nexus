import { Routes } from '@angular/router';

/**
 * Child routes of the gated `admin/access` parent (US-020 design §4.2). Empty in T-001 (A-1): the
 * entry gate, kill switch and nav pin exist before the console layout and pages, which arrive in
 * T-006. Until then an entitled `/admin/access` renders the shell with an empty `main`, and any
 * deeper path falls through to Not Found.
 */
export const ACCESS_MANAGEMENT_ROUTES: Routes = [];
