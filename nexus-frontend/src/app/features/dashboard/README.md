# Dashboard

`DashboardComponent` is the landing page after sign-in. It is an empty page with a heading (`data-testid="dashboard-root"`) and no logic.

The page chrome, the `GET /v1/users/me` priming request, the permission-filtered navigation and logout (US-005) belong to the shell, `core/layout/shell`, which also provides the page's single `main` landmark. See `docs/features/US-019/03-design.md` section 12.3 and `docs/features/US-005/03-design.md` for logout and revocation.
