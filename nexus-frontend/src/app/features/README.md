# features/

One folder per business feature (bounded context), lazy-loaded from `app.routes.ts`:

```
features/<feature-name>/
├── pages/        # Routed (smart) components — inject facades, own no presentation logic
├── components/   # Presentational (dumb) components — input()/output() only, OnPush
├── services/     # Feature facade + API access; state via signals exposed read-only
├── models/       # Domain types for this feature
└── <feature-name>.routes.ts
```

Rules:
- Features may import from `core/` and `shared/` — never from another feature.
- Register routes with `loadChildren: () => import('./features/<name>/<name>.routes')`.
- See `.claude/skills/angular-standards/SKILL.md` for component conventions.
