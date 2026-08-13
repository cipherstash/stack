# SQLx Migrations

There is a single migration: the generated EQL install. All test data is
provided per-test by the generated fixtures in `tests/sqlx/fixtures/` (see
`FIXTURE_SCHEMA.md`), not by migrations.

## Generated install migration

**Migration 001 is generated**, not static:
- Built from `src/v3/` using `mise run build` (the self-contained `eql_v3`
  surface)
- Automatically copied to `migrations/001_install_eql.sql` by `mise run test:sqlx`
- In `.gitignore` - never commit this file
- Ensures tests always use the current EQL version

## How SQLx Uses This Migration

When using `#[sqlx::test]`:
- Each test gets a fresh database
- Migration 001 runs automatically before each test, installing the latest
  built EQL
- Per-test data comes from generated fixtures opted into via
  `#[sqlx::test(fixtures(...))]`
- No need to manually reset the database between tests

## When to Manually Regenerate

**You usually don't need to regenerate** - the `test:sqlx` task handles it automatically.

Only regenerate manually if debugging migration issues:
```bash
mise run build
cp release/cipherstash-encrypt.sql tests/sqlx/migrations/001_install_eql.sql
```

## Adding New Test Data

Test data is provided by generated fixtures, not migrations. To add a new
scalar fixture, add a row to `eql-domains::CATALOG`; the generator produces
`tests/sqlx/fixtures/eql_v3_<T>.sql` on the next `mise run test:sqlx`. A test
opts in with `#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_<T>")))]`.
See `tests/sqlx/fixtures/FIXTURE_SCHEMA.md`.
