<!-- packages/prisma-next/scripts/REFRESH_EQL_V3.md -->
# Refreshing the vendored EQL v3 bundle

`src/migration/eql-v3-install.generated.ts` is a generated TypeScript module that
embeds `__tests__/fixtures/cipherstash-encrypt-v3.sql` (the self-contained
`eql_v3` Postgres installer) as a string. The v3 baseline migration installs that
string byte-for-byte under the `cipherstash:install-eql-v3-bundle-v1` invariant.

## SQL source of truth

The fixture itself is **not** authored here. It is the same artefact vendored in
`packages/drizzle/__tests__/fixtures/cipherstash-encrypt-v3.sql`, built from
`cipherstash/encrypt-query-language @ 035952e13fafc87c8a3c89fc7a7ff5447597bdd4`.
Follow `packages/drizzle/scripts/refresh-eql-v3-sql.md` to rebuild that fixture
from the EQL repo — it is the canonical procedure.

## Refresh procedure (this package)

1. Refresh the drizzle fixture per `packages/drizzle/scripts/refresh-eql-v3-sql.md`
   and record the new EQL commit SHA.
2. Re-copy it into this package:
   ```sh
   cp packages/drizzle/__tests__/fixtures/cipherstash-encrypt-v3.sql \
      packages/prisma-next/__tests__/fixtures/cipherstash-encrypt-v3.sql
   ```
3. Update `VERSION` in `scripts/vendor-eql-v3-install.ts` to the new SHA marker
   (`eql-v3-<short-sha>`).
4. Regenerate the embedded module:
   ```sh
   # tsx is not installed in this workspace; Node 22+ runs the TS script directly:
   node --experimental-strip-types packages/prisma-next/scripts/vendor-eql-v3-install.ts
   ```
5. Confirm the round-trip:
   ```sh
   pnpm -F @cipherstash/prisma-next vitest run test/v3/bundle.test.ts
   ```
6. Commit the fixture, the regenerated `.generated.ts`, and the version bump.

## Cross-package duplication hazard

The same large SQL artefact is vendored independently in `packages/drizzle` and
`packages/prisma-next`, each with its own refresh step — so the two copies can
drift. A shared `@cipherstash/eql-bundle` package would remove this hazard; it is
out of scope for this milestone. When refreshing, refresh **both** packages.
