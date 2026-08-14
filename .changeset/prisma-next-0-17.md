---
'@cipherstash/stack-prisma': major
'stash': patch
---

Upgrade the Prisma Next integration to Prisma Next 0.17 (the `prisma/prisma` "Prisma 8" main line). Consuming apps must move to the 0.17 publish surface to use this release.

Breaking changes for consumers:

- **Dependencies**: the `@prisma-next/*` scope is retired. An application now depends on exactly one database facade — `@prisma/orm-postgres@0.17.0` — plus this extension. `@cipherstash/stack-prisma` itself builds against `@prisma/orm-framework`, `@prisma/orm-family-sql`, and `@prisma/orm-toolchain`, and declares `@prisma/orm-target-postgres` as a peer dependency.
- **Generated imports**: the emitted `contract.d.ts` now imports this extension's types from `@cipherstash/stack-prisma/{codec-types,operation-types,runtime}` (previously the stale `@prisma-next/extension-cipherstash/*` names, which no longer resolve). Re-run `prisma-next contract emit` after upgrading.
- **Contract and migration hashes**: 0.17 renames the contract's `extensionPacks` key to `extensions` and drops the `sha256:` prefix from every content hash, so every contract `storageHash` and `migrationHash` changes. The shipped migration set is re-anchored accordingly; consumer repos convert their checked-in `migrations/` trees with the upstream `strip-sha256-hash-prefixes` codemod and `scripts/migrate-migrations-layout.mjs` (the content-addressed `migrations/snapshots/` store replaces per-migration `end-contract.*` files). Vendored `migrations/cipherstash/` copies must be refreshed (delete and re-run `prisma-next migration plan`, or copy the shipped artefacts).
- **Codec descriptors**: the v3 codec descriptors are now Postgres target descriptors (`nativeTypeFor` / `projectJson` via `postgresCodec`), replacing the deleted `meta.db.sql.postgres` channel, and the pack meta publishes them through `types.codecTypes.codecDescriptors` (0.17 removed `codecInstances`).
- **Config**: in `prisma-next.config.ts` use the facade's `defineConfig` from `@prisma/orm-postgres/config` with `extensions: [cipherstash]` (`extensionPacks` fails loudly on 0.17).

The `stash` CLI now also detects Prisma Next projects that depend on the 0.17 packages (`prisma-next` or any `@prisma/orm-*` package), and the bundled `stash-prisma` skill documents the 0.17 surface.
