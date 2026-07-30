---
'stash': patch
---

Make `stash encrypt` work in Prisma Next projects.

`stash encrypt backfill` could not run against a Prisma Next project for two independent reasons, both now fixed:

- **No encryption client file.** Prisma Next integrations deliberately have none — encrypted columns are declared in the PSL contract. Loading the encryption context hard-failed on the missing file. It now falls back (mirroring the existing Drizzle auto-derive) to detecting the project, locating the emitted `contract.json`, and deriving the v3 schemas with the adapter's own `deriveStackSchemasV3` + `Encryption`. Both `@cipherstash/stack-prisma` and `@cipherstash/stack` are resolved from the user's project, so the CLI's schema view always matches the application's.
- **`cipherstash.cs_migrations` never existed.** That schema is created by `stash eql install`, which the Prisma Next flow skips (EQL installs through the `prisma-next` migration graph, which doesn't carry the tracking schema). The first checkpoint write then failed with an opaque relation-does-not-exist error. `backfill` now bootstraps it via the existing idempotent `installMigrationsSchema` before any event is written.

`skills/stash-cli` documents both, including that the `client` config option is not required in Prisma Next projects.
