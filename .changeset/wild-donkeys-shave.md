---
'stash': patch
---

Fix invalid DDL when a Drizzle column changes to an EQL v3 domain.

`drizzle-kit generate` emits an in-place `ALTER TABLE … ALTER COLUMN … SET DATA TYPE`
when a plaintext column is changed to an encrypted one, which Postgres rejects — there
is no cast from `text`/`numeric` to an EQL type, and on drizzle-kit 0.31.0+ the emitted
type name is additionally mangled to `"undefined"."eql_v3_<name>"`. The migration
rewriter only recognised the EQL v2 type, so a v3 user was left with an un-runnable
migration and nothing to repair it.

The rewriter now matches the whole `eql_v3_*` domain family alongside `eql_v2_encrypted`,
across every mangled form observed from drizzle-kit 0.24 through 0.31, and emits the
matched domain in the replacement instead of a hardcoded v2 type. `stash eql migration
--drizzle` — the EQL v3 migration-first path — now runs the same sweep that `eql install
--drizzle` has always run, so the repair actually reaches v3 projects.

The rewrite's guidance comment now also warns that it drops the plaintext column in the
same migration, and points at the staged `stash encrypt` path (add → backfill → cutover →
drop) for populated production tables.
