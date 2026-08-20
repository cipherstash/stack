---
'stash': patch
---

Correct two things the bundled agent skills were telling customers wrongly
about EQL.

**`skills/stash-postgres` pointed at the wrong repository.** EQL's source now
lives in `cipherstash/stack` under `packages/eql/`, and that is where operator
gaps and domain-level bugs are filed; only *publishing* still happens from
`cipherstash/encrypt-query-language`, which the skill continues to say. The
skill also cited "the EQL skill" as a source of truth that "ships from
`encrypt-query-language` alongside the bundle" — no such skill ships from
either repository, so the reference is gone and the remaining three sources
(the generated types, the install SQL, and `SELECT eql_v3.version()`) are
renumbered.

**And it claimed the CLI pins an exact `@cipherstash/eql` version, "so a
database is only ever on one bundle."** Neither half holds: the CLI depends on
the workspace package rather than a pinned literal, and a database is on
whatever bundle was last applied to it — the Prisma Next adapter installs and
upgrades the bundle through its own migrations without involving the CLI at
all. Replaced with the guarantee that does hold: one `stash` release carries
one resolved bundle, and the database is the authority on which bundle it has.

**`skills/stash-prisma` hands out the functional-index recipe without saying an
EQL upgrade destroys it.** Installing a bundle begins with `DROP SCHEMA IF
EXISTS eql_v3 CASCADE`, which cascade-drops every index over an `eql_v3.*`
extractor — the PSL expression indexes Prisma Next 0.17 introduced and any
`rawSql` index DDL alike; queries keep working and silently sequential-scan.
Because an applied migration is never replayed, recovery is a NEW one: a PSL
expression index has to change its `name:` (the physical name carries a content
hash of the expression, so re-declaring the same one plans no work), and a
`rawSql` recovery op needs a new `id`. Said where the recipe is given, pointing
at `stash-indexing` for the mechanism and at
[cipherstash/stack#918](https://github.com/cipherstash/stack/issues/918) for
capturing and restoring them automatically.
