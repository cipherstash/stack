---
'stash': patch
---

The client file `stash init` writes now compiles.

Both placeholder templates emitted `await Encryption({ schemas: [] })`, and
`Encryption` requires at least one table — an empty schema set is a deliberate
compile error, so it cannot be relaxed. Every `stash init` therefore left a
project whose first `tsc` or `next build` failed, in a file the CLI had just
told the user not to hand-edit. The consolidated `Encryption` factory enforces
the non-empty schema requirement.

The scaffold now declares a single sentinel table, `__stash_placeholder__`, so
the file typechecks as written. Every command that reads the encryption client
— `stash db push`, `stash db validate`, and `stash encrypt backfill` — refuses
to run while that table is still the only one declared, and names it, rather
than failing later with a confusing "table not found". (`stash encrypt cutover`
and `stash encrypt drop` do not read the client file at all; they resolve
against the database.)

Nothing in the repo compiled this output before: `packages/cli` has no
typecheck step, the codegen tests only string-match fragments of the template,
and the step test stubs the generator out entirely. Both templates are now
committed as fixtures that CI typechecks, pinned byte-for-byte to the generator
so they cannot drift.

Superseded later in this release: the generated guidance no longer references removed `db push` or `encrypt cutover` commands.
