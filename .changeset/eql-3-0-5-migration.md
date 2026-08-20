---
'@cipherstash/stack-prisma': minor
---

Move the bundled EQL v3 migrations to **eql-3.0.5**, which renames the SQL
function `eql_v3.ste_vec_contains` to `eql_v3.jsonb_document_contains`.

**The blast radius is narrower than a renamed public function suggests.** The
`@>` / `<@` operators on `public.eql_v3_json_search` behave exactly as before,
and so do the two function-form entry points that exist for platforms without
operator support — `eql_v3.jsonb_contains(jsonb, jsonb)` and
`eql_v3.jsonb_contained_by(jsonb, jsonb)` are byte-identical to 3.0.4. Those
are what a PostgREST caller invokes, so PostgREST callers on the documented
surface are **not** affected. The renamed function is the typed implementation
those operators dispatch into.

**And the old name still works.** eql-3.0.5 ships `eql_v3.ste_vec_contains` as
a deprecated delegating alias for both overloads, so hand-written SQL naming it
— an application query, a view, an RLS policy, or a per-function
`GRANT EXECUTE ON FUNCTION eql_v3.ste_vec_contains(…)` — keeps resolving. The
typed overload stays inlinable, so a function-form query through the alias
still matches the same functional GIN index. Migrate to
`jsonb_document_contains` when convenient; nothing forces it at upgrade time.

**Separately — and true of every EQL upgrade, not just this one:** the install
bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, so applying it drops
every object in `eql_v3` / `eql_v3_internal` and everything that depended on
them. **Encrypted data and column types are not affected** — the storage
domains are `public.eql_v3_*`, deliberately outside both dropped schemas, and
their CHECK functions are re-created rather than dropped. What does not survive
is everything else pointing into the schema, which is two actions, neither of
them to do with the rename:

1. **Re-run your grant script.** Every grant on every `eql_v3` /
   `eql_v3_internal` object is gone. The schema-wide form EQL documents —
   `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO app_role` — picks up
   both the new name and the alias on its own.
2. **Recreate your functional indexes, then `ANALYZE`.** Indexes over
   `eql_v3.eq_term(…)` / `ord_term` / `match_term` / `to_ste_vec_query(…)`
   depend on the dropped schema and go with it. Nothing errors afterwards:
   encrypted predicates keep working and silently fall back to sequential
   scans. A migration runner will not redo an already-applied migration, so
   this has to be a *new* one. The `stash-indexing` skill documents the
   mechanism ("These indexes do not survive an EQL reinstall or upgrade") and
   the `EXPLAIN` check that confirms recovery; capturing and restoring them
   automatically is tracked in
   [cipherstash/stack#918](https://github.com/cipherstash/stack/issues/918).

Any RLS policy, view, or constraint that calls an `eql_v3` function is dropped
by the same CASCADE and needs recreating too. **The rename itself needs no
action — the alias makes it non-breaking.**

Two artefacts carry the new bundle:

- A new upgrade edge, `20260814T0000_upgrade_eql_v3_3_0_5`, carrying the
  invariant `cipherstash:upgrade-eql-v3-bundle-3.0.5-v1`. Databases already
  running an earlier bundle re-install through this edge on the next
  `prisma-next migration plan` followed by `prisma-next migrate`, exactly as
  they did for 3.0.2 and 3.0.4. **`migrate` alone is not enough** — the seed
  phase that copies a new migration package into your repo runs only from
  `migration plan`, so without it the 3.0.5 directory never reaches disk and
  `migrate` is a silent no-op that leaves the database on the older bundle.
- The baseline install migration `20260601T0100_install_eql_v3_bundle`, whose
  baked bundle moves to 3.0.5 and which gains a fourth no-SQL carrier op for
  the new invariant. Fresh databases therefore land on 3.0.5 from the single
  all-additive genesis edge, keeping `db init` (additive-only policy) working.

**Action required.** The baseline's bytes — and so its `migrationHash` — have
changed. If your project already has a `migrations/cipherstash/` directory
generated against `@cipherstash/stack-prisma@1.0.0` or `@1.1.0`, delete that
directory and re-run `prisma-next migration plan` (or `migrate`); the 1.1.0
Prisma Next 0.17 upgrade re-anchored the same artefacts, so a space vendored
against either release is stale here. The seed phase regenerates
it byte-identical to the shipped artefacts. Your database keeps its markers, so
already-applied invariants are not re-run — the only new work is the 3.0.5
upgrade edge.

If you skip the delete, nothing warns you: a vendored baseline is stale but
internally intact, so it passes every integrity check. On an existing database
the upgrade still applies correctly; on a **fresh** one, `db init` refuses with
`Operation cipherstash.upgrade-eql-v3-bundle-3.0.5 has class "data" which is
not allowed by policy.` — an error that names neither the directory nor the
remedy. See "Upgrading from 1.0.0" in the package README.

**Why the baseline was re-emitted rather than left frozen.** These artefacts are
content-addressed and normally append-only: an EQL bump ships as a new upgrade
directory and published directories are never rewritten. That rule cannot be
followed here without a second `from: null` genesis edge, because no upgrade
edge can ever be walked by `db init` — every upgrade edge is a self-edge, and
the integrity checker requires a self-edge to carry a `data`-class op, which
`db init`'s additive-only policy refuses. A fresh database must therefore
collect every head-ref invariant from the genesis edge it walks. The
append-only alternative would duplicate the full ~2.6 MB bundle into a new
genesis edge on every EQL release, permanently; re-emitting was taken instead
while 1.0.0 was two weeks old with negligible adoption, and is a decision to be
re-argued on adoption numbers rather than repeated by default.
