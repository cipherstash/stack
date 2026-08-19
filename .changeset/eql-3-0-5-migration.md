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

**What does break is hand-written SQL naming the old function** — an
application query, a view, an RLS policy, or a per-function
`GRANT EXECUTE ON FUNCTION eql_v3.ste_vec_contains(…)`. After the upgrade
those fail loudly (`function eql_v3.ste_vec_contains(…) does not exist`)
rather than silently, but they fail. Grep your migrations, views and policies
for `ste_vec_contains`.

**Separately — and true of every EQL upgrade, not just this one:** the install
bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, so applying it
destroys every grant on every object in `eql_v3` / `eql_v3_internal`, along
with anything that depended on them (this is the same mechanism that drops
functional indexes on encrypted columns). **Re-run your grant script after
upgrading.** The schema-wide form EQL documents —
`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO app_role` — picks the new
name up on its own; a hand-written per-function grant has to be edited first.

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
generated against `@cipherstash/stack-prisma@1.0.0`, delete that directory and
re-run `prisma-next migration plan`; the seed phase regenerates it
byte-identical to the shipped artefacts. Your database keeps its markers, so
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
