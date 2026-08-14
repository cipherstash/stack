---
'@cipherstash/stack-prisma': minor
---

Move the bundled EQL v3 migrations to **eql-3.0.5**, which renames the SQL
function `eql_v3.ste_vec_contains` to `eql_v3.jsonb_document_contains`. The
operators are unchanged (`@>` / `<@` on `public.eql_v3_json_search` behave
exactly as before) — only callers that invoke the function **by name** are
affected, which in practice means Supabase / PostgREST, since PostgREST calls
functions rather than operators.

Two artefacts carry the new bundle:

- A new upgrade edge, `20260814T0000_upgrade_eql_v3_3_0_5`, carrying the
  invariant `cipherstash:upgrade-eql-v3-bundle-3.0.5-v1`. Databases already
  running an earlier bundle re-install through this edge on the next
  `prisma-next migrate`, exactly as they did for 3.0.2 and 3.0.4.
- The baseline install migration `20260601T0100_install_eql_v3_bundle`, whose
  baked bundle moves to 3.0.5 and which gains a fourth no-SQL carrier op for
  the new invariant. Fresh databases therefore land on 3.0.5 from the single
  all-additive genesis edge, keeping `db init` (additive-only policy) working.

**Action required.** The baseline's bytes — and so its `migrationHash` — have
changed. If your project already has a `migrations/cipherstash/` directory
generated against `@cipherstash/stack-prisma@1.0.0`, delete that directory and
re-run `prisma-next migration plan` (or `migrate`); the seed phase regenerates
it byte-identical to the shipped artefacts. Your database keeps its markers, so
already-applied invariants are not re-run — the only new work is the 3.0.5
upgrade edge.

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
