---
'@cipherstash/stack-prisma': minor
---

Move the bundled EQL v3 migrations to **eql-3.0.6**. This release changes only
the version stamp: `eql_v3.version()` returns `'3.0.6'` and the `eql_v3` schema
comment reads `'3.0.6'`. No function, operator, domain or index behaviour
changes.

Two artefacts carry the new bundle:

- A new upgrade edge, `20261002T0000_upgrade_eql_v3_3_0_6`, carrying the
  invariant `cipherstash:upgrade-eql-v3-bundle-3.0.6-v1`. Existing databases
  re-install through it on the next `prisma-next migration plan` followed by
  `prisma-next migrate`. **`migrate` alone is not enough**: only
  `migration plan` copies the new directory into your repo.
- The baseline install migration `20260601T0100_install_eql_v3_bundle`, which
  now bakes 3.0.6 and gains a fifth op, a no-SQL carrier for the new
  invariant, so fresh databases land on 3.0.6 from the single all-additive
  genesis edge and `db init` keeps working.

**Upgrading a 1.0.0 or 1.1.x database installs the EQL bundle twice.** Those
releases shipped eql-3.0.4, so `migrate` walks the 3.0.5 upgrade edge and then
the 3.0.6 one, re-installing the ~2.6 MB bundle once for each in the same run.
That costs time, not correctness: the database ends on 3.0.6 with every
invariant recorded. The 3.0.5 edge is kept rather than folded into this one
because the frozen-history guard treats every committed edge as published, and
a database built from `main` may already have walked it and recorded its
invariant. As with every EQL upgrade, each re-install opens with
`DROP SCHEMA IF EXISTS eql_v3 CASCADE`: re-run your grant script, and recreate
functional indexes and anything else depending on `eql_v3` (see the 3.0.5
entry).

**Action required: the one in the 3.0.5 entry, once.** npm has only ever
shipped the eql-3.0.4 baseline (1.0.0 on 30 July, 1.1.0 on 19 August, 1.1.1 on
20 August), so this release changes the published baseline once, not twice. If
your project has a `migrations/cipherstash/` directory generated against any
earlier version, delete it and re-run `prisma-next migration plan`. Your
database keeps its markers, so already-applied invariants are not re-run. If
you skip the delete, a fresh `db init` refuses with
`Operation cipherstash.upgrade-eql-v3-bundle-3.0.5 has class "data" which is
not allowed by policy.` — see "Upgrading from 1.0.0 or 1.1.x" in the package
README.

**Why the baseline was re-emitted rather than given a second genesis edge.**
In this repository the baseline was already re-emitted once, for 3.0.5, and
that decision said the trade must be re-argued on adoption numbers at the next
bump. This is that bump, and the trade came out the same way.
`@cipherstash/stack-prisma` had 144 npm downloads in September 2026 (52 in the
last week), fewer than the ~253 monthly downloads at which the 3.0.5 re-emit
was judged a small, knowable blast radius. The 3.0.5 re-emit never reached
npm, so what this one rewrites is unpublished. And since 3.0.6 changes only
the version stamp, the append-only alternative, a second `from: null` genesis
edge, would add another permanent ~2.6 MB copy of the bundle for no change in
behaviour. Once this package has real adoption, the second genesis edge is the
right shape.
