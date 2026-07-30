---
'@cipherstash/stack-prisma': patch
'@cipherstash/stack': patch
'stash': patch
---

Fix `prisma-next db init` failing with PN-RUN-3020 on fresh databases, and bump the pinned EQL bundle to 3.0.4.

The cipherstash space's EQL install migration is re-emitted with `additive` operation class (it only CREATEs its own schemas/domains/functions, and the genesis edge is not a self-edge, so the integrity checker accepts it) and now bakes the eql-3.0.4 bundle while carrying the upgrade invariants, so fresh-database `db init` — including Prisma Compute preview deploys — satisfies the head ref from a single all-additive edge. A new `data`-classed 3.0.4 upgrade self-edge covers databases installed at an older bundle via `migrate`. Consumers with a vendored `migrations/cipherstash/` should delete the space directory and re-run `prisma-next migration plan` to pick up the re-emitted artefacts.
