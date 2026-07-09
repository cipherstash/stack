---
"@cipherstash/stack": patch
"stash": patch
---

Refresh the bundled `stash-drizzle` skill and correct the `eq`/`ne` operator docs.

The skill ships inside the `stash` tarball and `stash init` installs it for every
Drizzle project, so its errors land in customer repos. It was last substantively
updated before `packages/drizzle` and the Drizzle adapter moved.

- **`eq` / `ne` require `equality`, not "`equality` or `orderAndRange`."** The
  skill and the operator's own TSDoc both claimed either index worked. On an
  `orderAndRange`-only encrypted column, `eq` falls through to the plain Drizzle
  operator and compares your **plaintext** value against the ciphertext column.
  It does not throw. The query simply cannot match. Corrected in the skill and in
  `packages/stack/src/drizzle/operators.ts`'s TSDoc, and documented as a hazard
  alongside the contrast that the `jsonb*` operators *do* throw when
  `searchableJson` is missing.
- **`npx generate-eql-migration` does not work for the documented install.** The
  skill tells you to `npm install @cipherstash/stack drizzle-orm`, then run that
  bin — but it belongs to the separate `@cipherstash/drizzle` package, which
  `@cipherstash/stack` does not depend on. `npx` then looks for a package of that
  name on the registry and gets `404 Not Found`. Replaced with
  `stash eql install --drizzle`, which runs `drizzle-kit generate --custom` with
  the bundled EQL SQL.
- **An additive `db push` is promoted by `stash db activate`, not by
  `stash encrypt cutover`.** The skill told Proxy users the rollout's pending
  config would be promoted at cutover. It won't: cutover promotes only the
  *rename* pending, and the cutover-time `db push` calls `discardPendingConfig()`
  first — so an un-activated rollout pending is discarded and Proxy serves the
  old active config for the entire dual-write window. `db activate` was not
  mentioned anywhere in the skill.
- **Encrypted columns must be nullable.** The storage DDL declared an encrypted
  `jsonb NOT NULL` column, which the agent doctrine shipped alongside it forbids
  because it breaks inserts during a rollout. Also corrected "EQL extension" —
  EQL is a schema plus a composite type, installed by `stash eql install`.
- Documents the Drizzle-specific rename migration that `stash encrypt cutover`
  scaffolds to keep drizzle-kit's snapshot in sync; adds the missing `timestamp`
  and `text` `dataType` values (the `CastAs` union has 8 members, the skill listed
  6); repoints closed issue #447 at open #585; notes that the Drizzle path is EQL
  v2 only and that `@cipherstash/stack/drizzle` is self-contained (not a re-export
  of `@cipherstash/drizzle`).
