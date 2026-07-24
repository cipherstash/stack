---
'stash': patch
---

Correct the EQL v2/v3 rollout lifecycle in the bundled `stash-encryption`,
`stash-supabase` and `stash-drizzle` agent skills. Each described the **v2**
lifecycle as the unqualified default even though v3 is the default generation,
so an agent following the prose would run steps that do not apply — and, in one
case, expect the wrong column to be dropped.

- `stash encrypt drop` was documented as removing `<col>_plaintext`. That is the
  **v2** target. On a v3 column there is no `<col>_plaintext`: the command drops
  the **original `<col>`**, guarded by a `DO` block that takes `ACCESS EXCLUSIVE`
  and re-counts unencrypted rows at apply time, raising instead of dropping if
  any remain. Each step in the cutover table is now marked v2-only or v3, and the
  drop preconditions (`cut-over` for v2, `backfilled` for v3) are stated.
- "The pending row will be promoted to active by `stash encrypt cutover`" was
  false for v3, where cutover short-circuits before touching any configuration.
  `stash db activate` is the only promotion path there.
- The CipherStash Proxy call-outs told every reader to run `stash db push`.
  `db push`/`db activate` manage `eql_v2_configuration`, which EQL v3 does not
  ship — on a v3-only database `db push` reports "Nothing to do." and exits 0,
  and `db activate` errors. The call-outs are now scoped to the EQL v2 + Proxy
  path.
- The `stash encrypt cutover` row claimed application reads of the promoted
  column "return decrypted ciphertext transparently". That holds only through
  CipherStash Proxy, and it contradicted the next row, which requires the
  decrypt path — an agent following the table would return raw
  `eql_v2_encrypted` composites to end users. SDK/ORM reads are now stated to
  need the explicit decrypt path.
- `stash init`'s setup prompt told agents to declare an **EQL v2** cutover
  target with a `types.*` domain. Those are EQL v3 only; a v2 column is an
  `eql_v2_encrypted` composite. The v2 branch now points at the deprecated
  `@cipherstash/stack/schema` builders as a read-only path, decrypting through
  `@cipherstash/stack`.

Skills ship inside the `stash` tarball and are copied into user projects at
`stash init`, so this guidance was being installed into customer repos.
