---
'@cipherstash/stack': minor
'@cipherstash/stack-supabase': minor
'stash': patch
'@cipherstash/wizard': patch
---

Finish the EQL v2-removal release gates and adapter correctness pass.

- **Supabase encrypts leaves nested inside a PostgREST boolean group.** This
  is a disclosure fix, not a formatting one. The `.or()` string parser had
  no group recursion, so `.or('and(createdAt.gte.2026-01-01,note.eq.x)')`
  came back from the top-level split as one part and the leaf parser cut it
  at the first dot into the pseudo-column `and(createdAt`. That name matched
  no encrypted column, so the whole expression took the verbatim branch: the
  operand `2026-01-01` reached PostgREST **as plaintext, against an
  encrypted column**, under the JS property name `createdAt` rather than the
  DB column name `created_at`. Every encrypted leaf nested inside `and(...)`
  / `or(...)` / `not.and(...)` leaked its operand to the database and
  returned wrong results. Nested groups and `referencedTable` are now
  preserved while each encrypted leaf is substituted in place.
- Supabase never sends nullish encrypted search operands as plaintext, honours
  escaped LIKE metacharacters, rejects CSV result mode before decryption, and
  diagnoses the removed object-form factory call. The bundled `stash-supabase`
  skill no longer lists `csv()` among the transforms passed through to
  Supabase — it throws, and the skill now says so and shows serializing the
  decrypted rows instead.
- Native, WASM, and Supabase model decryption reconstruct valid date and
  timestamp values consistently, including nested paths, aliases, and bulk
  results, while leaving invalid values unchanged. That last clause is a
  behavioural change on the native typed client and the Supabase adapter,
  which previously pushed every date-like column through `new Date(...)`
  unconditionally: a stored value that does not parse used to come back as an
  Invalid `Date` and now comes back as the raw string, matching what the WASM
  entry already did. The declared column type is still `Date`, so code that
  assumed `instanceof Date` held for every date column — or called a `Date`
  method on it unguarded, so that `.getTime()` used to yield `NaN` and now
  throws a `TypeError` — has to handle the raw value.
- `stash init` names the concrete `public.eql_v3_*` domain family and gives
  `public.eql_v3_text_search` as a valid Supabase example.
- CLI and wizard skill selection stay in parity for every integration,
  including the Prisma Next skill, and verify that each selected skill has a
  `SKILL.md`.

The final 1.0 integration surface is `Encryption` from
`@cipherstash/stack/v3`, the `@cipherstash/stack-drizzle` package root, and
`encryptedSupabase` from `@cipherstash/stack-supabase`. DynamoDB decrypt
operations retain `.audit()` on the typed `Encryption` client. Existing EQL v2
ciphertext remains readable through the core client; authoring and adapter
writes use EQL v3.
