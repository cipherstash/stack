---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'stash': patch
'@cipherstash/wizard': patch
---

Finish the EQL v2-removal release gates and adapter correctness pass.

- Supabase preserves nested PostgREST boolean expressions and
  `referencedTable`, never sends nullish encrypted search operands as
  plaintext, honours escaped LIKE metacharacters, rejects CSV result mode
  before decryption, and diagnoses the removed object-form factory call.
- Native, WASM, and Supabase model decryption reconstruct valid date and
  timestamp values consistently, including nested paths, aliases, and bulk
  results, while leaving invalid values unchanged.
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
