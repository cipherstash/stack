---
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack': minor
---

EQL v3 Drizzle: encrypt every query operand with `encryptQuery`, not `encrypt` (#622).

The v3 Drizzle operators (`eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`notBetween`/
`inArray`/`notInArray`/`contains`) previously encrypted their operands with
`client.encrypt`, producing a full storage envelope (including the ciphertext `c`)
cast to `::jsonb`. A WHERE-clause operand should be a query *term*, not a value to
store. Every operator now uses `client.encryptQuery`, which yields a
ciphertext-free query term cast to the column's `eql_v3.query_<domain>` type — so
predicates carry no ciphertext and reach the bundle's `(domain, query_<domain>)`
operator overloads. This unifies the scalar/text operators with the JSON
containment path (already on `encryptQuery`) and removes the previously-optional
`encryptQuery` guard: it is now a required capability of the operand client.

`@cipherstash/stack` gains a batch `encryptQuery(terms)` overload on
`TypedEncryptionClient` (the type `EncryptionV3` returns), mirroring the nominal
`EncryptionClient`. This is additive — it lets `inArray`/`notInArray` encrypt a
whole list of query terms in one crossing.
