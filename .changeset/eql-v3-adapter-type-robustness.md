---
'@cipherstash/stack': minor
---

Restore the EQL v3 envelope and `Result` types the adapters were erasing.

Both v3 adapters typed their operand-encryption paths as `unknown` and dropped
the `Result` wrapper, so the query-type encoding and the failure channel were
invisible to the type system:

- `eql/v3/drizzle/operators.ts` typed the client's `encrypt`/`bulkEncrypt` as
  returning `unknown`, collapsed the operation's `Result` to
  `{ data?: unknown; failure?: { message } }`, and cast the bulk response to
  `Array<{ data: unknown }>`.
- `supabase/query-builder-v3.ts` returned `Promise<unknown[]>` from
  `encryptCollectedTerms`, `bulkEncryptGroup` and `encryptGroupPerTerm`, and the
  base `query-builder.ts` did the same.

These now carry the SDK's real types — `Encrypted` (the storage envelope union,
which includes every v3 per-domain payload), `BulkEncryptedData`, and
`EncryptedQueryResult` — threaded through a properly-typed operation surface that
resolves `Result<T, EncryptionError>`. The Supabase divergence the erasure hid is
now explicit: the v2 path yields `encryptQuery` composite literals and the v3
path yields `JSON.stringify`'d envelope strings, and both are `EncryptedQueryResult`.

Bumped `minor`, not `patch`: `createEncryptionOperatorsV3` is a public export
(`@cipherstash/stack/eql/v3/drizzle`), and tightening its client contract from
`unknown` to a typed operation surface is a compile-time breaking change — a
downstream consumer passing a loosely-typed (`unknown`-returning) client double
will now fail `tsc`. That tightening has teeth: `operators.test-d.ts` pins it
with a negative type-test asserting an `unknown`-returning `{ encrypt }` double
is rejected (a positive "correctly-typed double is accepted" assertion cannot
catch a re-erasure, since a correct value is assignable to `unknown`).

Behaviour is otherwise unchanged, with one addition: the Supabase v3 bulk path
now rejects a `null` envelope returned by `bulkEncrypt` (the restored
`Encrypted | null` type makes that arm reachable, and a `null` would otherwise
be `JSON.stringify`'d to the literal `"null"` and sent as a filter operand).
