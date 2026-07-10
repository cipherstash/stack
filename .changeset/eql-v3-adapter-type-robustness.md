---
'@cipherstash/stack': patch
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

No runtime change. The un-erasure has teeth: a `{ encrypt }` double returning
`unknown` no longer satisfies `createEncryptionOperatorsV3`, pinned in
`operators.test-d.ts`.
