---
'@cipherstash/stack': minor
---

Close two fail-open paths in the EQL v3 Drizzle adapter.

`ops.contains()` now throws `EncryptionOperatorError` when the search term is
shorter than the match index tokenizer's `token_length` (3 by default). Such a
term produces no ngrams, so its bloom filter is empty — and `stored_bf @> '{}'`
is true for every row. Previously a user searching `"ad"` silently received the
entire table; measured live, the needles `"ad"`, `"a"` and `"x"` each returned
every seeded row, including one in which `"x"` did not appear. The length floor
is shared with the v2 adapter via `matchNeedleError` in `schema/match-defaults`,
since both build byte-identical bloom filters.

`v3FromDriver()` now throws the new `EqlV3CodecError` on a payload that is not
an EQL envelope, instead of surfacing a raw `SyntaxError` for malformed JSON and
passing a bare scalar through unchecked — `v3FromDriver('5')` previously returned
`5` typed as `Encrypted`, which then reached `decrypt` as garbage. The guard
accepts both scalar envelopes (ciphertext at `c`) and SteVec documents
(ciphertext at `sv[0].c`). `EqlV3CodecError` is exported from
`@cipherstash/stack/eql/v3/drizzle` so callers can catch it.

Also removes an unreachable branch in `inArray`/`notInArray`, whose empty-list
guard already throws before it.
