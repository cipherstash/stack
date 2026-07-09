---
'@cipherstash/stack': minor
---

Close two fail-open paths in the EQL v3 Drizzle adapter.

`ops.contains()` now throws `EncryptionOperatorError` for a search term that
tokenizes to nothing: the empty string, or a term shorter than the match index
tokenizer's `token_length` (3 by default). Such a term produces an empty bloom
filter, and `stored_bf @> '{}'` is true for every row — so a user searching
`"ad"` silently received the entire table. Measured live, the terms `"ad"`,
`"a"` and `"x"` each returned every seeded row, including one in which `"x"`
did not appear.

The floor counts Unicode codepoints, matching the tokenizer. A UTF-16 length
check would wave through an astral-plane term — `"👍👍"` is 4 code units but
only 2 codepoints, yields no trigram, and matched every row.

**Breaking for callers passing short terms:** `contains()` calls that previously
returned every row now throw. Terms of 3+ codepoints are unaffected.

`v3FromDriver()` now throws the new `EqlV3CodecError` on a payload that is not
an EQL envelope, instead of surfacing a raw `SyntaxError` for malformed JSON and
passing a bare scalar through unchecked — `v3FromDriver('5')` previously returned
`5` typed as `Encrypted`, which then reached `decrypt` as garbage. The guard
accepts both scalar envelopes (ciphertext at `c`) and SteVec documents
(ciphertext at `sv[0].c`). A SteVec's `sv` must be a non-empty array: `sv[0]` is
the decryption root, so `sv: []` carries a ciphertext key but no ciphertext, and
is now rejected rather than passed to `decrypt`. `EqlV3CodecError` is exported
from `@cipherstash/stack/eql/v3/drizzle` so callers can catch it.

Also removes an unreachable branch in `inArray`/`notInArray`, whose empty-list
guard already throws before it.

Note: the v2 Drizzle adapter's `like`/`ilike` path builds the same bloom filters
and has the same short-term fail-open. It is **not** fixed here — v2 terms carry
SQL wildcards, so the floor must be measured against what its tokenizer actually
receives before the shared guard can be reused. Tracked separately.
