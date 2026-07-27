---
'@cipherstash/stack': minor
---

`Encryption({ schemas, config: { eqlVersion: 2 } })` now throws when every table
in `schemas` is an EQL v3 table, instead of building a client that writes EQL v2
payloads into `eql_v3_*` columns.

`EncryptionV3` used to prevent this by forcing `eqlVersion: 3` over whatever the
caller passed — the override's comment said that was why it existed. Collapsing
`EncryptionV3` into a deprecated alias of `Encryption` removed the override, and
nothing else rejected the combination: `resolveEqlVersion` already threw for a
mixed v2/v3 schema set and for legacy v2 `searchableJson()`, but returned an
explicit version unchanged. So a caller upgrading from
`EncryptionV3({ schemas: [v3Table], config: { eqlVersion: 2 } })` — previously
auto-corrected, and working — silently got a v2-wire client instead, with no
diagnostic at any layer. The type surface agreed with the runtime (both say
"nominal client"), so nothing disagreed loudly enough to notice, and the failure
surfaced later as an `eql_v3_*` domain CHECK rejecting the write, or as v2 wire
landing in a v3 column wherever the check is looser.

The escape hatch itself is unchanged where it is actually used: an explicit
`eqlVersion: 2` over an **EQL v2** schema set still emits v2 wire, which is how
v2 payloads are minted for the read-compatibility suite. Mixed sets still throw
the existing mixing error. Reading v2 payloads is unaffected — `decrypt` and
`decryptModel` continue to read both generations regardless of the client's wire
version.

If you hit the new error, drop `config.eqlVersion` to emit v3, or build the
client from the EQL v2 schema you actually intend to write.
