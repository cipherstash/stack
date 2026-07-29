---
'@cipherstash/stack-supabase': patch
'@cipherstash/stack': minor
'stash': patch
---

Diagnose a legacy EQL v2 table shape by name instead of crashing with a raw
`TypeError`.

A table created by the former v2 API is structurally similar to a v3 one. Old
compiled code or untyped JavaScript could therefore pass that shape to
`encryptedSupabase({ schemas })` and fail deep inside verification, naming an
internal method rather than the version mismatch that caused it.

Both paths now fail closed with the table named and the fix stated. The check
routes through `hasBuildColumnKeyMap`, the canonical v2/v3 discriminator, rather
than a second hand-written spelling of it.

First-party adapters share an internal discriminator through
`@cipherstash/stack/adapter-kit`; it is adapter plumbing rather than an
end-user schema-authoring API.
