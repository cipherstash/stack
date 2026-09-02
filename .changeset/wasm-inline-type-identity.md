---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'stash': patch
---

Fix: a schema authored with `encryptedTable`/`types` from
`@cipherstash/stack/wasm-inline` was a compile error wherever an EQL v3 table was
expected — `encryptedSupabase`'s `schemas`, the Drizzle helpers, Prisma Next, the
native `Encryption` — and native-authored tables were rejected by the WASM
`Encryption`, with `Types have separate declarations of a private property
'columnName'`. The two entries shipped separately-emitted copies of every column
class, and TypeScript compares classes with private members by declaration
origin. The runtime was never affected, which made `as any` the tempting fix.

Every entry now resolves one declaration, so one schema module can be shared
between a Node server and an Edge Function in either direction. `./wasm-inline`
keeps its ESM-only shape.
