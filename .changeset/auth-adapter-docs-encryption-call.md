---
"@cipherstash/auth": patch
"stash": patch
---

Fix the README and `@cipherstash/auth/next` JSDoc examples, which called
`new Encryption({ authStrategy })`. `Encryption` from `@cipherstash/stack` is
an async function that takes `{ schemas, config }`, so the examples failed to
type-check and threw `Encryption is not a constructor`. They now call
`await Encryption({ schemas, config: { authStrategy } })`. The two Edge
Function examples now import the `@cipherstash/stack/wasm-inline` entry, which
is the one that loads in Deno, and pass the `clientId` and `clientKey` it
requires.

The `stash-auth` skill now covers the Next.js and TanStack Start adapters
(`@cipherstash/auth/next`, `@cipherstash/auth/start`): the warmed strategy,
which does not refresh, the unauthenticated warmed-token header on Next.js,
and where `csFederateCurrent` must be called on Start.
