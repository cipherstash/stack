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
requires. Their import map pins exact versions, with `@cipherstash/auth` at
the version `@cipherstash/stack` depends on, and says the schema is authored
from the `wasm-inline` entry.

The `stash-auth` skill now covers the Next.js and TanStack Start adapters
(`@cipherstash/auth/next`, `@cipherstash/auth/start`): the warmed strategy,
which does not refresh, the unauthenticated warmed-token header on Next.js,
and where `csFederateCurrent` must be called on Start. The Next.js example
there runs inside a function, because `headers()` throws outside a request,
and the skill's `description` is back under the 1024-character limit.
