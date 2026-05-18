---
"@cipherstash/prisma-next": minor
---

Upgrade `@prisma-next/*` peer/runtime stack from `0.6.0-dev.8` to `0.8.0`.

`@prisma-next/sql-runtime@0.8` reordered the SQL execution pipeline so the `beforeExecute` middleware chain fires *before* `encodeParams`. `bulkEncryptMiddleware` now mutates params via `replaceValues(...)` ahead of encode, which means `CipherstashCellCodec.encode` is invoked with the wire-format string rather than the original `EncryptedEnvelopeBase`. The cell codec now short-circuits string values through unchanged; the envelope path is preserved for direct (non-runtime) callers such as the codec unit tests.

`SqlMiddlewareContext.scope` (`"runtime" | "connection" | "transaction"`) also became required in 0.8 (was optional in 0.7); test mocks now set `scope: 'runtime'` explicitly.
