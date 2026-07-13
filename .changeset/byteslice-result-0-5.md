---
'@cipherstash/stack': minor
---

Upgrade `@byteslice/result` to 0.5.0. Its `FailureOption` no longer accepts a bare `{ type }` shape — a failure must be an `Error` or carry an `error: Error`. `EncryptionError` now includes a required `error: Error` holding the originating error, and all failures are built through the new `toEncryptionError(type, error, code?)` factory (which coerces any caught value to a real `Error`). The existing `type` / `message` / `code` fields are unchanged, so code that reads `result.failure.type` / `.message` / `.code` keeps working.
