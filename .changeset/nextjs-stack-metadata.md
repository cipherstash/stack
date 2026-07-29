---
'@cipherstash/nextjs': patch
---

Correct the published package metadata to reference `@cipherstash/stack`
instead of the removed `@cipherstash/protect` package. The package now also
ships with its own source typecheck command and keeps its Vitest mock typing
compatible with the repository-pinned test runner.
