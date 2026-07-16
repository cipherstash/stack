---
'stash': patch
'@cipherstash/stack-drizzle': patch
---

The legacy `@cipherstash/drizzle` package (the `@cipherstash/protect`-based
Drizzle integration) is removed from the repository and the release train —
`@cipherstash/protect` is sunsetting at Stack 1.0, and the package's successor
is `@cipherstash/stack-drizzle`. Already-published versions remain installable
from npm (deprecated, pointing here); the git history preserves the source for
any emergency maintenance. The `stash-drizzle` skill and the
`@cipherstash/stack-drizzle` README now state the deprecation explicitly so
nobody (human or agent) installs the legacy package by mistake.
