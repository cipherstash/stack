---
'@cipherstash/prisma-next': patch
---

`@cipherstash/prisma-next` now versions in lockstep with the Stack release
train (`stash`, `@cipherstash/stack`, and the other adapters) via a Changesets
`fixed` group — `stash init` installs it pinned by exact version, so the two
must always release together. This moves the package from its previous `0.4.x`
line onto the shared train version; no API changes.
