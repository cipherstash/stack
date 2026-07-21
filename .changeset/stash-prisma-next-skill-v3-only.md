---
'stash': patch
---

Update the bundled `stash-prisma-next` skill for the EQL v3-only
`@cipherstash/prisma-next`: drop the stale references to the removed EQL v2
surface (`cipherstashFromStackV2`, the `cipherstash*` operators, the "legacy v2"
subpath note) so the guidance copied into customer repos matches the package.
