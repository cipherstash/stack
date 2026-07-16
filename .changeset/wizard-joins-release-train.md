---
'@cipherstash/wizard': patch
---

`@cipherstash/wizard` now versions in lockstep with the Stack release train
(`stash`, `@cipherstash/stack`, and the adapters) via a Changesets `fixed`
group — the `stash` CLI executes the wizard by exact version, so the two must
always release together. This moves the package from its previous `0.5.x`
line onto the shared train version; no API changes.
