---
'stash': patch
---

`skills/stash-encryption` now documents how to name the client's type
(`EncryptionClientFor<S>`, not `Awaited<ReturnType<typeof Encryption>>`, which
always resolves to the untyped nominal client) and states that `schemas` accepts
any non-empty array of v3 tables rather than only an array literal.
