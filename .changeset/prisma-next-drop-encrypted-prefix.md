---
'@cipherstash/prisma-next': minor
'stash': patch
---

**Breaking (v3 authoring surface):** the EQL v3 PSL column constructors drop
the `Encrypted` prefix to line up with the stack / Drizzle `types.*` catalog —
the `cipherstash.` namespace already disambiguates. So
`cipherstash.EncryptedTextSearch()` → `cipherstash.TextSearch()`,
`cipherstash.EncryptedDoubleOrd()` → `cipherstash.DoubleOrd()`,
`cipherstash.EncryptedBoolean()` → `cipherstash.Boolean()`, etc.

The v3 one-call setup function is renamed `cipherstashFromStackV3` →
`cipherstashFromStack` (v3 is the default), and the existing v2 setup function
becomes `cipherstashFromStackV2`.

Unchanged: the runtime value envelopes (`EncryptedString`, `EncryptedNumber`,
`EncryptedBoolean`, …), the `cipherstash.*V2` legacy column constructors, the
generated `contract.json` / codec ids, and the `eql*` query operators. The
camelCase TS-authoring factory exports (`encryptedTextSearch`, …) keep their
prefix for now — a follow-up will align them.

The `stash-prisma-next` skill is updated to the new names (skills ship in the
`stash` tarball).
