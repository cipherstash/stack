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
`cipherstashFromStack`, the package's sole setup path.

The camelCase TS-authoring factory exports move in lockstep:
`encryptedTextSearch` → `textSearch`, `encryptedDoubleOrd` → `doubleOrd`, etc.
(a property test enforces the PSL and TS names agree modulo first-letter case).

Unchanged: the runtime value envelopes (`EncryptedString`, `EncryptedNumber`,
`EncryptedBoolean`, …), the generated `contract.json` / codec ids, and the
`eql*` query operators. The legacy v2 constructors are removed elsewhere in
this release.

The `stash-prisma-next` skill is updated to the new names (skills ship in the
`stash` tarball).
