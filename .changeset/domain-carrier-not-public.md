---
'@cipherstash/stack': patch
---

The phantom domain carrier on encrypted v3 columns is no longer part of the
public surface.

Recovering a column's domain after declaration emit requires the type parameter
to appear bare somewhere in the instance type, which is what makes typed
`encryptQuery` callable against the published package. That carrier was a
plainly named `__domain` property, and this build has no `stripInternal`, so
`@internal` was documentation rather than enforcement: it appeared in
autocomplete on every column and could be read from consumer code, typed
`D | undefined` while being `undefined` at runtime in every case.

It is now keyed by a `unique symbol` that is not exported, so it is unnameable
outside the package while remaining exactly as inferrable. Nothing is emitted at
runtime and no call site changes.
