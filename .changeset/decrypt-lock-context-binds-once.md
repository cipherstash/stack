---
'@cipherstash/stack': patch
---

`decryptModel` / `bulkDecryptModels` now drop `.withLockContext()` from the
returned operation once a lock context is bound, so binding twice is a compile
error instead of a runtime throw.

Passing a lock context positionally and then chaining it —
`client.decryptModel(row, users, lockContext).withLockContext(lockContext)` —
type-checked, then threw `this decrypt operation is already bound to a lock
context`. The type promised a method the runtime rejected.

The operation interface is split to match what the encrypt path already does,
where `EncryptModelOperationWithLockContext` simply lacks the method: the
new `LockBoundDecryptModelOperation` carries `.audit()` only, and
`AuditableDecryptModelOperation.withLockContext()` returns it. The runtime throw
stays as the backstop for plain-JavaScript callers.

An OPTIONAL lock context still type-checks. `decryptModel(row, users,
session?.lockContext)` — where the value is `LockContextInput | undefined` — is
the ordinary shape for code that decrypts identity-bound rows only for
signed-in users, and it compiled against the single optional parameter this
replaces. The positional overloads accept `LockContextInput | undefined` so it
keeps compiling; `undefined` binds nothing.
