---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package, now supports Stack Encrypt's owned API for the EQL v4 types.

- Every EQL v4 type that Stack Encrypt produces implements `EncryptTarget` and `DecryptSource`. Every derived query type implements `EncryptTarget`.
- A Rust program can write `email.encrypt_into_with_context(&keyset, column)` and `String::decrypt_from(stored, &keyset)`. The owned traits take the plaintext by value and wipe it.
- The by-name dispatch (`encryption::targets`) runs each type through these traits.
- An `Option` of an EQL type stores a database NULL for `None`.
- A type encrypted from an `Option` of its plaintext still seals a null, as before.

The stored format, the SQL bundle, and the TypeScript types do not change.
