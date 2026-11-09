---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package, now supports Stack Encrypt's owned API for the EQL v4 types.

- Every EQL v4 type that Stack Encrypt produces implements `EncryptTarget` and `DecryptSource`. Every derived query type implements `EncryptTarget`.
- A Rust program can write `email.encrypt_into_with_context(&keyset, column)` and `String::decrypt_from(stored, &keyset)`. The owned traits take the plaintext by value and wipe it.
- The same derives still implement the older `EncryptFrom` and `DecryptInto`. So `encrypt_as`, plans, and the by-name dispatch work as before.
- The derives no longer generate a `plan()` function on each type. To build a plan for a type, use `Plan::value::<P>().encrypt_into::<T>()`.
- Both APIs write the same terms. Each API opens what the other API wrote.
- An `Option` of an EQL type stores a database NULL for `None`.
- A type encrypted from an `Option` of its plaintext still seals a null, as before.

The stored format, the SQL bundle, and the TypeScript types do not change.
