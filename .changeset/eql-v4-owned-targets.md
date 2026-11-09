---
'@cipherstash/eql': minor
---

`eql-bindings` (the Rust crate released with this package): every EQL v4 type Stack Encrypt produces now implements Stack Encrypt's owned traits, `EncryptTarget` and `DecryptSource`, and every derived query type implements `EncryptTarget`. A Rust program can write `email.encrypt_into_with_context(&keyset, column)` and `String::decrypt_from(stored, &keyset)` for an EQL type. The owned traits take the plaintext by value and wipe it. The same derives still implement the older `EncryptFrom` and `DecryptInto`, so `encrypt_as`, plans and the by-name dispatch work as before. Both APIs write the same terms, and each opens what the other wrote. An `Option` of an EQL type stores nothing for `None`, which is a database NULL. A type over an `Option` of its plaintext still seals a null, as before. The stored format, the SQL bundle and the TypeScript types do not change.
