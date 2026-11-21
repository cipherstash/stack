---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: the EQL v4 types no longer implement Stack Encrypt's older traits `EncryptFrom` and `DecryptInto`. Stack Encrypt removed them, with `encrypt_as`, `decrypt_as`, the plan builder and the query chain.

- Every type keeps `EncryptTarget` and `DecryptSource`. Write with `value.encrypt_into_with_context(&keyset, column)` and read with `P::decrypt_from_with_context(stored, &keyset, column)`.
- A typed query is a field reference of a derived record, such as `EncryptedMember::EMAIL.eq("bob").encrypt(&keyset)`.
- A JSON document is a `JsonPlaintext`, not a `serde_json::Value`. A typed JSON query is a document field's reference query, such as `EncryptedCustomer::PROFILE.at().age().gt(30).encrypt(&keyset)`.
- `JsonTree` no longer implements `stack_encrypt::target::Layout`. `encryption()`, `index()` and `specs()` are its own methods.

The stored format, the SQL bundle, and the TypeScript types do not change.
