---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: an EQL v4 type can now be a field of a Stack Encrypt record.

- A `#[derive(EncryptTarget, DecryptSource)]` record with `struct = ..` can have fields such as `email: TextEq` or `profile: JsonTreeDocument`. The field's column is the record's scope and the field's name, so `scope = "members"` and the field `email` store `{"t": "members", "c": "email"}` in `i`.
- With no scope and no binding, a field writes the same terms as the type written on its own under that column, and as a data plan that names the type. A data plan is how the Go module writes the type.
- A record can list a scope or a binding, such as `scope(tenant: u64)` or `bind(row: u128)`. The terms of an EQL field then derive under the column and the scope. The ciphertext is sealed under the column, the scope and the binding. A field of any other type works the same way. `i` stores the column alone, so the reader supplies the scope and the binding again. The same is true of an EQL field of a record nested in another.
- A query from a field reference takes the record's scope with `.scope(..)`. It gives the term of the values stored under that scope.
- A data plan that names an EQL type takes a scope and a binding in the same way. So a Go struct with an `encrypt_into` field now seals through `cipher.Scope(..).Bind(..)`, where it was refused.
- `JsonTreeDocument` now implements `EncryptTarget` and `DecryptSource` for `JsonPlaintext`. It encrypts under the default options, with the column as its context.

The stored format, the SQL bundle, and the TypeScript types do not change.
