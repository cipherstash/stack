---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: an EQL v4 type can now be a field of a Stack Encrypt record.

- A `#[derive(EncryptTarget, DecryptSource)]` record with `struct = ..` can have fields such as `email: TextEq` or `profile: JsonTreeDocument`. The field's column is the record's scope and the field's name, so `scope = "members"` and the field `email` store `{"t": "members", "c": "email"}` in `i`.
- A field writes the same terms as the type written on its own under that column, and as a data plan that names the type. A data plan is how the Go module writes the type.
- A record that lists a caller scope or a binding cannot have an EQL field, because an EQL value stores only a table and a column. Every call is refused with `PlanError::ContextNotStorable`, which names the field, before any key is requested.
- `JsonTreeDocument` now implements `EncryptTarget` and `DecryptSource` for `JsonPlaintext`. It encrypts under the default options, with the column as its context.

The stored format, the SQL bundle, and the TypeScript types do not change.
