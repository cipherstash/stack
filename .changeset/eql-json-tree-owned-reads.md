---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: the parts of a `JsonSearch` document now decrypt through the owned API.

- `JsonTreeExtracted`, the entry `->` returns, implements `DecryptSource<JsonPlaintext>`.
- `JsonTreeSubtree`, the rows of a subtree read, implements `DecryptSource` for `JsonPlaintext`, `Option<JsonPlaintext>` and `Vec<JsonPlaintext>`.
- The decrypted value is a `JsonPlaintext`, which is wiped when it is dropped.
- The context is required. Pass the document's column. For a document that is a field of a record with scopes or bindings, pass the column, then those scopes and bindings.

The stored format, the SQL bundle, and the TypeScript types do not change.
