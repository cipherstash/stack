---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package, can now decrypt one child of a JSON node on its own. A read of one child no longer needs the parent's whole subtree.

- Your app pairs each entry that `eql_v4.json_tree_children` returned with the parent's `JsonSubtreeKey`, through `JsonTreeChild::from_key(&key, entry)`.
- Decrypting checks that the entry is a child of that parent.
- Your app decrypts into a `JsonPlaintext` for the child's value. Decrypt into a `JsonChildPlaintext` for its key or index too.
- A child with members of its own does not decrypt alone. Read it through `JsonTreeSubtree`.

The EQL v4 JSON tree reference describes the child read. The stored format and the SQL bundle do not change.
