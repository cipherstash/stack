---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: `JsonTreeChild::from_key(&key, entry)` opens one entry `eql_v4.json_tree_children` returned, checked against the `JsonSubtreeKey` of its parent's path, to the child's value. A read of one child no longer needs the parent's whole subtree. A child with members of its own does not open alone, and is read through `JsonTreeSubtree`.

The EQL v4 JSON tree reference describes opening a child. The stored format and the SQL bundle do not change.
