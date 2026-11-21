---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: a `JsonTreeDocument` field of a derived Stack Encrypt record is queried from its field reference, and each query returns the EQL query type a parameter binds as.

- `EncryptedCustomer::PROFILE.contains(doc)` gives a `JsonTreeQuery` for `@>`, and `contained_by(doc)` one for `<@`.
- `at(path).gt(v)` and the other comparisons give a `JsonTreeLeafQuery`, `at(path).between(lo, hi)` two of them, and `at(path).selector()` the `JsonTreeSelector` that `->` takes.
- `elements(path).eq(member, v)..` gives a `JsonTreeElementsQuery`, `predicate(text)` a `JsonTreePredicateQuery`, and `children(path)` a `JsonTreeToken`.
- `#[stash(json(ordered = ["$.age"]))]` on the field names the paths the documents order. The field is sealed under those options and queried under them.

Each query is the operand a data plan naming `JsonSearch` derives for the same column and options, which is what the Go SDK sends.

A value passed by value is now sealed without a copy when its type seals it and derives no search term: a `JsonTreeDocument`, a data plan field that names `JsonSearch`, and the storage-only v4 types (`Integer`, `Text`, `Json` and the rest). The copy was wiped before, so nothing leaked; it was not needed.

The stored format, the SQL bundle and the TypeScript types do not change.
