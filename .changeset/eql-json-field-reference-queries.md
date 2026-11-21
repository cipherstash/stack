---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: a `JsonTreeDocument` field of a derived Stack Encrypt record is queried from its field reference, and each query returns the EQL query type a parameter binds as.

- `EncryptedCustomer::PROFILE.contains(doc)` gives a `JsonTreeQuery` for `@>`, and `contained_by(doc)` one for `<@`.
- `#[stash(json(ordered = { "$.age": u32, "$.visits[*].place": String }))]` on the field names the paths the documents order and the type of the values at each. The field is sealed under those options and queried under them. `paths = { "$.name": String }` beside it declares a path compared with equality alone, which adds no ordering term. Stack Encrypt's derive checks every path when it compiles the record.
- Each declared path has a typed method: `at().age().gt(v)` and the other comparisons give a `JsonTreeLeafQuery`, `at().age().between(lo, hi)` two of them, and `at().age().selector()` the `JsonTreeSelector` that `->` takes. A path, a member or a value type the field does not declare does not compile, and neither does an ordering of a `paths` path.
- `elements().visits().place().eq(v).and()..` gives a `JsonTreeElementsQuery`, `predicate(text).var(name, v)` a `JsonTreePredicateQuery`, and `children(path)` a `JsonTreeToken`.
- A path built at run time is text: `at_text_path(path)` and `elements_text_path(path)` check it when the query is encrypted.

Each query is the operand a data plan naming `JsonSearch` derives for the same column and options, which is what the Go SDK sends.

A value passed by value is now sealed without a copy when its type seals it and derives no search term: a `JsonTreeDocument`, a data plan field that names `JsonSearch`, and the storage-only v4 types (`Integer`, `Text`, `Json` and the rest). The copy was wiped before, so nothing leaked; it was not needed.

The stored format, the SQL bundle and the TypeScript types do not change.
