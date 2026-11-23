---
'@cipherstash/eql': minor
---

`eql-bindings`, the Rust crate released with this package: the field reference of an ordered EQL v4 type answers order queries. `EncryptedMember::AGE.gt(30).encrypt(&keyset)` gives the type's query twin (`IntegerOrdQuery`, `DateOrdOreQuery`, …) for `lt`, `lte`, `gt` and `gte` on every `…Ord`, `…OrdOpe` and `…OrdOre` type. `TextOrd`, `TextOrdOpe` and `TextOrdOre` answer `eq` too, and `TextSearch` and `TextSearchOre` answer `eq`, the orderings and `matches`. Each query is the one a data plan derives for a field that names the type.

A `TextOrd*` query carries its `hm` and its order term whatever the operator, and is refused, before any key is requested, for text either index refuses. `between` is not answered from a field reference.

The stored format, the SQL bundle and the TypeScript types do not change.
