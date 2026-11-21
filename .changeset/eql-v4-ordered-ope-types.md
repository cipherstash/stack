---
'@cipherstash/eql': minor
---

**Stack Encrypt produces the OPE-ordered EQL v4 types `IntegerOrd`, `SmallintOrd`, `BigintOrd`, `RealOrd`, `DoubleOrd`, `TextOrd` and their `OrdOpe` twins** (`eql-bindings`, `stack-encrypt` feature). Their `op` term orders by ADR-0002's order key, so `<`, `<=`, `>`, `>=` and `ORDER BY eql_v4.ord_term(col)` compare integers by value, floats as PostgreSQL's `float8` does and text by its fold (case and accents folded). `=` on text reads `TextEq`'s equality term. `TextSearch` stays unproducible, with a reason: its query carries a match term that short text cannot make.
