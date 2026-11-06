---
'@cipherstash/eql': minor
---

**Stack Encrypt produces the EQL v4 types `Smallint` and `SmallintEq`** (`eql-bindings`, `stack-encrypt` feature), from `i16`. `SmallintEq`'s equality term is the integer one, so a smallint and an integer of the same value under one column share it. The `date`, `timestamp` and `numeric` types now say they wait for a choice of Rust plaintext type, not for an engine kind.
