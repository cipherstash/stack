---
'@cipherstash/eql': minor
---

**Stack Encrypt produces the EQL v4 ordered date, timestamp and numeric types** (`eql-bindings`, `stack-encrypt` feature): `DateOrd`, `DateOrdOpe`, `DateOrdOre`, `TimestampOrd`, `TimestampOrdOpe`, `TimestampOrdOre`, `NumericOrd`, `NumericOrdOpe` and `NumericOrdOre`. A date orders by its day, a timestamp by the microsecond (truncated, as `TimestampEq`'s `=` is) and a decimal by value, so `1.5` and `1.50` order as equal. `v4::plaintext::Date`, `Timestamp` and `Decimal` are Vitamin C's types, re-exported through Stack Encrypt at the same path, with `OutOfRange` for a jiff `Timestamp` outside the range. The Go SDK's `encrypt/eql` table marks the nine producible.
