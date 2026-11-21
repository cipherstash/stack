---
'@cipherstash/eql': minor
---

**`eql-bindings` says which match options an EQL type's filter is built under** (`targets` feature). `Target::match_options()` returns `EqlMatch`'s options for a type with a match index (`TextMatch`) and `None` otherwise, so Stack Encrypt can answer `matches` through the type's query twin: it cuts the query's tokens for `verify` exactly as the stored filter was cut. The SQL surface and the TypeScript package are unchanged.
