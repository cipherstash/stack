---
'@cipherstash/eql': minor
---

**The `eql-bindings` crate has an `eql_bindings::v4` module: payload types for the EQL v4 domains.** EQL v4 is the v3 SQL installed under a second name (ADR-0002), for values written by Stack Encrypt. The module is generated from the same catalog as `v3`, with `eql_v4_*` domain names and `"v": 4`, and has its own `SchemaVersion`, which rejects any other version. Only v4 types derive Stack Encrypt's `EncryptFrom` and `DecryptInto`, and the Stack Encrypt target table names v4 domains. The `v3` types and the TypeScript package are unchanged.
