---
'@cipherstash/eql': minor
---

**The `eql-bindings` crate has an `eql_bindings::v4` module: payload types for the EQL v4 domains.** EQL v4 is the v3 SQL installed under a second name (ADR-0002), for values written by Stack Encrypt. The module is generated from the same catalog as `v3`, with `eql_v4_*` domain names and `"v": 4`. `SchemaVersion` is now generic over the version it admits: `v3::SchemaVersion` is `SchemaVersion<3>` and `v4::SchemaVersion` is `SchemaVersion<4>`, each refusing the other's payloads, and plain `SchemaVersion` still means v3. Only v4 types derive Stack Encrypt's `EncryptFrom` and `DecryptInto`, and the Stack Encrypt target table (now `eql_bindings::v4::targets`) names v4 domains. Besides `TextEq`, Stack Encrypt now produces `Text`, `Integer`, `IntegerEq`, `Bigint`, `BigintEq`, `Boolean`, `Real` and `Double`, from the plaintext types in `eql_bindings::encryption::plaintext`; the Go SDK's `encrypt/eql` table marks them producible.

Nothing a released version shipped has changed. The v3 types, the v3 SQL and the TypeScript package are as they were; the `stack-encrypt` derives on the v3 text types and the `v3::targets` module were added after the last release and are moved to v4 here, not removed from a release.
