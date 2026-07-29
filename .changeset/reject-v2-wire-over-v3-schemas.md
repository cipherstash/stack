---
'@cipherstash/stack': minor
---

`Encryption` no longer accepts a public wire-version override or legacy schema
set. It requires EQL v3 tables and always builds a client that writes EQL v3,
eliminating the configuration that could write EQL v2 payloads into
`eql_v3_*` columns.

Reading stored EQL v2 payloads is unaffected: native `decrypt` and
`decryptModel` continue to read both generations. Compatibility fixtures mint
v2 payloads directly through the FFI rather than through the public Stack
authoring API.
