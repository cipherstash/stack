---
'@cipherstash/eql': minor
---

**Rust `eql_bindings::v4::text::{TextEq, TextEqQuery}` support Stack Encrypt's target-directed API behind the `stack-encrypt` feature.** Stack Encrypt writes EQL v4 only, so the `eql_v3` types carry no Stack Encrypt traits. The stored table and column identifier supplies the encryption context; native ciphertext and equality terms are transcoded into EQL payloads while Vitamin C owns plaintext encoding. This is a new producer profile with exact string equality, independent of existing cipherstash-client ciphertext and terms. Query operands carry no recoverable ciphertext.
