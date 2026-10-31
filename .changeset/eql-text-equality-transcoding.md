---
'@cipherstash/eql': minor
---

**Rust `eql_bindings::v4::text::{TextEq, TextEqQuery}` support Stack Encrypt's target-directed API behind the `stack-encrypt` feature.** Stack Encrypt writes EQL v4 only, so the `eql_v3` types carry no Stack Encrypt traits. The stored table and column identifier supplies the encryption context; native ciphertext and equality terms are transcoded into EQL payloads while Vitamin C owns plaintext encoding. This is a new producer profile whose string equality compares text in Unicode 16 NFC without folding case, independent of existing cipherstash-client ciphertext and terms. Text holding a code point unassigned in Unicode 16 is refused, when it is stored as well as when it is queried. Query operands carry no recoverable ciphertext.
