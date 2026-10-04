---
'@cipherstash/eql': minor
---

**Rust `TextEq` and `TextEqQuery` support Stack Encrypt's target-directed API behind the `stack-encrypt` feature.** The stored table and column identifier supplies the encryption context; native ciphertext and equality terms are transcoded into EQL payloads while Vitamin C owns plaintext encoding. This is a new producer profile with exact string equality, independent of existing cipherstash-client ciphertext and terms. Query operands carry no recoverable ciphertext.
