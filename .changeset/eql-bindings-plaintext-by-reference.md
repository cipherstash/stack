---
'@cipherstash/eql': minor
---

**eql-bindings reads every plaintext in place** (`stack-encrypt` feature). The EQL v4 types seal and index a plaintext without copying it, so a plaintext no longer needs `Clone`.

- The `Ciphertext` and `Hmac256` targets, and the query twins, are bounded by `Encrypt + EncryptRef`, where they were bounded by `Encrypt + Clone`. A plaintext with only a by-value `Encrypt` impl adds `impl Encrypt for &T`.
- A query twin's plaintext is `Zeroize`, because a query hands its value to the index by value and wipes it.
- `v4::plaintext::Date`, `Timestamp`, and `Decimal` are Vitamin C's types, built from jiff's and rust_decimal's values. They are not `Clone`.
- The crate's `jiff` and `rust_decimal` features now only turn on `stack-encrypt`. That feature turns on both.
