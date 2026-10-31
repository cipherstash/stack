---
---

Stack Encrypt's Rust scalar API now consumes plaintext and returns an opaque
`Ciphertext`, with separate methods for omitted and supplied context. Owned
`EncryptInto` / `DecryptFrom` conversions use explicit context capabilities.
The stored sealed-leaf format is unchanged.

Low-level structural encryption and decryption use `encrypt_tree` and
`decrypt_tree`, returning and opening a tree of individually sealed leaves.

This is a Rust-only release, versioned by release-plz from the conventional
commit. No npm package needs a version bump; EQL changes only adapt tests.
