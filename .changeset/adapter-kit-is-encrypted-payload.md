---
"@cipherstash/stack": patch
---

`@cipherstash/stack/adapter-kit` now exports `isEncryptedPayload`, the check
model decryption uses to find an encrypted value in a row. The Supabase adapter
uses it to refuse a row it would otherwise return undecrypted.
