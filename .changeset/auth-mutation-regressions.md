---
"@cipherstash/auth": patch
---

Internal test-only change to the underlying Rust crate: adds regression coverage for token expiry, credential rejection, device metadata, and browser-launch results. No API or behaviour change for `@cipherstash/auth` consumers; this entry exists because CI requires a changeset for changes under the crate.
