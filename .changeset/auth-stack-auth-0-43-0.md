---
"@cipherstash/auth": patch
---

The native binding is now built from the `stack-auth` 0.43.0 crate, so its
requests identify themselves as `stack-auth/0.43.0` in the user agent. No API
or behaviour change for `@cipherstash/auth` consumers.
