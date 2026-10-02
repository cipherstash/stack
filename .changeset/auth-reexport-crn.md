---
"@cipherstash/auth": patch
---

Internal addition to the underlying Rust crate: `stack_auth` now re-exports
`Crn` (the workspace CRN every strategy is bound to) so a caller that builds
a strategy by hand needs nothing else from `cts-common`. No API or behaviour
change for `@cipherstash/auth` consumers.
