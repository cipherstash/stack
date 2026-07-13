---
'stash': patch
'@cipherstash/stack': patch
---

Docs: stop teaching the deprecated `LockContext.identify()` as the primary
identity-aware-encryption path (#591). The `stash-encryption` and `stash-supabase`
skills and the `@cipherstash/stack` README now lead with the current pattern —
authenticate the client with `OidcFederationStrategy`, then bind the claim per
operation with `.withLockContext({ identityClaim })` — and demote
`LockContext.identify()` to a clearly-marked deprecated note (per-operation CTS
tokens were removed in protect-ffi 0.25). Skills ship in the `stash` tarball, so
this keeps the bundled guidance correct for the 1.0 surface.
