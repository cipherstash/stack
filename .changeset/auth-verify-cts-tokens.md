---
"@cipherstash/auth": patch
---

The Rust `stack-auth` crate behind `@cipherstash/auth` can now verify the access tokens CTS issues before using them: RS256 signature against the keys CTS publishes at `/.well-known/jwks.json`, plus issuer, expiry and not-before (with 60 seconds of clock skew allowed), audience when one is requested, the access key as subject for access-key strategies, and the workspace on the signed `workspace` claim. A device session given no workspace CRN is held to the workspace of the session it starts from. The trusted issuer is the CTS for the workspace's region, pinned separately from `CS_CTS_HOST` and any `baseUrl` override. Verification is opt-in in this release and is not yet exposed through the JavaScript API, so `@cipherstash/auth`'s behaviour is unchanged.
