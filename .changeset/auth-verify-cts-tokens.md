---
"@cipherstash/auth": patch
---

The Rust `stack-auth` crate behind `@cipherstash/auth` can now verify the access tokens CTS issues before using them: RS256 signature against the keys CTS publishes at `/.well-known/jwks.json`, plus issuer, expiry and (when requested) audience. The trusted issuer is the CTS for the workspace's region, pinned separately from `CS_CTS_HOST` and any `baseUrl` override. Verification is opt-in in this release and is not yet exposed through the JavaScript API, so `@cipherstash/auth`'s behaviour is unchanged.
