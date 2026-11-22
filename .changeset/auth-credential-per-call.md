---
'@cipherstash/auth': patch
---

Rebuild on a `stack-auth` whose Rust API can issue the token for a credential passed with the call. The JavaScript API is unchanged: `getToken` and `getTokenForJwt` behave as before, and share one token cache. In Rust, `CredentialAuthStrategy` is the trait for a credential passed with the call, and an `OidcFederationStrategy` can be built with no provider callback (`OidcFederationStrategy::credential_per_call`). Such a strategy has no `get_token`, so a call that brings no credential does not compile. A Rust strategy built with a provider callback takes no JWT from its caller. The Node and wasm bindings therefore build the Rust strategy with `credential_per_call`, keep the `getJwt` callback themselves, and pass a JWT with each call.
