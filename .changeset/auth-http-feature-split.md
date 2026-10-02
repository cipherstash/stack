---
"@cipherstash/auth": patch
---

Internal restructuring of the underlying Rust crate: HTTP transport (reqwest
and the bundled access-key, device-session, OIDC-federation and auto
strategies) now sits behind an `http` cargo feature, on by default and always
enabled in the npm builds — no API change for `@cipherstash/auth` consumers.
The only observable difference is the wording of transport-failure error
messages, which now read "Request to the auth server failed: …" instead of
"HTTP request failed: …".
