---
'@cipherstash/auth': patch
---

Token JSON saved by `InMemoryTokenStore`, callback token stores (including the
`loadToken`/`saveToken` callbacks of the Node and WASM builds), and the request
bodies sent to CTS (access keys, OIDC JWTs, refresh tokens), are now
serialised into a buffer that wipes itself as it grows, so no partial copies
are left in memory.
