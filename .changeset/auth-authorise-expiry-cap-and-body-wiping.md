---
'@cipherstash/auth': patch
---

Cap the access-token expiry from CTS's `/api/authorise` at 30 days from now,
as a relative `expires_in` already is. A token loaded from a token store, or
passed in when the client is built, that claims to last longer than that is
refreshed before it is used. A bad `expiry` value can no longer make a token look
valid for ever, which kept the client sending a dead token until the process
restarted.

Token JSON saved by `InMemoryTokenStore`, callback token stores (including the
`loadToken`/`saveToken` callbacks of the Node and WASM builds), and the request
bodies sent to CTS (access keys, OIDC JWTs, refresh tokens), are now
serialised into a buffer that wipes itself as it grows, so no partial copies
are left in memory.

A response body from CTS, which carries the new access token, is now taken over
from the HTTP client's buffer where that buffer is not shared, rather than always
copied, so it is wiped with the response instead of being freed unwiped.
