---
'@cipherstash/nextjs': patch
---

Harden the CipherStash session cookie (`__cipherstash_cts_session`).

- The cookie is now written `httpOnly`, and `secure` when `NODE_ENV` is `production`. It holds a bearer token and nothing in this package reads it client-side; if your own client code read it, move that read to the server.
- A session is only reused for the user it was minted for. The cookie now records the subject of the OIDC token it was minted from, and `protectMiddleware` and `protectClerkMiddleware` replace a session left behind by another user (for example after a Clerk multi-session `setActive` switch, or a sign-out on a route the middleware does not match). If a replacement cannot be minted, the stale cookie is cleared. Cookies written by earlier versions carry no subject and are re-minted once.
- `getCtsToken(oidcToken)` only returns the cookie session when it belongs to the subject of `oidcToken`, and otherwise fetches a fresh session for that token.
- An expired or malformed session cookie no longer passes through or throws: it is treated as no session and re-minted or cleared by the middleware, instead of returning a 500 on every matched route.
