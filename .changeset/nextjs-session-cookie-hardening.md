---
'@cipherstash/nextjs': patch
---

Harden the CipherStash session cookie (`__cipherstash_cts_session`).

- The cookie is now written `httpOnly`, and `secure` when `NODE_ENV` is `production`. It holds a bearer token and nothing in this package reads it client-side; if your own client code read it, move that read to the server.
- A session is only reused for the user it was minted for. The cookie now records the issuer and subject (`iss` and `sub`) of the OIDC token it was minted from, and `protectMiddleware` and `protectClerkMiddleware` replace a session left behind by another user (for example after a Clerk multi-session `setActive` switch, or a sign-out on a route the middleware does not match). If a replacement cannot be minted, the stale cookie is cleared. Cookies written by earlier versions carry no owner and are re-minted once. Ownership is read without verifying a signature, so the token you pass to `protectMiddleware` or `getCtsToken` must be one your application has already authenticated.
- `getCtsToken(oidcToken)` only returns the cookie session when it belongs to the issuer and subject of `oidcToken`, and otherwise fetches a fresh session for that token.
- An expired or malformed session cookie no longer passes through or throws: it is treated as no session and re-minted or cleared by the middleware, instead of returning a 500 on every matched route.
- A successful CTS response is now validated before it is used. A 2xx body that is not an unexpired token (non-JSON, the wrong shape, or an `expiry` already past) is reported as a failure instead of being written to the cookie or thrown out of the middleware.
- `GetCtsTokenResponse` now uses `success: true` and `success: false` as literal discriminants, so checking `result.success` narrows `result.ctsToken` to a `CtsToken`.
- When the middleware replaces or clears the session, the request forwarded to route handlers and server components is updated in the same request, so `getCtsToken()` there never sees the previous user's session. Next.js only does this itself from 14.2.10, and this package supports `^14`. If the response you pass in already overrides the forwarded request headers, the forwarded session cookie is set to the one the middleware decided on, whether your override replaced the cookie or left it out.
- A CTS transport failure (DNS, TLS, connection reset) is reported as a failure instead of throwing, so the middleware still clears a stale session and does not return a 500. The error does not repeat the exception's message, which a fetch wrapper could fill with the request body.
