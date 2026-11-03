---
"@cipherstash/auth": minor
---

Add the `@cipherstash/auth/start` entry: a TanStack Start adapter for federated
CTS tokens, built on the same federate-or-reuse core as `@cipherstash/auth/next`.

- `csFederationMiddleware(options)` returns a Start function middleware
  (`createMiddleware({ type: "function" })`) that federates-or-reuses the
  current user's token on every server-function call, persists it to the
  per-workspace `cs_token_<workspaceId>` cookie, appends the refreshed
  `Set-Cookie` to Start's response without dropping the cookies already there,
  and passes the token to the handler as a typed `context.csAuth`
  (`WarmedAuthStrategy`). It throws on failure, the signed-out case included;
  `onError: "null"` passes `context.csAuth = null` instead.
- `csFederateRequest(options)` runs the same federation against an explicit
  `request` / `responseHeaders` pair and returns `{ result, strategy }`, for a
  request middleware or a route handler.

Unlike the Next.js adapter, nothing rides on a request header: a Start function
middleware hands values to the server function through `next({ context })`,
so there is no `csSanitizeHeaders` / `csAuthHeader` counterpart, and the
unauthenticated-header caveat documented on `csAuthHeader` does not apply to
this entry.

`@tanstack/react-start` (1.132 or later) is an optional peer dependency loaded
only by the new entry. On Start 1.169 and later the cookie is appended through
`appendResponseHeader`; on earlier Start it is appended to the live response
headers.

`WarmedAuthStrategy` is now declared in a module shared by both adapters and
re-exported from `@cipherstash/auth/next` unchanged.
