---
"@cipherstash/auth": minor
---

Add the `@cipherstash/auth/start` entry: a TanStack Start adapter for federated
CTS tokens, built on the same federate-or-reuse core as `@cipherstash/auth/next`.

- `csFederateCurrent(options)` federates-or-reuses the current user's token for
  the request Start is handling and resolves a `WarmedAuthStrategy`. Call it
  inside the `.server()` callback of a function middleware you declare yourself,
  and pass the result on as `context.csAuth`. It reads and writes the
  per-workspace `cs_token_<workspaceId>` cookie through Start's own
  `getCookie` / `setCookie`, so the cookies already on the response are kept,
  and every caller inside one request shares one federation. It throws on
  failure, the signed-out case included; `onError: "null"` resolves `null`
  instead.
- `csFederateRequest(options)` runs the same federation against an explicit
  `request` / `responseHeaders` pair and returns `{ result, strategy }`, for a
  route handler that builds its own response.

Unlike the Next.js adapter, nothing rides on a request header: a Start function
middleware hands values to the server function through `next({ context })`,
so there is no `csSanitizeHeaders` / `csAuthHeader` counterpart, and the
unauthenticated-header caveat documented on `csAuthHeader` does not apply to
this entry.

The entry exports a function to call inside your middleware, not a ready-made
middleware, on purpose: Start strips a middleware's `.server()` callback from
the client bundle only where the `createMiddleware().server()` chain is written
in the app's own module. A middleware built inside this package would leave the
app's `getJwt`, its environment reads and this package's inline wasm in the
browser bundle.

`@tanstack/react-start` (1.132 or later) is an optional peer dependency loaded
only by the new entry.

`cookieStore` (`@cipherstash/auth/cookies`) and `csFederate`
(`@cipherstash/auth/next`) accept a `jar` in place of `request` /
`responseHeaders`: a framework's own cookie API, `{ get(name), set(name, value,
attributes) }`, for frameworks that own the response. `cookieStore` now throws
when given neither a jar nor both `request` and `responseHeaders`, where it
previously failed on the first read. Existing calls are unchanged.

`WarmedAuthStrategy` is now declared in a module shared by both adapters and
re-exported from `@cipherstash/auth/next` unchanged.
