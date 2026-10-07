---
"@cipherstash/auth": minor
---

`OidcFederationStrategy` now keeps one CTS token per distinct provider JWT
instead of one token for everyone. `getJwt` is called on every `getToken()`
and must return the JWT of the user the current request is for; a JWT is
exchanged once and its CTS token reused while that token is valid *and* the
JWT's entry is still in the bounded least-recently-used cache (eviction before
expiry, or `cacheCapacity: 0`, means another exchange; see below). Previously
the strategy cached the first user's token and handed it to
every caller until it expired, so on a server serving many users through one
client a value one user encrypted under a lock context could be bound to
another user's identity (cipherstash/stack#1045).

`getToken()` now calls `getJwt` in the caller's own async context and hands the
JWT to a new `getTokenForJwt(jwt)` method, on both the Node and `wasm-inline`
entries. Previously the Node binding ran `getJwt` through a napi threadsafe
function, in the async context of `create()`, so a callback that read the
request from `AsyncLocalStorage` (Clerk's `auth()`, Next.js `headers()`) saw
no request from a module-level strategy, or the creating request from one
created inside a request. One long-lived strategy now serves every user from
such a callback. `getTokenForJwt` is also public, for a caller that already
holds the user's JWT; it shares the strategy's cache with `getToken()`.

A token persisted through `createWithStore` (for example a cookie) is now
served only to the JWT it was federated from, so a store shared across users,
or a cookie left over from a previous sign-in, is a cache miss rather than
another user's token. The store is still one slot, so a store shared by
several users caches only the most recent of them; give each user their own
(a per-browser cookie already is). The stored JSON carries a new
`federated_from` field; tokens stored by earlier releases have none and are
re-federated once.

Because the cache is keyed on the whole JWT, an identity provider that rotates
JWTs faster than the CTS token lifetime (about 15 minutes) re-federates on each
rotation, where earlier releases reused the stored token.

The cache holds 1024 JWTs unless told otherwise. `create` and `createWithStore`
take an optional `cacheCapacity` after `baseUrl` (the `cacheCapacity` option on
`@cipherstash/auth/wasm-inline`); when the cache is full the least recently
used JWT's token is dropped, that user is exchanged again on their next call,
and the eviction is logged at `debug`. `0` caches nothing. Existing calls are
unchanged.
