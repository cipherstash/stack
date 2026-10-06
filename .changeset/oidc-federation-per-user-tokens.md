---
"@cipherstash/auth": minor
---

`OidcFederationStrategy` now keeps one CTS token per distinct provider JWT
instead of one token for everyone. `getJwt` is called on every `getToken()`
and must return the JWT of the user the current request is for; each JWT is
exchanged once while its CTS token is valid, in a bounded least-recently-used
cache. Previously the strategy cached the first user's token and handed it to
every caller until it expired, so on a server serving many users through one
client a value one user encrypted under a lock context could be bound to
another user's identity (cipherstash/stack#1045).

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
