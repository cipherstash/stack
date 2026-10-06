---
"@cipherstash/stack": patch
"stash": patch
---

Document how `OidcFederationStrategy` is used safely with many users: the
`getJwt` callback runs on every operation and must return the JWT of the user
the request is for, and each user's JWT is exchanged for that user's own token
(stack-auth's fix for cipherstash/stack#1045). Build one client per request or
per user and capture the request in the `getJwt` closure: in Node the callback
runs outside the caller's async context (`AsyncLocalStorage`), so a `getJwt`
that reads the request from there finds no request, or the request a shared
client was created in. The docs and the `stash-auth`, `stash-encryption`,
`stash-supabase` and `stash-edge` skills say so.
