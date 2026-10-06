---
"@cipherstash/stack": patch
"stash": patch
---

Document how `OidcFederationStrategy` serves many users through one client: the
`getJwt` callback runs on every operation and must return the JWT of the user
behind the current request, and each user's JWT is exchanged for that user's
own token (stack-auth's fix for cipherstash/stack#1045). The docs and the
`stash-auth`, `stash-encryption`, `stash-supabase` and `stash-edge` skills say
so, and say that on earlier `@cipherstash/auth` releases a strategy caches one
token for everyone, so a client there must serve one user.
