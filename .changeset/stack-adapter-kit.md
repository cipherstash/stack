---
'@cipherstash/stack': minor
---

Add the `@cipherstash/stack/adapter-kit` subpath — a narrow support surface for
the first-party adapter packages (`@cipherstash/stack-supabase`,
`@cipherstash/stack-drizzle`) being split out of this package (#627). It
re-exports exactly the core internals the adapters consume (the logger,
`AuditConfig`, the v3 column model + `DATE_LIKE_CASTS`, the domain registry, the
match-index guard, and the model→composite helpers) so those imports resolve
across the package boundary without leaking six internal module paths. This is the
core↔adapter seam, not general-purpose public API.
