---
'@cipherstash/stack': minor
---

Export `DOMAIN_REGISTRY`, `factoryForDomain`, `stripDomainSchema`, and the
`V3ColumnFactory` type from `@cipherstash/stack/eql/v3`. These let integration
adapters (e.g. `@cipherstash/prisma-next`) derive the full EQL v3 domain
catalog — native types, capabilities, cast kinds, and indexes — from the stack
instead of hand-maintaining a copy.
