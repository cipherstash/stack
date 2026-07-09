---
'@cipherstash/prisma-next': minor
---

Upgrade to Prisma Next 0.14.0 (from 0.8.0). Every `@prisma-next/*` dependency is now pinned at 0.14.0; consuming apps must run Prisma Next 0.14 to use this release.

Highlights of the upgrade:

- The extension contract space is re-emitted in the 0.14 canonical shape: storage is namespace-enveloped (`storage.namespaces.public.entries.table`), the domain plane replaces flat `models`, and the baseline EQL-install migration is re-pinned to the new storage hash. The vendored EQL bundle SQL is unchanged byte-for-byte.
- `deriveStackSchemas` reads the namespace-enveloped contract shape emitted by Prisma Next 0.10+.
- The bulk-encrypt middleware accepts the widened insert/update AST value unions introduced through 0.9–0.11.
- README examples use the namespace-qualified ORM accessors (`db.orm.public.User`) required since Prisma Next 0.14.
