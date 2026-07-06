---
'@cipherstash/stack': minor
---

Add the EQL v3 Prisma ORM integration (`@cipherstash/stack/eql/v3/prisma`).

`encryptedPrisma({ encryptionClient, prismaClient, prisma, tables })` returns:

- `client` — the `$extends`-wrapped Prisma client: models registered in
  `tables` transparently encrypt on write (`create`/`update`/`upsert`/
  `createMany`/`updateMany` + `AndReturn` variants, with `null` normalized to
  `Prisma.DbNull` so the `eql_v3` domain CHECK is satisfied) and decrypt on
  read (including `Date` reconstruction). Encrypted columns referenced
  through the typed `where`/`orderBy`/`distinct`/`cursor`/`having` surface
  throw `PrismaEncryptedColumnError` — Prisma's Json lowering casts the
  column side to jsonb, bypassing the `eql_v3` operators, so a typed filter
  would silently match nothing.
- `where` — capability-checked `Prisma.sql` fragment builders (`eq`, `ne`,
  `gt`, `gte`, `lt`, `lte`, `between`, `notBetween`, `contains`, `in`,
  `notIn`, `orderBy`, `isNull`, `isNotNull`) lowering to the two-arg
  `eql_v3.*` function forms with full-envelope operands (interim, tracked by
  CIP-3402/CIP-3423).
- `$queryRawEncrypted(table, sql)` — runs a raw query and decrypts the
  result rows.

Declare encrypted columns as `Json` fields in `schema.prisma`; the DB
columns are the `eql_v3.*` domains (edit the generated migration SQL).
