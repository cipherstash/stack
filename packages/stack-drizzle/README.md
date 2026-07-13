# @cipherstash/stack-drizzle

Drizzle ORM integration for [CipherStash Stack](https://www.npmjs.com/package/@cipherstash/stack) —
searchable, application-layer field-level encryption for PostgreSQL.

Depends on `@cipherstash/stack`; install both:

```bash
npm install @cipherstash/stack @cipherstash/stack-drizzle drizzle-orm
```

## EQL v2 (package root)

```ts
import { encryptedType, extractEncryptionSchema, createEncryptionOperators } from '@cipherstash/stack-drizzle'
import { Encryption } from '@cipherstash/stack'
```

`encryptedType` defines an `eql_v2_encrypted` column; `createEncryptionOperators`
returns query operators (`eq`, `like`, `gt`, `inArray`, …) that transparently
encrypt search values.

## EQL v3 (`/v3` subpath)

```ts
import { types, createEncryptionOperatorsV3, extractEncryptionSchemaV3, makeEqlV3Column } from '@cipherstash/stack-drizzle/v3'
```

Each encrypted column is a concrete `public.eql_v3_*` Postgres domain; query
capabilities are fixed by the chosen `types.*` factory.

See the `stash-drizzle` agent skill and https://cipherstash.com/docs for the full guide.

> Not to be confused with `@cipherstash/drizzle`, the older `@cipherstash/protect`-based package.
