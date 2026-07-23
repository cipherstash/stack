---
'@cipherstash/stack-drizzle': major
'@cipherstash/stack': patch
'stash': patch
---

Remove the EQL v2 authoring surface from `@cipherstash/stack-drizzle` and collapse the EQL v3 `./v3` subpath into the package root.

**Breaking (`@cipherstash/stack-drizzle`):**

- The EQL v2 root exports are gone: `encryptedType`, the v2 `extractEncryptionSchema`, the v2 `createEncryptionOperators` (including the `like` / `ilike` operators), and `EncryptionConfigError`. Authoring or querying `eql_v2_encrypted` columns through Drizzle is no longer supported.
- The `./v3` subpath is **removed** from the package `exports` map and `typesVersions`. The EQL v3 implementation is now the package root, and the `*V3` names are de-suffixed (`createEncryptionOperatorsV3` → `createEncryptionOperators`, `extractEncryptionSchemaV3` → `extractEncryptionSchema`). This is a **hard break with no alias**: post-collapse the root names would collide with the removed v2 names, and keeping an alias would silently type-check v2 call sites against v3 semantics.

**Migration** — import the v3 surface from the package root instead of `./v3`, and drop the `V3` suffix:

```diff
- import { types, extractEncryptionSchemaV3, createEncryptionOperatorsV3 } from '@cipherstash/stack-drizzle/v3'
+ import { types, extractEncryptionSchema, createEncryptionOperators } from '@cipherstash/stack-drizzle'
```

The `types.*` column factories, `makeEqlV3Column` / `getEqlV3Column` / `isEqlV3Column`, the codec helpers (`v3ToDriver` / `v3FromDriver` / `EqlV3CodecError`), and `EncryptionOperatorError` are unchanged apart from moving to the root.

Existing EQL v2 ciphertext remains decryptable via `@cipherstash/stack` — only the Drizzle-side v2 authoring and query-building is removed.

**`stash` (patch):** `stash init --drizzle` scaffolded the removed surface — the generated encryption-client file and the Drizzle placeholder both imported `extractEncryptionSchemaV3` from `@cipherstash/stack-drizzle/v3`, so a freshly-initialised project would not resolve against this release. Both now emit the collapsed root import. The bundled `stash-drizzle` and `stash-encryption` skills are updated to match.

**`@cipherstash/stack` (patch):** README only — its Drizzle section documented the removed `./v3` subpath and the `*V3` export names.
